//! One owner of request metadata under the existing inventory process lock.
use super::requests::{
    Canonical, Capability, CheckIn, ClientStatus, Clock, CollectionProof, CollectionRecovery,
    Delivery, Negotiated, Proof, RequestJournal, RetainedInventory,
};
use super::state::Lock;
use super::transport::Response;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub struct Readiness {
    pub enabled: bool,
    pub coherent: bool,
    pub clock_available: bool,
}
impl Readiness {
    fn allowed(&self) -> bool {
        self.enabled && self.coherent && self.clock_available
    }
}
pub struct Control<'a> {
    journal: RequestJournal<'a>,
    dir: PathBuf,
    enrollment: String,
    readiness: Readiness,
    recovery: CollectionRecovery,
    negotiated: Option<Negotiated>,
    source_revision: u64,
    in_flight: bool,
}
/// Captured before collection; cannot be cloned or created by the collector.
pub struct StartedCollection {
    dir: PathBuf,
    enrollment: String,
    request_id: String,
    proof: CollectionProof,
}
impl StartedCollection {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn report_id(&self) -> &str {
        &self
            .proof
            .scan
            .as_ref()
            .expect("Started collection proof")
            .report_id
    }
}
impl<'a> Control<'a> {
    pub fn collect_daily<T>(
        &mut self,
        tools: &impl super::process::Tools,
        collect: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        self.before_daily_collection()?;
        self.in_flight = true;
        // The exclusive mutable borrow prevents response intake or a requested
        // start until the daily collector and its publication have both returned.
        let result = collect();
        self.finish_native_collection(tools);
        result
    }
    fn before_daily_collection(&mut self) -> Result<(), String> {
        if self.in_flight || self.recovery == CollectionRecovery::Unfinished {
            return Err("Native collection cleanup unconfirmed; daily collection deferred".into());
        }
        self.journal.before_daily_collection()
    }
    pub fn publish_collection(
        &mut self,
        mut started: StartedCollection,
        scan: Value,
        clock: &Clock,
        store: &mut super::state::Store,
        tools: &impl super::process::Tools,
        now: u64,
    ) -> Result<(), String> {
        if !self.in_flight || started.dir != self.dir || started.enrollment != self.enrollment {
            return Err("Collection publication token does not belong to this active scan".into());
        }
        let result = (|| {
            clock.validate()?;
            if !self.in_flight
                || store.dir != self.dir
                || store.schedule.enrollment_id != self.enrollment
                || clock.boot_id != started.proof.boot_id
            {
                return Err("Collection publication scope unavailable".into());
            }
            let proof_scan = started
                .proof
                .scan
                .as_mut()
                .ok_or("Collection start proof unavailable")?;
            if clock.boottime_ms < proof_scan.started_boottime_ms
                || scan["scanId"] != proof_scan.report_id
                || proof_scan.sequence > store.schedule.sequence
            {
                return Err("Collection publication identity invalid".into());
            }
            let collected = scan["completedAt"]
                .as_str()
                .ok_or("Collection timestamp missing")?;
            let report = json!({"schema_version":1,"enrollment_id":self.enrollment,"report_id":proof_scan.report_id,
            "sequence":proof_scan.sequence,"source_revision":proof_scan.source_revision,"refresh_request_id":null,
            "collection_request_id":started.request_id,"collected_at":collected,"scan":scan,
            "metadata_refresh":{"result":"deferred","successful_checked_at":null,"policy_generation":null,"reason":"not_configured"}});
            let bytes = super::state::encode_report(&report)?;
            let digest = tools.sha256(&bytes)?;
            proof_scan.finished_boottime_ms = Some(clock.boottime_ms);
            let id = proof_scan.report_id.clone();
            let sequence = proof_scan.sequence;
            // Bind before replacing the one retained body. A crash between writes is
            // recovered as superseded; no package body is journaled or recreated.
            self.journal.bind_ready_report(
                Capability::Collection,
                &Proof::Collection(started.proof),
                &id,
                sequence,
                &digest,
            )?;
            store.replace_encoded(&bytes, now)?;
            Ok(())
        })();
        self.finish_native_collection(tools);
        result
    }
    fn finish_native_collection(&mut self, tools: &impl super::process::Tools) {
        self.in_flight = false;
        self.negotiated = None;
        // The native collector has returned. Keep physical/recovery uncertainty
        // distinct from the live execution guard so check-ins can reconcile.
        self.recovery = CollectionRecovery::Unfinished;
        if let Ok(latest) = self.retained_inventory(tools)
            && let Ok(recovery) = self.journal.recover_collection(latest.as_ref())
        {
            self.recovery = recovery;
        }
    }
    fn retained_inventory(
        &self,
        tools: &impl super::process::Tools,
    ) -> Result<Option<RetainedInventory>, String> {
        let path = self.dir.join("latest.json");
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("Retained inventory unavailable".into()),
            Ok(_) => {}
        }
        let bytes = super::state::read(&path, super::state::MAX_REPORT)?;
        let report: Value =
            serde_json::from_slice(&bytes).map_err(|_| "Retained inventory invalid")?;
        Ok(Some(RetainedInventory {
            enrollment_id: report["enrollment_id"]
                .as_str()
                .ok_or("Retained inventory enrollment invalid")?
                .into(),
            report_id: report["report_id"]
                .as_str()
                .ok_or("Retained inventory identity invalid")?
                .into(),
            sequence: report["sequence"]
                .as_u64()
                .ok_or("Retained inventory sequence invalid")?,
            sha256: tools.sha256(&bytes)?,
        }))
    }
    pub fn acknowledge(&mut self, response: &Response) -> Result<(), String> {
        if self.in_flight {
            return Ok(());
        }
        let result = (|| {
            if response.status != 200 || !response.json_content_type {
                return Err("Inventory request acknowledgement unavailable".into());
            }
            self.journal.canonical(
                Capability::Collection,
                &Canonical::parse(&response.raw_body)?,
            )
        })();
        if result.is_err() {
            self.negotiated = None;
        }
        result
    }
    pub fn start_collection(
        &mut self,
        report_id: &str,
        sequence: u64,
        clock: &Clock,
    ) -> Result<StartedCollection, String> {
        if !self.allowed() || self.in_flight {
            return Err("Inventory collection start unavailable".into());
        }
        clock.validate()?;
        let session = self
            .negotiated
            .as_ref()
            .ok_or("Inventory request negotiation unavailable")?;
        if !session.allows(Capability::Collection) {
            return Err("Inventory collection capability unavailable".into());
        }
        let pending = self
            .journal
            .pending(Capability::Collection)?
            .ok_or("No collection request")?;
        let proof = self.journal.start_collection(
            report_id,
            sequence,
            self.source_revision,
            clock,
            session,
        )?;
        self.in_flight = true;
        Ok(StartedCollection {
            dir: self.dir.clone(),
            enrollment: self.enrollment.clone(),
            request_id: pending.request_id,
            proof,
        })
    }
    pub fn open(
        dir: &Path,
        enrollment: &str,
        lock: &'a Lock,
        readiness: Readiness,
        latest: Option<&RetainedInventory>,
    ) -> Result<Self, String> {
        let mut journal = RequestJournal::open(dir, enrollment, lock)?;
        let recovery = journal.recover_collection(latest)?;
        Ok(Self {
            journal,
            dir: dir.to_owned(),
            enrollment: enrollment.into(),
            readiness,
            recovery,
            negotiated: None,
            source_revision: 0,
            in_flight: false,
        })
    }
    fn allowed(&self) -> bool {
        self.readiness.allowed() && self.recovery != CollectionRecovery::Unfinished
    }
    fn advertised(&self) -> Vec<Capability> {
        if self.allowed() {
            vec![Capability::Collection]
        } else {
            Vec::new()
        }
    }
    pub fn frame(&self, mut base: Value) -> Result<Value, String> {
        base["capabilities"] = json!(self.advertised());
        let collection = self.journal.pending(Capability::Collection)?;
        base["collection_result"] = match collection {
            Some(pending) if pending.status != ClientStatus::Received || self.allowed() => {
                serde_json::to_value(pending).map_err(|_| "Cannot encode collection status")?
            }
            _ => Value::Null,
        };
        let manual = self.journal.pending(Capability::Manual)?;
        base["refresh_result"] = match manual {
            Some(pending) if pending.status != ClientStatus::Received => {
                serde_json::to_value(pending).map_err(|_| "Cannot encode manual status")?
            }
            _ => Value::Null,
        };
        if self.recovery == CollectionRecovery::Unfinished {
            base["collection_state"] = json!("error");
        }
        Ok(base)
    }
    pub fn reconcile(
        &mut self,
        response: &Response,
        clock: Option<&Clock>,
        suffix: &str,
    ) -> Result<(), String> {
        // Responses received during a scan are reconciled on the next check-in.
        // They cannot replace its purpose or authorize another native invocation.
        if self.in_flight {
            return Ok(());
        }
        self.negotiated = None;
        if response.status != 200 || !response.json_content_type {
            return Err("Inventory request check-in unavailable".into());
        }
        let response = CheckIn::parse(&response.raw_body)?;
        for (cap, status) in [
            (Capability::Manual, response.refresh_status.as_ref()),
            (Capability::Collection, response.collection_status.as_ref()),
        ] {
            if let Some(status) = status {
                self.journal.canonical(cap, status)?;
            }
        }
        let negotiated = Negotiated::new(
            &self.advertised(),
            &response.capabilities,
            response.requests_enabled,
        )?;
        self.source_revision = response.source_revision;
        if response.refresh_request.is_some() {
            return Err("Unadvertised manual delivery rejected".into());
        }
        if let Some(delivery) = response.collection_request {
            if !self.allowed() {
                return Err("Unadvertised collection delivery rejected".into());
            }
            let clock =
                clock.ok_or("Native request clock unavailable; delivery retained by controller")?;
            clock.validate()?;
            self.journal.admit(
                Delivery::Collection(delivery),
                self.source_revision,
                clock,
                suffix,
                &negotiated,
            )?;
        }
        self.negotiated = Some(negotiated);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{requests::CounterSeeds, state};
    const EPOCH: &str = "00000000-0000-4000-8000-000000000001";
    fn fixture() -> (state::tests::TestDir, Lock) {
        let dir = state::tests::TestDir::new();
        let lock = Lock::acquire(&dir.0).unwrap();
        RequestJournal::initialize(
            &dir.0,
            EPOCH,
            CounterSeeds {
                helper: 0,
                observation: 0,
            },
            &lock,
        )
        .unwrap();
        (dir, lock)
    }
    fn clock() -> Clock {
        Clock {
            boot_id: EPOCH.into(),
            boottime_ms: 1000,
            unix_ms: 1793145600000,
        }
    }
    fn base() -> Value {
        json!({"schema_version":1,"enrollment_id":EPOCH,"agent_version":"synthetic-request","latest_report":null,"collection_state":"idle","refresh_result":null})
    }
    fn response() -> Response {
        let body = json!({"schema_version":1,"server_time":"2026-10-28T00:00:00Z","source_revision":2,"reporting_enabled":true,"receipt":null,"refresh_request":null,"capabilities":["inventory_collection_v1"],"requests_enabled":true,"collection_request":{"request_id":"00000000-0000-4000-8000-000000000002","delivery_sequence":1,"not_before":"2026-10-28T00:00:00Z","source_revision":2},"refresh_status":null,"collection_status":null});
        Response {
            status: 200,
            raw_body: serde_json::to_vec(&body).unwrap(),
            json_content_type: true,
            body,
            retry_after: 0,
        }
    }
    fn acknowledge(control: &mut Control<'_>) {
        let pending = control
            .journal
            .pending(Capability::Collection)
            .unwrap()
            .unwrap();
        let body = json!({"schema_version":1,"request":{"request_id":pending.request_id,"delivery_sequence":pending.delivery_sequence,"status":"delivered","reason":null,"report_id":null,"report_sha256":null,"operation_nonce":pending.operation_nonce},"receipt":null});
        control
            .acknowledge(&Response {
                status: 200,
                raw_body: serde_json::to_vec(&body).unwrap(),
                json_content_type: true,
                body,
                retry_after: 0,
            })
            .unwrap();
    }
    #[test]
    fn live_source_failure_cannot_hide_historical_native_uncertainty_from_new_start() {
        let (dir, lock) = fixture();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        let pending = control
            .journal
            .pending(Capability::Collection)
            .unwrap()
            .unwrap();
        let body = json!({"schema_version":1,"request":{"request_id":pending.request_id,"delivery_sequence":1,"status":"running","reason":null,"report_id":null,"report_sha256":null,"operation_nonce":pending.operation_nonce},"receipt":null});
        control
            .acknowledge(&Response {
                status: 200,
                raw_body: serde_json::to_vec(&body).unwrap(),
                json_content_type: true,
                body: body.clone(),
                retry_after: 0,
            })
            .unwrap();
        let mut next = response();
        let mut failed = body;
        failed["request"]["status"] = json!("failed");
        next.body["collection_status"] = failed;
        next.body["collection_request"]["request_id"] =
            json!("00000000-0000-4000-8000-000000000004");
        next.body["collection_request"]["delivery_sequence"] = json!(2);
        next.raw_body = serde_json::to_vec(&next.body).unwrap();
        assert!(
            control
                .reconcile(&next, Some(&clock()), "bbbbbbbbbbbbbbbb")
                .is_err()
        );
        let retained = control
            .journal
            .pending(Capability::Collection)
            .unwrap()
            .unwrap();
        assert_eq!(retained.request_id, pending.request_id);
        assert_eq!(retained.status, ClientStatus::Unconfirmed);
        assert!(
            control
                .start_collection("00000000-0000-4000-8000-000000000005", 1, &clock())
                .is_err()
        );
        // Reoffering higher requests cannot prune the old physical uncertainty.
        for sequence in [3, 4] {
            next.body["collection_request"]["delivery_sequence"] = json!(sequence);
            next.raw_body = serde_json::to_vec(&next.body).unwrap();
            assert!(
                control
                    .reconcile(&next, Some(&clock()), "bbbbbbbbbbbbbbbb")
                    .is_err()
            );
            assert_eq!(
                control
                    .journal
                    .pending(Capability::Collection)
                    .unwrap()
                    .unwrap()
                    .request_id,
                pending.request_id
            );
        }
    }

    #[test]
    fn authentication_rejection_after_acknowledgement_requires_fresh_negotiation() {
        let (dir, lock) = fixture();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        acknowledge(&mut control);
        assert!(
            control
                .acknowledge(&Response {
                    status: 401,
                    body: Value::Null,
                    raw_body: b"null".to_vec(),
                    json_content_type: true,
                    retry_after: 0
                })
                .is_err()
        );
        assert!(
            control
                .start_collection("00000000-0000-4000-8000-000000000003", 1, &clock())
                .is_err()
        );
        assert_eq!(
            control
                .journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::Received
        );
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        assert!(
            control
                .start_collection("00000000-0000-4000-8000-000000000003", 1, &clock())
                .is_ok()
        );
    }
    #[test]
    fn daily_collection_never_runs_while_requested_scan_is_in_flight() {
        let (dir, lock) = fixture();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        acknowledge(&mut control);
        let _started = control
            .start_collection("00000000-0000-4000-8000-000000000003", 1, &clock())
            .unwrap();
        let calls = std::cell::Cell::new(0);
        assert!(
            control
                .collect_daily(&super::super::process::SystemTools, || {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(calls.get(), 0);
    }
    #[test]
    fn failed_publication_unwinds_live_scan_and_reconciles_metadata_without_recreating_body() {
        let (dir, lock) = fixture();
        state::Store::initialize(&dir.0, EPOCH).unwrap();
        let mut store = state::Store::load(&dir.0, EPOCH).unwrap();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        acknowledge(&mut control);
        let id = "00000000-0000-4000-8000-000000000003";
        let started = control
            .start_collection(id, store.reserve().unwrap(), &clock())
            .unwrap();
        let newer = json!({"enrollment_id":EPOCH,"report_id":"00000000-0000-4000-8000-000000000004","sequence":store.reserve().unwrap()});
        store.replace(&newer, 1793145600).unwrap();
        let original = state::read(&dir.0.join("latest.json"), state::MAX_REPORT).unwrap();
        let mut finished = clock();
        finished.boottime_ms += 1;
        assert!(
            control
                .publish_collection(
                    started,
                    json!({"scanId":id,"completedAt":"2026-10-28T00:00:01Z"}),
                    &finished,
                    &mut store,
                    &super::super::process::SystemTools,
                    1793145601
                )
                .is_err()
        );
        assert!(!control.in_flight);
        assert_eq!(
            control
                .journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::ResultSuperseded
        );
        assert_eq!(
            state::read(&dir.0.join("latest.json"), state::MAX_REPORT).unwrap(),
            original
        );
        let pending = control
            .journal
            .pending(Capability::Collection)
            .unwrap()
            .unwrap();
        let body = json!({"schema_version":1,"request":{"request_id":pending.request_id,"delivery_sequence":1,"status":"failed","reason":"result_superseded","report_id":null,"report_sha256":null,"operation_nonce":pending.operation_nonce},"receipt":null});
        control
            .acknowledge(&Response {
                status: 200,
                raw_body: serde_json::to_vec(&body).unwrap(),
                json_content_type: true,
                body,
                retry_after: 0,
            })
            .unwrap();
        let mut next = response();
        next.body["collection_request"]["request_id"] = newer["report_id"].clone();
        next.body["collection_request"]["delivery_sequence"] = json!(2);
        next.raw_body = serde_json::to_vec(&next.body).unwrap();
        control
            .reconcile(&next, Some(&clock()), "bbbbbbbbbbbbbbbb")
            .unwrap();
        assert_eq!(
            control
                .journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .delivery_sequence,
            2
        );
    }

    #[test]
    fn replacing_ready_report_for_daily_collection_first_persists_supersession() {
        let (dir, lock) = fixture();
        state::Store::initialize(&dir.0, EPOCH).unwrap();
        let mut store = state::Store::load(&dir.0, EPOCH).unwrap();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        acknowledge(&mut control);
        let id = "00000000-0000-4000-8000-000000000003";
        let started = control
            .start_collection(id, store.reserve().unwrap(), &clock())
            .unwrap();
        assert!(control.before_daily_collection().is_err());
        let mut finished = clock();
        finished.boottime_ms += 1;
        control
            .publish_collection(
                started,
                json!({"scanId":id,"completedAt":"2026-10-28T00:00:01Z"}),
                &finished,
                &mut store,
                &super::super::process::SystemTools,
                1793145601,
            )
            .unwrap();
        let original = state::read(&dir.0.join("latest.json"), state::MAX_REPORT).unwrap();
        control.before_daily_collection().unwrap();
        assert_eq!(
            control
                .journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::ResultSuperseded
        );
        // The notice precedes report replacement and never writes another package body.
        assert_eq!(
            state::read(&dir.0.join("latest.json"), state::MAX_REPORT).unwrap(),
            original
        );
    }
    #[test]
    fn changed_source_without_terminal_reconciliation_cannot_start_old_delivery() {
        let (dir, lock) = fixture();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        acknowledge(&mut control);
        let mut changed = response();
        changed.body["source_revision"] = json!(3);
        changed.body["collection_request"] = Value::Null;
        changed.raw_body = serde_json::to_vec(&changed.body).unwrap();
        control
            .reconcile(&changed, Some(&clock()), "bbbbbbbbbbbbbbbb")
            .unwrap();
        assert!(
            control
                .start_collection("00000000-0000-4000-8000-000000000003", 1, &clock())
                .is_err()
        );
        assert_eq!(
            control
                .journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::Received
        );
    }
    #[test]
    fn finished_scan_publishes_exact_bound_bytes_with_original_request_purpose() {
        let (dir, lock) = fixture();
        state::Store::initialize(&dir.0, EPOCH).unwrap();
        let mut store = state::Store::load(&dir.0, EPOCH).unwrap();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        acknowledge(&mut control);
        let sequence = store.reserve().unwrap();
        let id = "00000000-0000-4000-8000-000000000003";
        let started = control.start_collection(id, sequence, &clock()).unwrap();
        // A delivery arriving while native collection runs cannot relabel this result.
        let mut next = response();
        next.body["source_revision"] = json!(3);
        next.body["collection_request"]["source_revision"] = json!(3);
        next.body["collection_request"]["request_id"] =
            json!("00000000-0000-4000-8000-000000000004");
        next.body["collection_request"]["delivery_sequence"] = json!(2);
        next.raw_body = serde_json::to_vec(&next.body).unwrap();
        control
            .reconcile(&next, Some(&clock()), "bbbbbbbbbbbbbbbb")
            .unwrap();
        let mut finished = clock();
        finished.boottime_ms += 1000;
        let scan =
            json!({"scanId":id,"completedAt":"2026-10-28T00:00:01Z","machines":[],"software":[]});
        control
            .publish_collection(
                started,
                scan,
                &finished,
                &mut store,
                &super::super::process::SystemTools,
                1793145601,
            )
            .unwrap();
        let bytes = state::read(&dir.0.join("latest.json"), state::MAX_REPORT).unwrap();
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        let pending = control
            .journal
            .pending(Capability::Collection)
            .unwrap()
            .unwrap();
        assert_eq!(
            report["collection_request_id"],
            "00000000-0000-4000-8000-000000000002"
        );
        assert_eq!(report["source_revision"], 2);
        assert_eq!(pending.report_id.as_deref(), Some(id));
        use super::super::process::Tools;
        assert_eq!(
            pending.report_sha256.as_deref(),
            Some(
                super::super::process::SystemTools
                    .sha256(&bytes)
                    .unwrap()
                    .as_str()
            )
        );
        assert!(pending.attempt.unwrap()["scan"]["finished_boottime_ms"].is_number());
        assert!(!control.in_flight);
    }
    #[test]
    fn collection_start_requires_persisted_matching_acknowledgement_and_is_one_use() {
        let (dir, lock) = fixture();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        let id = "00000000-0000-4000-8000-000000000003";
        assert!(control.start_collection(id, 1, &clock()).is_err());
        let pending = control
            .journal
            .pending(Capability::Collection)
            .unwrap()
            .unwrap();
        let body = json!({"schema_version":1,"request":{"request_id":pending.request_id,"delivery_sequence":1,"status":"delivered","reason":null,"report_id":null,"report_sha256":null,"operation_nonce":pending.operation_nonce},"receipt":null});
        control
            .acknowledge(&Response {
                status: 200,
                raw_body: serde_json::to_vec(&body).unwrap(),
                json_content_type: true,
                body,
                retry_after: 0,
            })
            .unwrap();
        let started = control.start_collection(id, 1, &clock()).unwrap();
        assert_eq!(started.report_id(), id);
        assert_eq!(started.request_id(), "00000000-0000-4000-8000-000000000002");
        assert!(control.start_collection(id, 1, &clock()).is_err());
    }
    #[test]
    fn enabled_coherent_control_advertises_and_durably_admits_collection_before_any_start() {
        let (dir, lock) = fixture();
        let mut control = Control::open(
            &dir.0,
            EPOCH,
            &lock,
            Readiness {
                enabled: true,
                coherent: true,
                clock_available: true,
            },
            None,
        )
        .unwrap();
        let frame = control.frame(base()).unwrap();
        assert_eq!(frame["capabilities"], json!(["inventory_collection_v1"]));
        assert!(frame["collection_result"].is_null());
        control
            .reconcile(&response(), Some(&clock()), "aaaaaaaaaaaaaaaa")
            .unwrap();
        let pending = control
            .journal
            .pending(Capability::Collection)
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.status,
            super::super::requests::ClientStatus::Received
        );
        assert!(
            control
                .journal
                .begin(
                    Capability::Collection,
                    &clock(),
                    control.negotiated.as_ref().unwrap()
                )
                .is_err()
        );
    }
}
