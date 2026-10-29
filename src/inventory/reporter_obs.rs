//! Scripted OBS publication seam only; no process, Root grant or scan authority.
//! Deadline comparisons here do not bound arbitrary blocking I/O. A real
//! admitted nonblocking exchange and source/lifetime proofs remain separate.

use super::reporter_frame::parse_frame;
use super::requests::{
    Clock, NativeCollectionIntent, Negotiated, PublishedNativeCollection, RequestJournal,
};
use serde::Deserialize;
use serde_json::json;

const ERROR: &str = "Reporter OBS publication unavailable";
const SAFE: u64 = 9_007_199_254_740_991;
type Result<T> = std::result::Result<T, String>;

fn require(condition: bool) -> Result<()> {
    if condition { Ok(()) } else { Err(ERROR.into()) }
}

// Deliberately module-private: only the deterministic scripted implementation
// below exists. A future real bounded transport requires independent review.
// None of these methods may call ANY Journal API, spawn, or wait for Root.
trait Exchange {
    fn sample(&mut self) -> Result<Clock>;
    fn read(&mut self) -> Result<Vec<u8>>;
    fn write(&mut self, raw: &[u8]) -> Result<()>;
    fn close(&mut self) -> Result<()>;
}

struct ExpectedPin {
    cache_generation: String,
    policy_generation: String,
    successful_checked_at: String,
    boot_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    cache_generation: String,
    policy_generation: String,
    successful_checked_at: String,
    boot_id: String,
    pinned_boottime_ms: u64,
}

fn checked_at(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(bytes.len() == 20 || (22..=27).contains(&bytes.len())) || bytes.last() != Some(&b'Z') {
        return false;
    }
    if !bytes.iter().enumerate().all(|(index, byte)| match index {
        4 | 7 => *byte == b'-',
        10 => *byte == b'T',
        13 | 16 => *byte == b':',
        i if i == bytes.len() - 1 => *byte == b'Z',
        19 if bytes.len() > 20 => *byte == b'.',
        _ => byte.is_ascii_digit(),
    }) {
        return false;
    }
    let number = |from, to| value[from..to].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    day > 0 && day <= days[(month - 1) as usize]
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(PartialEq)]
enum Phase {
    Admitting,
    Pinned,
    Publishing,
    Published,
    Closed,
}
struct PinnedSession<E: Exchange> {
    exchange: Option<E>,
    context: Pin,
    deadline: u64,
    last: u64,
    phase: Phase,
}
struct PublishedSession<E: Exchange> {
    session: PinnedSession<E>,
    published: PublishedNativeCollection,
}

impl<E: Exchange> PinnedSession<E> {
    fn admit(exchange: E, expected: ExpectedPin) -> Result<Self> {
        let mut value = Self {
            exchange: Some(exchange),
            context: Pin {
                cache_generation: String::new(),
                policy_generation: String::new(),
                successful_checked_at: String::new(),
                boot_id: expected.boot_id.clone(),
                pinned_boottime_ms: 0,
            },
            deadline: 0,
            last: 0,
            phase: Phase::Admitting,
        };
        require(
            hex(&expected.cache_generation, 32)
                && hex(&expected.policy_generation, 64)
                && checked_at(&expected.successful_checked_at),
        )?;
        let first = value.port()?.sample().map_err(|_| ERROR.to_owned())?;
        first.validate().map_err(|_| ERROR.to_owned())?;
        require(first.boot_id == expected.boot_id)?;
        value.deadline = first
            .boottime_ms
            .checked_add(120000)
            .filter(|limit| *limit <= SAFE)
            .ok_or(ERROR)?;
        value.last = first.boottime_ms;
        let raw = value.port()?.read().map_err(|_| ERROR.to_owned())?;
        value.check()?;
        let frame = parse_frame(&raw).map_err(|_| ERROR.to_owned())?;
        let object = frame.as_object().ok_or(ERROR)?;
        require(
            object.len() == 5
                && frame["schema_version"].as_u64() == Some(1)
                && frame["id"].as_u64() == Some(0)
                && frame["operation"] == "initialize"
                && frame["phase"] == "pinned",
        )?;
        let context: Pin =
            serde_json::from_value(frame["context"].clone()).map_err(|_| ERROR.to_owned())?;
        require(
            context.cache_generation == expected.cache_generation
                && context.policy_generation == expected.policy_generation
                && context.successful_checked_at == expected.successful_checked_at
                && context.boot_id == expected.boot_id
                && context.pinned_boottime_ms <= value.last
                && context.pinned_boottime_ms <= SAFE,
        )?;
        value.context = context;
        value.check()?;
        value.phase = Phase::Pinned;
        Ok(value)
    }
    fn port(&mut self) -> Result<&mut E> {
        self.exchange.as_mut().ok_or(ERROR.into())
    }
    fn check(&mut self) -> Result<Clock> {
        require(self.phase != Phase::Closed)?;
        let clock = self.port()?.sample().map_err(|_| ERROR.to_owned())?;
        clock.validate().map_err(|_| ERROR.to_owned())?;
        require(
            clock.boot_id == self.context.boot_id
                && clock.boottime_ms >= self.last
                && clock.boottime_ms < self.deadline,
        )?;
        self.last = clock.boottime_ms;
        Ok(clock)
    }
    fn publish(
        mut self,
        journal: &mut RequestJournal<'_>,
        intent: NativeCollectionIntent,
        session: &Negotiated,
    ) -> Result<PublishedSession<E>> {
        require(self.phase == Phase::Pinned)?;
        self.phase = Phase::Publishing;
        let clock = self.check()?;
        let published=journal.publish_native_observation(intent,&clock,session,|nonce| {
            // Borrow the session; no Drop/teardown or Journal reentry under the
            // global publication mutex. No Root offer/scan/receipt operation.
            self.check()?;
            let raw=serde_json::to_vec(&json!({"schema_version":1,"id":1,"operation":"publish_observation","nonce":nonce})).map_err(|_|ERROR.to_owned())?;
            let mut command=raw;command.push(b'\n');self.port()?.write(&command).map_err(|_|ERROR.to_owned())?;
            self.check()?;
            let raw=self.port()?.read().map_err(|_|ERROR.to_owned())?;self.check()?;
            let frame=parse_frame(&raw).map_err(|_|ERROR.to_owned())?;let object=frame.as_object().ok_or(ERROR)?;
            require(object.len()==4 && frame["schema_version"].as_u64()==Some(1) && frame["id"].as_u64()==Some(1) &&
                frame["operation"]=="publish_observation" && frame["phase"]=="published")?;
            self.check()?;Ok(())
        }).map_err(|_|ERROR.to_owned())?;
        // The journal's post-callback protected snapshot can itself consume the
        // remaining budget. Late success drops the opaque token, never remints.
        self.check()?;
        self.phase = Phase::Published;
        Ok(PublishedSession {
            session: self,
            published,
        })
    }
}
impl<E: Exchange> Drop for PinnedSession<E> {
    fn drop(&mut self) {
        self.phase = Phase::Closed;
        if let Some(mut exchange) = self.exchange.take() {
            let _ = exchange.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::requests::{
        Canonical, CanonicalRequest, CanonicalStatus, Capability, CollectionDelivery, CounterSeeds,
        Delivery,
    };
    use serde_json::{Value, json};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const BOOT: &str = "00000000-0000-4000-8000-000000000001";
    const REPORT: &str = "00000000-0000-4000-8000-000000000002";
    fn clock(time: u64) -> Clock {
        Clock {
            boot_id: BOOT.into(),
            boottime_ms: time,
            unix_ms: 1_767_225_600_000,
        }
    }
    fn negotiated() -> Negotiated {
        Negotiated::new(&[Capability::Collection], &[Capability::Collection], true).unwrap()
    }
    fn expected() -> ExpectedPin {
        ExpectedPin {
            cache_generation: "a".repeat(32),
            policy_generation: "b".repeat(64),
            successful_checked_at: "2026-01-01T00:00:00.123456Z".into(),
            boot_id: BOOT.into(),
        }
    }
    fn initial() -> Vec<u8> {
        format!("{}\n",json!({"schema_version":1,"id":0,"operation":"initialize","phase":"pinned","context":{
        "cache_generation":"a".repeat(32),"policy_generation":"b".repeat(64),"successful_checked_at":"2026-01-01T00:00:00.123456Z","boot_id":BOOT,"pinned_boottime_ms":1001}})).into_bytes()
    }
    fn ack() -> Vec<u8> {
        b"{\"schema_version\":1,\"id\":1,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n".to_vec()
    }

    struct Fixture {
        dir: std::path::PathBuf,
        lock: crate::inventory::state::Lock,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "inventory-obs-{}",
                    crate::inventory::transport::report_id().unwrap()
                ));
            std::fs::create_dir(&dir).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let lock = crate::inventory::state::Lock::acquire(&dir).unwrap();
            RequestJournal::initialize(
                &dir,
                BOOT,
                CounterSeeds {
                    helper: 5,
                    observation: 7,
                },
                &lock,
            )
            .unwrap();
            Self { dir, lock }
        }
        fn ready(&self, session: &Negotiated) -> RequestJournal<'_> {
            let mut journal = RequestJournal::open(&self.dir, BOOT, &self.lock).unwrap();
            journal
                .admit(
                    Delivery::Collection(CollectionDelivery {
                        request_id: REPORT.into(),
                        delivery_sequence: 1,
                        not_before: "2026-01-01T00:00:00.000Z".into(),
                        source_revision: 1,
                    }),
                    1,
                    &clock(1000),
                    "aaaaaaaaaaaaaaaa",
                    session,
                )
                .unwrap();
            let pending = journal.pending(Capability::Collection).unwrap().unwrap();
            journal
                .canonical(
                    Capability::Collection,
                    &Canonical {
                        schema_version: 1,
                        request: CanonicalRequest {
                            request_id: pending.request_id,
                            delivery_sequence: 1,
                            status: CanonicalStatus::Delivered,
                            reason: None,
                            report_id: None,
                            report_sha256: None,
                            operation_nonce: pending.operation_nonce,
                        },
                        receipt: None,
                    },
                )
                .unwrap();
            journal
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[derive(Default)]
    struct Recorded {
        writes: Vec<Vec<u8>>,
        closes: usize,
        durable_seen: bool,
        reads: usize,
        samples: usize,
    }
    struct Scripted {
        frames: VecDeque<Vec<u8>>,
        times: VecDeque<Clock>,
        record: Arc<Mutex<Recorded>>,
        path: std::path::PathBuf,
        fail_write: bool,
        change_on_ack: bool,
    }
    impl Exchange for Scripted {
        fn sample(&mut self) -> Result<Clock> {
            self.record.lock().unwrap().samples += 1;
            self.times
                .pop_front()
                .ok_or("Synthetic clock exhausted".into())
        }
        fn read(&mut self) -> Result<Vec<u8>> {
            let mut record = self.record.lock().unwrap();
            record.reads += 1;
            if record.reads == 2 && self.change_on_ack {
                let mut bytes = std::fs::read(&self.path).unwrap();
                bytes.push(b'\n');
                std::fs::write(&self.path, bytes).unwrap();
            }
            self.frames.pop_front().ok_or("Synthetic EOF".into())
        }
        fn write(&mut self, raw: &[u8]) -> Result<()> {
            let saved: Value = serde_json::from_slice(&std::fs::read(&self.path).unwrap()).unwrap();
            let command: Value = serde_json::from_slice(raw).unwrap();
            assert_eq!(saved["collection"]["active"]["submitted"], true);
            assert!(saved["collection"]["active"]["proof"]["evidence"]["scan"].is_null());
            assert_eq!(
                saved["collection"]["active"]["native_attempt"]["observation_nonce"],
                command["nonce"]
            );
            let mut record = self.record.lock().unwrap();
            record.durable_seen = true;
            record.writes.push(raw.to_vec());
            if self.fail_write {
                Err("Synthetic possibly visible write failure".into())
            } else {
                Ok(())
            }
        }
        fn close(&mut self) -> Result<()> {
            self.record.lock().unwrap().closes += 1;
            Ok(())
        }
    }
    fn scripted(fixture: &Fixture) -> (Scripted, Arc<Mutex<Recorded>>) {
        let record = Arc::new(Mutex::new(Recorded::default()));
        (
            Scripted {
                frames: VecDeque::from([initial(), ack()]),
                times: (0..20).map(|_| clock(1002)).collect(),
                record: record.clone(),
                path: fixture.dir.join("requests.json"),
                fail_write: false,
                change_on_ack: false,
            },
            record,
        )
    }

    fn unfinished(fixture: &Fixture, before: &Value) {
        let mut reopened = RequestJournal::open(&fixture.dir, BOOT, &fixture.lock).unwrap();
        assert_eq!(
            reopened.recover_collection(None).unwrap(),
            crate::inventory::requests::CollectionRecovery::Unfinished
        );
        let after: Value =
            serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap())
                .unwrap();
        assert_eq!(after["counters"], before["counters"]);
        let retained = after["collection"]["active"]
            .as_object()
            .or_else(|| after["collection"]["last_terminal"].as_object())
            .unwrap();
        assert_eq!(retained["submitted"], true);
        assert!(retained["proof"]["evidence"]["scan"].is_null());
        assert_eq!(
            retained["native_attempt"]["observation_nonce"],
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        assert!(
            reopened
                .admit_native_collection(
                    REPORT,
                    1,
                    1,
                    &clock(1010),
                    "cccccccccccccccc",
                    &negotiated()
                )
                .is_err()
        );
    }
    fn saved(fixture: &Fixture) -> Value {
        serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap()).unwrap()
    }

    #[test]
    fn publication_uses_durable_native_admission_before_one_exact_reporter_write() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let (exchange, record) = scripted(&fixture);
        let pinned = PinnedSession::admit(exchange, expected()).unwrap();
        let published = pinned.publish(&mut journal, intent, &session).unwrap();
        assert_eq!(
            published.published.observation_nonce(),
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        assert_eq!(published.session.context.pinned_boottime_ms, 1001);
        let saved = record.lock().unwrap();
        assert!(saved.durable_seen);
        assert_eq!(saved.writes.len(), 1);
        let command: Value = serde_json::from_slice(&saved.writes[0]).unwrap();
        assert_eq!(
            command,
            json!({"schema_version":1,"id":1,"operation":"publish_observation","nonce":"0000000000000008bbbbbbbbbbbbbbbb"})
        );
        drop(saved);
        drop(published);
        assert_eq!(record.lock().unwrap().closes, 1);
    }

    #[test]
    fn pin_admission_rechecks_original_deadline_after_frame_validation() {
        let fixture = Fixture::new();
        let (mut exchange, record) = scripted(&fixture);
        exchange.times = VecDeque::from([clock(1002), clock(1002), clock(121002)]);
        assert!(PinnedSession::admit(exchange, expected()).is_err());
        let record = record.lock().unwrap();
        assert!(record.writes.is_empty());
        assert_eq!(record.closes, 1);
    }

    #[test]
    fn invalid_pin_fields_cannot_produce_a_publication_session() {
        for change in 0..10 {
            let fixture = Fixture::new();
            let (mut exchange, record) = scripted(&fixture);
            let mut frame: Value = serde_json::from_slice(&initial()).unwrap();
            match change {
                0 => frame["id"] = json!(false),
                1 => frame["context"]["pinned_boottime_ms"] = json!(true),
                2 => frame["context"]["pinned_boottime_ms"] = json!(1003),
                3 => frame["context"]["cache_generation"] = json!("d".repeat(32)),
                4 => frame["context"]["policy_generation"] = json!("d".repeat(64)),
                5 => frame["context"]["boot_id"] = json!("00000000-0000-4000-8000-000000000003"),
                6 => frame["context"]["successful_checked_at"] = json!("2026-01-01T00:00:00.123Z"),
                7 => frame["context"]["extra"] = json!(false),
                8 => frame["extra"] = json!(false),
                _ => frame["phase"] = json!("published"),
            }
            exchange.frames[0] = format!("{frame}\n").into_bytes();
            assert!(
                PinnedSession::admit(exchange, expected()).is_err(),
                "case {change}"
            );
            let record = record.lock().unwrap();
            assert!(record.writes.is_empty());
            assert_eq!(record.closes, 1);
        }
        for timestamp in [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.1Z",
            "2026-01-01T00:00:00.123456Z",
            "2024-02-29T23:59:59.123Z",
        ] {
            assert!(checked_at(timestamp));
        }
        for timestamp in [
            "2026-02-29T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00.1234567Z",
            "2026-01-01T00:00:00+00:00",
            "0000-01-01T00:00:00Z",
        ] {
            assert!(!checked_at(timestamp));
        }
    }

    #[test]
    fn stale_epoch_negotiation_source_or_disk_never_invokes_reporter_io() {
        for change in 0..5 {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (exchange, record) = scripted(&fixture);
            let pinned = PinnedSession::admit(exchange, expected()).unwrap();
            let current = if change == 1 {
                negotiated()
            } else {
                session.clone()
            };
            match change {
                0 => {
                    journal
                        .reserve_nonce(
                            crate::inventory::requests::OperationDomain::Helper,
                            "dddddddddddddddd",
                        )
                        .unwrap();
                }
                2 => {
                    let pending = journal.pending(Capability::Collection).unwrap().unwrap();
                    journal
                        .canonical(
                            Capability::Collection,
                            &Canonical {
                                schema_version: 1,
                                request: CanonicalRequest {
                                    request_id: pending.request_id,
                                    delivery_sequence: pending.delivery_sequence,
                                    status: CanonicalStatus::Failed,
                                    reason: Some("inventory_authority_changed".into()),
                                    report_id: None,
                                    report_sha256: None,
                                    operation_nonce: pending.operation_nonce,
                                },
                                receipt: None,
                            },
                        )
                        .unwrap();
                }
                3 => {
                    let path = fixture.dir.join("requests.json");
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes.push(b'\n');
                    std::fs::write(path, bytes).unwrap();
                }
                4 => {
                    journal.recover_collection(None).unwrap();
                }
                _ => {}
            }
            let after_change = saved(&fixture);
            assert!(
                pinned.publish(&mut journal, intent, &current).is_err(),
                "case {change}"
            );
            let record = record.lock().unwrap();
            assert!(record.writes.is_empty());
            assert_eq!(record.reads, 1);
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished(&fixture, if change == 0 { &after_change } else { &before });
        }
    }

    #[test]
    fn malformed_partial_or_missing_ack_preserves_submitted_scope_without_retry() {
        for raw in [
            b"{\"schema_version\":1,\"id\":2,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n".as_slice(),
            b"{\"schema_version\":1,\"id\":true,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n",
            b"{\"schema_version\":1,\"id\":1.0,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n",
            b"{\"schema_version\":1,\"id\":1,\"operation\":\"await_open\",\"phase\":\"published\"}\n",
            b"{\"schema_version\":1,\"id\":1,\"operation\":\"publish_observation\",\"phase\":\"scan_proposed\"}\n",
            b"{\"schema_version\":1,\"id\":1,\"operation\":\"publish_observation\",\"phase\":\"published\",\"extra\":0}\n",
            b"{\"schema_version\":1,\"id\":1,\"id\":1,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n",
            b"{\"schema_version\":1",b"",
        ] {
            let fixture=Fixture::new();let session=negotiated();let mut journal=fixture.ready(&session);
            let intent=journal.admit_native_collection(REPORT,1,1,&clock(1001),"bbbbbbbbbbbbbbbb",&session).unwrap();let before=saved(&fixture);
            let (mut exchange,record)=scripted(&fixture);exchange.frames[1]=raw.to_vec();
            let pinned=PinnedSession::admit(exchange,expected()).unwrap();
            assert!(pinned.publish(&mut journal,intent,&session).is_err());
            let record=record.lock().unwrap();assert_eq!(record.writes.len(),1);assert_eq!(record.closes,1);drop(record);
            drop(journal);unfinished(&fixture,&before);
        }
    }

    #[test]
    fn visible_write_failure_and_postcallback_disk_change_never_mint_published_session() {
        for change_disk in [false, true] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (mut exchange, record) = scripted(&fixture);
            exchange.fail_write = !change_disk;
            exchange.change_on_ack = change_disk;
            let pinned = PinnedSession::admit(exchange, expected()).unwrap();
            assert!(pinned.publish(&mut journal, intent, &session).is_err());
            if change_disk {
                assert!(journal.pending(Capability::Collection).is_err());
                assert_eq!(
                    std::fs::read(fixture.dir.join("requests.json"))
                        .unwrap()
                        .last(),
                    Some(&b'\n')
                );
            }
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 1);
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished(&fixture, &before);
        }
    }

    #[test]
    fn expiry_or_clock_failure_is_absorbing_even_after_ack_and_postsnapshot() {
        for sample in [3, 4, 5, 6, 7, 8] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (mut exchange, record) = scripted(&fixture);
            exchange.times[sample] = clock(121002);
            let pinned = PinnedSession::admit(exchange, expected()).unwrap();
            assert!(
                pinned.publish(&mut journal, intent, &session).is_err(),
                "sample {sample}"
            );
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), usize::from(sample >= 5));
            if sample == 8 {
                assert_eq!(record.reads, 2);
                assert_eq!(record.samples, 9);
            }
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished(&fixture, &before);
        }
        for changed_boot in [false, true] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let (mut exchange, record) = scripted(&fixture);
            exchange.times[3] = clock(1001);
            if changed_boot {
                exchange.times[3].boot_id = "00000000-0000-4000-8000-000000000003".into();
            }
            let pinned = PinnedSession::admit(exchange, expected()).unwrap();
            assert!(pinned.publish(&mut journal, intent, &session).is_err());
            assert!(record.lock().unwrap().writes.is_empty());
        }
    }
}
