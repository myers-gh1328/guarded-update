// Disconnected request foundation; runtime integration is separately gated.
#[cfg(any(target_os = "macos", test))]
mod brew;
#[cfg(test)]
mod clock;
#[cfg(test)]
mod lifecycle;
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
mod process;
#[cfg(test)]
mod reporter_frame;
#[cfg(test)]
mod reporter_obs;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod reporter_pipe;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod reporter_status;
#[cfg(test)]
mod requests;
mod state;
mod transport;
use process::{SystemTools, Tools};
use serde_json::{Value, json};
use state::{Lock, Store};
use transport::{Config, Response};

trait Network {
    fn post(&self, config: &Config, path: &str, body: &str, now: u64) -> Result<Response, String>;
}
struct Https;
impl Network for Https {
    fn post(&self, config: &Config, path: &str, body: &str, now: u64) -> Result<Response, String> {
        transport::post(config, path, body, now)
    }
}

fn while_collecting(
    collect: impl FnOnce() -> Result<Value, String> + Send,
    mut heartbeat: impl FnMut(),
    interval: std::time::Duration,
) -> Result<Value, String> {
    std::thread::scope(|scope| {
        let collector = scope.spawn(collect);
        let mut next = std::time::Instant::now() + interval;
        while !collector.is_finished() {
            if std::time::Instant::now() >= next {
                heartbeat();
                next += interval;
            }
            std::thread::sleep(interval.min(std::time::Duration::from_millis(50)));
        }
        collector
            .join()
            .map_err(|_| "Inventory collection failed")?
    })
}

fn collect_native(tools: &impl Tools, id: &str, started: &str) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    return linux::collect(tools, id, started);
    #[cfg(target_os = "macos")]
    return macos::collect(tools, id, started);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err("Native inventory collection requires Linux or macOS".into())
}

fn pass(
    config: &Config,
    store: &mut Store,
    tools: &impl Tools,
    network: &impl Network,
    now: u64,
) -> Result<(), String> {
    let latest_result = store.latest();
    let invalid_latest = latest_result.is_err();
    let latest = latest_result.unwrap_or(None);
    let descriptor=latest.as_ref().map(|report|->Result<Value,String> {
        let bytes=state::read(&store.dir.join("latest.json"),state::MAX_REPORT)?;
        Ok(json!({"report_id":report["report_id"],"sequence":report["sequence"],"sha256":tools.sha256(&bytes)?,"collected_at":report["collected_at"]}))
    }).transpose()?;
    let checkin = json!({"schema_version":1,"enrollment_id":config.enrollment_id,"agent_version":env!("CARGO_PKG_VERSION"),
        "latest_report":descriptor,"collection_state":if store.schedule.permanent_error || invalid_latest || store.schedule.collection_error {"error"} else {"idle"},"refresh_result":null});
    // Always check in before upload retry admission. A queued/invalid report never suppresses liveness.
    let response = network.post(
        config,
        "/api/agent/v1/inventory/check-ins",
        &checkin.to_string(),
        now,
    );
    let response = match response {
        Ok(response) if response.status >= 500 => None,
        Ok(response) => Some(response),
        Err(_) => None,
    };
    if let Some(response) = &response
        && (response.status != 200
            || !response.json_content_type
            || response.raw_body.len() > 65_536
            || response.body["schema_version"] != 1
            || response.body["reporting_enabled"] != true)
    {
        return Err("Inventory check-in rejected or reporting disabled".into());
    }
    if invalid_latest {
        return Err("Latest inventory report invalid; error check-in continues; reconcile state without resetting sequence".into());
    }
    if let Some(report) = &latest
        && let Some(response) = &response
    {
        let digest = descriptor
            .as_ref()
            .and_then(|v| v["sha256"].as_str())
            .ok_or("Latest digest unavailable")?;
        if state::matches_receipt(report, digest, &response.body["receipt"]) {
            store.schedule.acknowledged_sha256 = Some(digest.into());
            store.schedule.permanent_error = false;
            store.save()?;
        }
    }
    let revision = if let Some(response) = &response {
        response.body["source_revision"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= 9_007_199_254_740_991)
            .ok_or("Invalid inventory source revision")?
    } else {
        store.schedule.source_revision
    };
    if revision == 0 {
        return Err(
            "Initial inventory check-in unavailable; no source authority cached yet".into(),
        );
    }
    store.schedule.source_revision = revision;
    store.save()?;
    let source_changed = latest
        .as_ref()
        .is_some_and(|report| report["source_revision"] != revision);
    let next_collection = if store.schedule.next_collection_at == 0 {
        store.schedule.collected_at_secs.saturating_add(86400)
    } else {
        store.schedule.next_collection_at
    };
    if latest.is_none() || source_changed || now >= next_collection {
        let sequence = store.reserve()?;
        store.schedule.collection_error = true;
        store.save()?;
        let id = transport::report_id()?;
        let started = crate::timefmt::rfc3339(now as i64);
        let mut collecting_checkin = checkin.clone();
        collecting_checkin["collection_state"] = json!("collecting");
        let scan = while_collecting(
            || collect_native(tools, &id, &started),
            || {
                let _ = network.post(
                    config,
                    "/api/agent/v1/inventory/check-ins",
                    &collecting_checkin.to_string(),
                    crate::timefmt::now_secs().max(0) as u64,
                );
            },
            std::time::Duration::from_secs(300),
        )?;
        let collected = scan["completedAt"]
            .as_str()
            .ok_or("Collection timestamp missing")?;
        let report = json!({"schema_version":1,"enrollment_id":config.enrollment_id,"report_id":id,"sequence":sequence,
            "source_revision":revision,"refresh_request_id":null,"collected_at":collected,"scan":scan,
            "metadata_refresh":{"result":"deferred","successful_checked_at":null,"policy_generation":null,"reason":"not_configured"}});
        store.replace(&report, now)?;
    }
    if response.is_none() {
        return Err("Check-in unavailable; latest local inventory retained for retry".into());
    }
    if now < store.schedule.retry_at || store.schedule.permanent_error {
        return Ok(());
    }
    let Some(report) = store.latest()? else {
        return Ok(());
    };
    let bytes = state::read(&store.dir.join("latest.json"), state::MAX_REPORT)?;
    let digest = tools.sha256(&bytes)?;
    if store.schedule.acknowledged_sha256.as_deref() == Some(&digest) {
        return Ok(());
    }
    let body = std::str::from_utf8(&bytes).map_err(|_| "Invalid latest report encoding")?;
    let result = network.post(
        config,
        "/api/agent/v1/inventory/reports",
        body,
        crate::timefmt::now_secs().max(0) as u64,
    );
    match result {
        Ok(response)
            if matches!(response.status, 200 | 201)
                && response.json_content_type
                && response.raw_body.len() <= 65_536
                && state::matches_receipt(&report, &digest, &response.body) =>
        {
            store.schedule.acknowledged_sha256 = Some(digest);
            store.schedule.retry_delay = 0;
            store.schedule.retry_at = 0;
            store.save()
        }
        result => {
            let mut retry_after = 0;
            if let Ok(response) = &result {
                retry_after = response.retry_after;
                if (400..500).contains(&response.status) && !matches!(response.status, 408 | 429) {
                    store.schedule.permanent_error = true;
                }
            }
            store.schedule.retry_delay =
                (store.schedule.retry_delay.saturating_mul(2)).clamp(300, 3600);
            let jitter = u64::from_str_radix(&transport::random_hex(2)?, 16)
                .map_err(|_| "Retry jitter unavailable")?
                % 61;
            store.schedule.retry_at = now + store.schedule.retry_delay.max(retry_after) + jitter;
            store.save()?;
            Err(if store.schedule.permanent_error {
                "Inventory report rejected; check-in continues, operator reconciliation required"
            } else {
                "Inventory upload deferred with bounded retry; check-in continues"
            }
            .into())
        }
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["--version"] {
        crate::output::Output::new(crate::redact::Redactor::patterns_only()).stdout(concat!(
            "command-center-inventory ",
            env!("CARGO_PKG_VERSION")
        ));
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "prepare" | "verify-preparation"))
    {
        #[cfg(target_os = "macos")]
        return preparation_cli(&args);
        #[cfg(not(target_os = "macos"))]
        return Err("Local Homebrew preparation requires macOS".into());
    }
    if args.len() != 3
        || !matches!(args[0].as_str(), "sync" | "initialize")
        || args[1] != "--config"
    {
        return Err("Usage: command-center-inventory sync|initialize --config PATH".into());
    }
    let config = Config::load(std::path::Path::new(&args[2]))?;
    let _lock = Lock::acquire(&config.state_dir)?;
    if args[0] == "initialize" {
        return Store::initialize(&config.state_dir, &config.enrollment_id);
    }
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return Err("Native inventory collection requires Linux or macOS".into());
    }
    let mut store = Store::load(&config.state_dir, &config.enrollment_id)?;
    pass(
        &config,
        &mut store,
        &SystemTools,
        &Https,
        crate::timefmt::now_secs().max(0) as u64,
    )
}

#[cfg(target_os = "macos")]
fn preparation_cli(args: &[String]) -> Result<(), String> {
    if args.len() < 5 || args[1] != "--provider" || args[3] != "--selection" {
        return Err("Usage: command-center-inventory prepare|verify-preparation --provider homebrew_formula|homebrew_cask --selection all|comma,separated,packages [--snapshot PATH]".into());
    }
    let selected = if args[4] == "all" {
        None
    } else {
        Some(args[4].split(',').map(str::to_owned).collect::<Vec<_>>())
    };
    if selected
        .as_ref()
        .is_some_and(|items| items.iter().any(|item| !brew::package_name(item)))
    {
        return Err("Invalid package selection".into());
    }
    let current = brew::snapshot(&SystemTools, &args[2], selected.as_deref())?;
    let output = crate::output::Output::new(crate::redact::Redactor::patterns_only());
    if args[0] == "verify-preparation" {
        if args.len() != 7 || args[5] != "--snapshot" {
            return Err("Verification requires --snapshot PATH".into());
        }
        let original: Value = serde_json::from_slice(&state::read(
            std::path::Path::new(&args[6]),
            state::MAX_REPORT,
        )?)
        .map_err(|_| "Invalid preparation snapshot")?;
        brew::verify(&original, &current)?;
        output.stdout(
            "Homebrew state and metadata match the snapshot; execution remains unavailable.",
        );
    } else {
        if args.len() != 5 {
            return Err("Unexpected preparation argument".into());
        }
        output.stdout(&current.to_string());
    }
    Ok(())
}

pub fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            crate::output::Output::new(crate::redact::Redactor::patterns_only()).stderr(&message);
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct FakeNetwork {
        offline: bool,
        calls: RefCell<Vec<Value>>,
    }
    impl Network for FakeNetwork {
        fn post(&self, _: &Config, path: &str, body: &str, _: u64) -> Result<Response, String> {
            self.calls
                .borrow_mut()
                .push(json!({"path":path,"body":serde_json::from_str::<Value>(body).unwrap()}));
            if self.offline {
                return Err("synthetic offline".into());
            }
            Ok(Response {
                status: 200,
                body: json!({"schema_version":1,"reporting_enabled":true,"source_revision":1,"receipt":null}),
                retry_after: 0,
                raw_body: Vec::new(),
                json_content_type: true,
            })
        }
    }
    struct FakeTools;
    struct FailedCollector;
    impl Tools for FailedCollector {
        fn text(&self, _: &str, _: &[&str], _: usize) -> Result<String, String> {
            Err("synthetic collection failure".into())
        }
        fn sha256(&self, bytes: &[u8]) -> Result<String, String> {
            SystemTools.sha256(bytes)
        }
    }
    impl Tools for FakeTools {
        fn text(&self, program: &str, _: &[&str], _: usize) -> Result<String, String> {
            match program {
                "/bin/hostname" => Ok("synthetic.test".into()),
                "/usr/bin/uname" => Ok("arm64".into()),
                "/usr/bin/sw_vers" => Ok("15".into()),
                "/usr/sbin/system_profiler" => Ok("{\"SPApplicationsDataType\":[]}".into()),
                _ => Err("synthetic unavailable".into()),
            }
        }
        fn sha256(&self, bytes: &[u8]) -> Result<String, String> {
            SystemTools.sha256(bytes)
        }
    }
    fn config(dir: &std::path::Path) -> Config {
        Config {
            schema_version: 1,
            server_url: "https://example.test".into(),
            device_id: "synthetic".into(),
            enrollment_id: "epoch".into(),
            key_id: "inventory-only".into(),
            reporting_private_key_file: dir.join("unused-key"),
            state_dir: dir.to_owned(),
        }
    }
    fn store() -> (state::tests::TestDir, Store) {
        let temp = state::tests::TestDir::new();
        Store::initialize(&temp.0, "epoch").unwrap();
        let store = Store::load(&temp.0, "epoch").unwrap();
        (temp, store)
    }
    #[test]
    fn malformed_latest_still_sends_error_checkin_without_resetting_sequence() {
        let (temp, mut store) = store();
        store.reserve().unwrap();
        state::atomic(&temp.0.join("latest.json"), b"broken").unwrap();
        let network = FakeNetwork {
            offline: false,
            calls: RefCell::new(vec![]),
        };
        assert!(pass(&config(&temp.0), &mut store, &FakeTools, &network, 100).is_err());
        assert_eq!(network.calls.borrow().len(), 1);
        assert_eq!(
            network.calls.borrow()[0]["body"]["collection_state"],
            "error"
        );
        assert_eq!(
            network.calls.borrow()[0]["body"]["latest_report"],
            Value::Null
        );
        assert_eq!(store.schedule.sequence, 1);
    }
    #[test]
    fn failed_collection_is_visible_on_next_independent_checkin() {
        let (temp, mut store) = store();
        let network = FakeNetwork {
            offline: false,
            calls: RefCell::new(vec![]),
        };
        assert!(
            pass(
                &config(&temp.0),
                &mut store,
                &FailedCollector,
                &network,
                100
            )
            .is_err()
        );
        assert!(
            pass(
                &config(&temp.0),
                &mut store,
                &FailedCollector,
                &network,
                400
            )
            .is_err()
        );
        assert_eq!(
            network.calls.borrow()[1]["body"]["collection_state"],
            "error"
        );
        assert_eq!(store.schedule.sequence, 2);
    }
    #[test]
    fn offline_controller_does_not_stop_due_daily_local_collection() {
        let (temp, mut store) = store();
        store.schedule.source_revision = 1;
        store.save().unwrap();
        let network = FakeNetwork {
            offline: true,
            calls: RefCell::new(vec![]),
        };
        assert!(pass(&config(&temp.0), &mut store, &FakeTools, &network, 100000).is_err());
        let latest = store.latest().unwrap().unwrap();
        assert_eq!(latest["sequence"], 1);
        assert_eq!(latest["source_revision"], 1);
        assert_eq!(network.calls.borrow().len(), 1);
    }
    #[test]
    fn upload_backoff_never_suppresses_checkin() {
        let (temp, mut store) = store();
        store.reserve().unwrap();
        store.replace(&json!({"enrollment_id":"epoch","sequence":1,"report_id":"old","source_revision":1,"collected_at":"2026-01-01T00:00:00Z"}),100).unwrap();
        store.schedule.retry_at = 999;
        store.save().unwrap();
        let network = FakeNetwork {
            offline: false,
            calls: RefCell::new(vec![]),
        };
        assert!(pass(&config(&temp.0), &mut store, &FakeTools, &network, 200).is_ok());
        assert_eq!(network.calls.borrow().len(), 1);
        assert_eq!(store.schedule.sequence, 1);
    }
    #[test]
    fn slow_collection_keeps_independent_heartbeat_deadlines() {
        let mut heartbeats = 0;
        let (finished, wait) = std::sync::mpsc::sync_channel(1);
        let report = while_collecting(
            move || {
                // Collection may complete only after the observable heartbeat
                // requirement, regardless of hosted-runner scheduling speed.
                wait.recv_timeout(std::time::Duration::from_secs(10))
                    .map_err(|_| "Independent heartbeats did not run")?;
                Ok(json!({"complete":true}))
            },
            || {
                heartbeats += 1;
                if heartbeats == 2 {
                    finished.send(()).unwrap();
                }
            },
            std::time::Duration::from_millis(1),
        )
        .unwrap();
        assert!(heartbeats >= 2);
        assert_eq!(report["complete"], true);
    }
}
