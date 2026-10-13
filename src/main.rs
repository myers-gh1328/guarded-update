//! guarded-update: a config-driven host updater.
//!
//! This version detects and plans only (`check`, `run --dry-run`,
//! `validate`, `explain`); it installs nothing. See
//! `docs/adr/0001-guarded-update-design.md`.

mod ai;
mod app;
mod apply;
mod cli;
mod config;
mod exec;
mod http;
mod model;
mod output;
mod prompt;
mod providers;
mod redact;
mod scan;
mod schedule;
mod screen;
mod service_config;
mod setup;
mod state;
mod timefmt;
mod tui;
mod version;

use std::process::ExitCode;
use std::time::Duration;

use crate::config::Config;
use crate::exec::SystemRunner;
use crate::http::{CurlHttp, Http};
use crate::output::Output;
use crate::redact::Redactor;

fn http_for(config: &Config) -> Box<dyn Http> {
    Box::new(CurlHttp::new(
        Duration::from_secs(config.timeouts.http_secs),
        config.secrets.github_token_file.clone(),
    ))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = Output::new(Redactor::patterns_only());
    let runner = SystemRunner::new(Duration::from_secs(600));
    ExitCode::from(app::execute(&args, &runner, &http_for, &mut out))
}
