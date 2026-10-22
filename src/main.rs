//! OS-specific entry points. The APT artifact excludes the legacy module tree.
#[cfg(not(feature = "apt-agent"))]
include!("legacy.rs");

#[cfg(feature = "apt-remote")]
mod agent_protocol;
#[cfg(feature = "apt-agent")]
mod apt_agent;
#[cfg(feature = "apt-agent")]
#[allow(dead_code)]
#[path = "exec.rs"]
mod exec;
#[cfg(feature = "apt-agent")]
#[allow(dead_code)]
mod output;
#[cfg(feature = "apt-agent")]
#[allow(dead_code)]
mod redact;
#[cfg(feature = "apt-agent")]
#[allow(dead_code)]
mod timefmt;

#[cfg(feature = "apt-agent")]
fn main() -> std::process::ExitCode {
    apt_agent::main()
}
