//! Co-installable, reporting-only endpoint agent. No updater modules are linked.
mod inventory;
#[allow(dead_code)]
mod output;
#[allow(dead_code)]
mod redact;
#[allow(dead_code)]
mod timefmt;

fn main() -> std::process::ExitCode {
    inventory::main()
}
