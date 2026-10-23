# Current progress

## Current step

Dormant APT execution gate implemented behind `apt-executor`. The feature implies
`apt-remote`; existing artifacts do not include the gate. No installation command,
root execution path, provisioning, deployment, or production adapter exists.

## Evidence

Test-first: parser and manifest/gate tests first failed to compile because their
APIs did not exist; bounded manifest ingestion test also failed before its API was
implemented. Nine gate tests pass using synthetic inputs only. An independent review requested
architecture token tightening; its regression failed first, then passed after the
fix. New-dependency and duplicate-configuration cases are explicitly covered.

Verified before commit: default suite 189 tests, local-agent suite 25 tests,
remote-agent suite 34 tests, executor suite 43 tests; formatting and default and
executor Clippy passed with warnings denied. These are native development checks,
not ARM runtime or live APT integration verification.

## Next exact action

Review ADR-0003 and gate boundaries; implement a trusted archive/provenance adapter
and disposable Linux protocol-v3 integration tests before adding any dispatcher.
Fresh signed single-use claims, root-safe paths, journaling and reconciliation are
still mandatory. Reporting approval signatures never authorize installation.

## Latest inherited fix and verification

Cherry-picked the reporting branch's explicit remote-lock release fix after the
gate commit. Reverified executor suite: 44 tests passed; executor Clippy with
warnings denied and formatting also passed. Working tree is ready for parent
review; no push, release, deployment or live update was performed.

## Disposable integration harness prepared

Added the GitHub-hosted Linux/root/explicit-opt-in rejection harness and ignored
Rust test consuming its actual hook stream and synthetic archive. The test-only
archive adapter was introduced after its test failed to compile. No CI job is
wired here; the parent owns workflow changes and must review before pushing.

Native checks: 44 tests passed, one Linux integration test intentionally ignored;
formatting, Clippy with warnings denied, Bash syntax and ShellCheck passed. Running
the harness without disposable Linux/root opt-in exited 2 as required. No sudo,
APT invocation, fixture build or package operation ran on the development host.

Next exact action: wire and run the disposable Linux job, then inspect its evidence
before claiming APT hook integration works. Production adapters, claims and
dispatch remain absent.

## CI integration

Rebased on merged reporting main. Added executor native matrix profiles and a
disposable Ubuntu rejection job. Fresh local executor run: 44 passed, one
integration test ignored; formatting, Clippy and Bash syntax passed. Pending CI
proof of actual hook capture. No production execution adapter exists.
