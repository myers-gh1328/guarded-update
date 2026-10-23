# Agent Guidance: guarded-update

Public Rust repo `myers-gh1328/guarded-update`. Config-driven host updater for
personal infrastructure hosts. Design: `docs/adr/0001-guarded-update-design.md`.
Planning lives outside this repo; it holds code, CI, and public docs only.

## Boundaries

- Public repo: never commit private hostnames, LAN IPs, usernames, absolute
  home paths, secret file locations, or real host configs. Host-specific
  deployment (Ansible role, base config) lives in the owner's
  infrastructure repo, not here. `setup` installs the per-user nightly
  schedule itself (`src/schedule.rs`).
- Dependencies: only `serde` (derive), `serde_json` and `toml`. The setup
  wizard uses stdin prompts, a raw-mode checklist via `stty` (`src/tui.rs`)
  and `plutil`, not `inquire`/`crossterm`/`plist`/`toml_edit`.
  HTTPS uses the system `curl`; version comparison is in `src/version.rs`.
  Adding any crate needs the owner's explicit approval first, and the
  owner wants the dependency tree kept small.
- All output goes through `src/output.rs` (redaction). `clippy.toml` forbids
  `println!`/`eprintln!`/`stdout()` elsewhere; never `derive(Debug)` on a
  type that holds secret values.
- Detection must never change the host: only read-only commands
  (`brew outdated`, `brew upgrade --dry-run`, `brew info`, `hermes --version`,
  `softwareupdate --list`) and HTTPS GETs. Never `hermes update --check`
  (it fetches from git).
- Never use sudo or design a root path; root-only items are reported only.
- It updates itself only as a Homebrew formula from `myers-gh1328/tap`,
  through the same safety checks as any package; never by replacing its
  own binary.

## Build and verify

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

Test-driven: write the failing test first for any behavior change.
No coverage tooling yet.

## GitHub

- Authenticate the way the host's own agent instructions say; never
  commit or print a token or an authenticated remote URL.
- Work on a branch; open a PR; squash-merge only when every check is green.
- Release: bump `Cargo.toml`, update `CHANGELOG.md`, merge, then push a
  `vX.Y.Z` tag on `main`.

## Minimal Linux build variants

- `apt-agent` is a local read-only APT proposal CLI.
- `apt-remote` adds signed HTTPS reporting and polling for remotely managed devices,
  including owner-selected business devices. The user explicitly requested this
  separate opt-in path. Keep the legacy CLI's personal/no-root boundaries intact.
- Remote builds use existing system OpenSSL for P-256 signatures and curl for HTTPS;
  no private keys are bundled. The device signs requests; the controller signs
  approvals. Pin public keys at provisioning. See ADR-0002 and synthetic protocol
  vectors. No installation/execution authority exists in these builds yet.
- Verify default, apt-agent and apt-remote test/clippy profiles independently.

## Explicit remote execution profile

The owner authorized an isolated `apt-executor` profile for explicitly enrolled
remote business devices. This profile alone includes the system Python APT
adapter, root validator and unprivileged controller broker. Its scoped privileged
path does not change the legacy personal/no-root CLI or local reporting profile.
No credentials are packaged; no services or updates activate on package install.
Every transaction requires exact manifest approval, fresh one-use controller
claim, root state/archive verification and the mandatory APT hook. No reboot.
Interrupted execution is held for manual reconciliation and never replayed.
