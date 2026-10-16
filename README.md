# guarded-update

guarded-update keeps a self-hosted machine's software current overnight
without manual work, and refuses updates that would break it.

One nightly pass per host:

1. Detect available updates (Homebrew formulas and casks, Hermes Agent stable
   releases, versions pinned in git, macOS).
2. Screen the release notes of every skipped version against this host's real
   setup: operational limits and wait first, then host-specific review in JSON.
3. Update one dependency group at a time inside a time window.
4. Restart and health-check every affected service; on failure restart, then
   roll back or hold, then pin, and alert immediately.
5. Send a short report to Slack (directly or through Hermes).

A per-host config decides what is updated automatically, alerted on, or
ignored. Anything not configured is alert-only; with no config nothing is
updated.

## Status

Pre-release. `run` updates what passed the safety checks and restarts
the services it affects. Rollback and Slack reports arrive in later
versions. The design is in
[docs/adr/0001-guarded-update-design.md](docs/adr/0001-guarded-update-design.md).

## Usage

```bash
guarded-update setup               # answer questions to create the config
guarded-update setup --rescan      # refresh the saved list of services
guarded-update validate            # check the config and run health checks
guarded-update check               # list updates and dependency groups
guarded-update run                 # update what passed the checks
guarded-update run --dry-run       # the same pass, changing nothing
guarded-update explain [item]      # effective settings and their layer
```

Options: `--no-refresh` skips `brew update`; `--config`, `--overrides` and
`--state-dir` override the default paths. `screen`, `apply`,
`report`, `history`, `approve`, `auto` and `ignore` are reserved and report
that they are not available yet.

Exit codes: 0 ok, 1 finished with provider errors, 2 usage error, 3 not
available yet, 4 invalid config or state (nothing updated), 5 another
copy is running.

## Configuration

Two TOML layers, both optional and both mode 0600:

1. `~/.config/guarded-update/base.toml`, for example rendered by
   configuration management;
2. `~/.config/guarded-update/overrides.toml`, written by the setup wizard.

The overrides layer wins per key; `explain` shows which layer each value
came from. Every file must declare `schema_version = 1`; unknown keys are
errors. With no config at all, every item is alert-only. See
[examples/base.toml](examples/base.toml).

## Setup

The first `guarded-update setup` asks each question in turn. Running it
again shows every current setting on one screen instead; press its
number to change just that one, Enter to save, or q to leave without
saving:

```
Settings
  1  Updates by default           auto
  2  Hermes Agent releases        checked
  3  macOS updates                reported
  4  Apps that update themselves  included
  5  Wait after a release         2 days
  6  Big version jumps            held for you
  7  Warning words in notes       held for you
  8  AI check                     off
  9  Nightly run                  3:00 am
  0  Packages                     2 set differently
```

On the first run, setup asks about those settings in that order (the
suggested default policy is `auto`) and ends with every package on one
checklist with four pages:

1. **Restarts services**: packages that running launchd services use.
2. **Apps**: casks. Homebrew keeps no previous version of them.
3. **Tools**: command-line tools; nothing restarts when they update.
4. **By hand**: packages a root service uses and installers that need an
   administrator password. This tool reports them and never updates them.

Keys: ←→ or 1-4 change page, ↑↓ move, `a`, `l` or `i` set the package
under the cursor to auto, alert or ignore, `d` changes the default, Enter
finishes, Ctrl-C leaves without saving. Without a terminal (for example
with piped input) the same list is numbered and changed by typing
numbers and a letter, such as `3 7 l`.

Only the default and the packages that differ from it are written to the
overrides file. If input ends early, nothing is saved.

Setup also saves the service scan to `services.toml` next to the
overrides file. It records, for each launchd service, which Homebrew
packages it uses and how that was found (the program it runs, its Python
environment, or Homebrew paths in its arguments or start script).
Restart and health checks are worked out from it at run time:
`launchctl kickstart -k` and a running process for services kept alive,
`launchctl list` for scheduled jobs. `check`, `run` and `validate` say
when the launchd folders have changed since the scan;
`guarded-update setup --rescan` refreshes the file without asking
anything. Service scanning is macOS only in this version.

Setup also asks when the nightly run should start (suggested 3:00 am;
one key picks it) and installs a per-user launchd job for it, replacing
any earlier one; "Don't run it automatically" removes it. A Mac that is
asleep at that time runs it when it wakes. If setup was started from a
build folder (`target/`), it first copies itself to
`~/.local/bin/guarded-update` and the job runs that copy. Installed with
Homebrew, the job runs Homebrew's `bin` link, so upgrades do not break
it. Scheduling is
macOS only in this version.

To add a link the scan cannot see, or a custom check, put a `[services]`
entry in the base config. It overrides the scan for that label:

```toml
[services."com.example.web"]
packages = ["node@24"]
health = ["curl", "-fsS", "http://127.0.0.1:8080/health"]
# requires_root = true   # never update what this depends on automatically
```

## What a run does

`run` updates each group that is set to `auto` and passed the safety
checks: plain tools first, then groups that restart services. For each
group it runs `brew upgrade`, checks that every package is now at the
version that was screened (even when Homebrew exits with an error, such
as a link conflict, which the report then shows), restarts each affected service and waits up to 30
seconds for its health check, restarting once more if needed. Packages
left below the new version, or every package of a group whose service
did not come back, are held (written to `state.json`), so later runs
leave them alone until you deal with them. There is no rollback yet,
Hermes is not updated by this version, and nothing that needs an
administrator password or a root restart is ever attempted.

## Safety checks

Before an `auto` update is applied, the wait always applies. Without AI,
version and keyword rules provide conservative screening. The dry run
says which check held an update and why:

1. **Wait after a release** (`wait_days`, default 2): counted from the
   first run that saw that version.
2. **Big version jumps** (`hold_major`): 2.x to 3.0, or 0.21 to 0.22 below
   1.0. Calendar versions such as 2026.1 do not count.
3. **Warning words in the release notes** (`hold_words`, `words`): read
   from the package's GitHub releases between the installed and the new
   version. Every release in the range is read, however many there are;
   if some cannot be read, the update is held. Rebuilds have no new
   notes. With AI off, when no notes are found the keyword check passes
   and the dry run says so; a major-jump hold still applies.

```toml
[screening]
wait_days = 2
hold_major = true
hold_words = true
words = ["breaking", "removed", "migration"]
```

### Optional AI check

A model server on this computer or the local network can read the
release notes for actual impact on this host, including major jumps and
warning words. With AI configured, an explained `ok` verdict can allow
these changes when they do not apply to this host. Applicable risks and
uncertain breaking changes hold. Operational restrictions (root restarts,
disabled/report-only items, prior failures and non-auto policies) and wait
periods cannot be overridden by the model.

Missing, incomplete or oversized notes hold when AI is configured. The
target release must have notes, and every published stable release in the
range must have a nonempty body. This cannot detect releases upstream
never published on GitHub. Any model failure (no answer, timeout, invalid
JSON or missing explanation) also holds; there is no silent fallback to
approval when review cannot happen.
Setup finds Ollama and LM Studio on their usual ports, or takes any
OpenAI-compatible endpoint (a model router, vLLM, llama.cpp, or another
computer) and, if it needs one, an API key. A pasted key is saved to
`secrets/ai-key` next to the overrides file (mode 0600); the config only
names that file. Setup lists the models and tests one with a sample
release note before saving.

```toml
[screening.ai]
url = "http://127.0.0.1:11434/v1"   # unset = no AI
model = "qwen3:8b"
# api_key_file = "/path/to/key"     # when the server needs a key
timeout_secs = 180
```

The model sees the host OS and architecture (OS version is unknown),
package name, versions, release notes, mapped services and their config
files, after the redaction layer. No mapped services does not mean an
unused CLI. Unknown usage, missing config and absent keys are not evidence
that a changed feature is unused; implicit defaults matter too.
A config file is one a service names in its launchd arguments (such as
`-config=/opt/homebrew/etc/app/config.yml`); values of keys such as
`password`, `token` or `community`, private keys and passwords in URLs
are removed first, and files named like secrets (`.env`, `*key*`,
`*secret*`) are never read. Services without supplied configuration are
explicitly identified as unknown. Files over
12,000 characters are not shown, and the history file lists which files
were shown but not what they contain. Online AI
services and agents that can run tools (such as Hermes) are not offered,
because release notes are untrusted text.

Long release notes are read in parts, never cut; more than about 96,000
characters holds the update instead. Every answer, approvals included, is
saved in full in the run's history file: the verdict, reason, evidence
(and whether it is really a quote from the notes), the model that
answered, its raw answer and the notes it read.

## Files it writes

- `~/.config/guarded-update/overrides.toml`: your setup answers.
- `~/.config/guarded-update/services.toml`: the generated service scan.
- `~/Library/LaunchAgents/io.github.myers-gh1328.guarded-update.plist`: the
  nightly schedule; its output goes to
  `~/.local/state/guarded-update/logs/launchd.log`.

- `~/.local/state/guarded-update/lock`: one copy at a time.
- `~/.local/state/guarded-update/history/<run-id>.json`: one per run,
  kept for 14 days (the newest 10 runs always stay).
- `~/.local/state/guarded-update/state.json`: held items, approvals, and
  when each waiting version was first seen (written by dry runs too, so
  dry runs count toward the wait).
- `~/.local/state/guarded-update/logs/guarded-update.jsonl`: JSON lines
  labelled `service=guarded-update`.

Each log is moved to `<name>.1` once it passes 1 MB, so the logs never
take more than about 4 MB together.

Every line printed, logged or written to history passes through one
redaction layer first.

## Who it is for, and what it does not do

For an owner/operator running a few personal Apple Silicon Macs and Raspberry
Pis. It does not:

- apply macOS updates (it reports them only);
- run anything as root or with sudo (such items are reported as manual);
- replace its own binary (installed from the Homebrew tap, it is updated
  like any other formula, after the same checks);
- update models, back up data, or touch business or multi-tenant systems.

## Platforms

Release builds: `aarch64-apple-darwin` and `aarch64-unknown-linux-gnu`. One
static binary per target with no extra runtime. Differences between hosts are
configuration only.

## Install

With Homebrew on an Apple Silicon Mac:

```bash
brew install myers-gh1328/tap/guarded-update
guarded-update setup
```

The nightly job then runs Homebrew's link, `$(brew --prefix)/bin/guarded-update`,
so later versions arrive through the nightly run itself, after the same
safety checks as every other package.

Or download the archive for your target from the GitHub release, check it, and
put the binary on your `PATH`:

```bash
shasum -a 256 -c guarded-update-vX.Y.Z-aarch64-apple-darwin.tar.gz.sha256
tar -xzf guarded-update-vX.Y.Z-aarch64-apple-darwin.tar.gz
```

Runtime requirements: `curl` (for release lookups) and, for the Homebrew
provider, `brew`.

Build from a clean clone (Rust stable, 1.94 or later):

```bash
cargo build --release
./target/release/guarded-update --version
```

## Verify changes locally

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

CI (`.github/workflows/ci.yml`) runs the same three checks natively on both
targets for every pull request and push to `main`. Docs-only changes skip it.

There is no coverage tooling yet and no numeric coverage gate. Tests use
fake command runners and HTTP clients, so they need no network and change
nothing on the machine. `clippy.toml` forbids printing outside
`src/output.rs`, so all output goes through the redaction layer.

## Releases and versioning

Semantic versioning with `vMAJOR.MINOR.PATCH` tags; the first useful release
will be `v0.1.0`. Pushing a tag runs `.github/workflows/release.yml`, which
checks the tag matches `Cargo.toml`, runs the checks, builds both targets, and
attaches each `.tar.gz` with a `.sha256` checksum to a GitHub release. Changes
are listed in [CHANGELOG.md](CHANGELOG.md).

## Security and privacy

- Runs as the host's normal user. Never uses sudo.
- Credentials (Slack token, optional GitHub token, model API key) are referenced
  by file path in the config and read only when needed. They are never copied
  into the config, logs, reports, or the model prompt.
- Release notes are untrusted input. The model can only hold an update the
  user's rules allowed; it cannot release a held one or take any action.
- Child processes never receive environment variables whose names look
  secret (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*KEY*`, ...).
- Local data: a TOML config, one JSON state file and one history file per run,
  and JSON-lines logs. Nothing is sent anywhere except release-note fetches,
  the configured model endpoint, and the configured report destination.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Repository posture

- Public. Licensed under either of [Apache-2.0](LICENSE-APACHE) or
  [MIT](LICENSE-MIT), at your option.
- Secret scanning, Dependabot security alerts, SonarCloud and a default-branch
  ruleset (required CI checks, no required reviews) are to be enabled when the
  GitHub repo is created. Dependabot version updates are not enabled.
- Never commit: real configs, state or history files, logs, `.env` files,
  tokens, build output, or local release archives (see `.gitignore`).

## Contributing and support

Single-maintainer project. Issues are welcome; pull requests are not accepted
yet. Best effort, no warranty.
