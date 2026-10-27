# Changelog

All notable changes are listed here. Versions follow semantic versioning.

## [0.1.6] - Unreleased

### Added

- Separate opt-in `command-center-inventory` macOS reporting executable and
  hosted archive. Read-only native application/Homebrew collection uses its own
  purpose-bound P-256 identity, atomic single-latest report, burned sequence,
  independent check-ins and bounded retry; existing updater binaries/keys remain
  separate. No services activate on installation.
- Read-only Homebrew selected/all-eligible preparation snapshots, pin exclusions,
  native recipe/artifact metadata and bounded-expiry state/metadata drift checks.
  Central execution stays unavailable until exact frozen native transactions and
  privileges can be proven. macOS system updates remain report-only.
- Native macOS inventory profile checks/artifacts and Windows provider-discovery
  contract checks in hosted CI.

## [0.1.5] - Unreleased

### Fixed

- Root executor response waits consume both request and response spool entries on
  success, rejection or timeout. Late broker responses and interrupted temporary
  writes expire after ten minutes through bounded response-only cleanup. Stale
  cleanup skips symlinks and foreign-owned files; transaction/claim journals stay
  untouched.

## [0.1.4] - Unreleased

### Added

- The opt-in APT executor can poll signed, bounded package-preparation requests
  through its unprivileged broker. Root policy pins device/fleet, allowed package
  names and metadata-refresh permission. Each job retains immutable state;
  preparation never grants installation or reboot authority.
- Interrupted preparation, controller outages and lost publication responses retain
  conservative recovery state. Prepared transactions still require exact human
  approval and the existing fresh one-use execution claim.
- Executor packages include an inactive dispatcher policy example. Local-only
  builds contain no dispatcher, remote credentials or services.

### Fixed

- The opt-in APT executor verifies the actual root-controlled archive path APT
  will unpack, including cache copies, against the approved identity and digest.
- Claims rejected before execution starts retain separate correlation so their
  interrupted result is reported without replaying APT. Correlation cannot prove
  successful installation. Logs use static rejection categories.

## [0.1.3] - 2026-10-19

### Changed

- Release notes lose link addresses, bare URLs, commit hashes and
  author tags before the checks read them; every other word stays.
  Per-commit notes shrink by about half.
- Notes up to about 192,000 characters (16 parts) are read, up from
  96,000, so long release ranges such as Hermes 0.21 -> 0.22 are
  checked instead of always held.

## [0.1.2] - 2026-10-15

### Changed

- AI screening now reviews major upgrades and breaking-change warnings
  to decide whether they affect this computer, instead of blocking them
  before the model can review them. Without AI, the existing major-version
  and keyword checks still apply. Waiting periods and operational
  restrictions, such as root-required restarts, remain enforced.
- Reviews include the host OS and architecture and identify missing
  configuration or usage information. No mapped services does not mean
  a command-line tool is unused.
- With AI enabled, updates are held when release notes are missing or
  incomplete, including a missing target release or empty release body.
  Failed reviews and verdicts without an explanation also hold the update.
  Review decisions are recorded in run history.

## [0.1.1] - 2026-10-13

### Added

- The AI check sees each affected service's config files (named in its
  launchd arguments, with secret values removed), so a change that the
  configuration does not use no longer holds the update. A quote from
  the configuration counts as evidence, and the history lists which
  files were shown.

### Changed

- CI and release workflows use the Node.js 24 versions of the GitHub
  actions (`checkout@v7`, `upload-artifact@v7`, `download-artifact@v8`).

## [0.1.0] - 2026-10-11

### Added

- Install with `brew install myers-gh1328/tap/guarded-update`. Setup
  then schedules Homebrew's `bin` link instead of the versioned Cellar
  path, so the nightly run keeps working after upgrades and updates
  guarded-update itself like any other formula.
- The project lives at `myers-gh1328/guarded-update`; the nightly job is
  now `io.github.myers-gh1328.guarded-update`, and setup removes a job
  saved under the old `io.github.aegir-tech` name.
- Every AI answer is saved in full in the run's history, approvals
  included: verdict, reason, evidence and whether it is a real quote from
  the notes, the model that answered, its raw answer and the notes it
  read. Hold reasons and quoted lines are no longer shortened.
- All release notes between the installed and the new version are read:
  GitHub releases are fetched page by page (previously only the newest
  30, which missed most of copilot-cli's range), long notes go to the AI
  in parts instead of being cut at 12,000 characters, and notes that
  cannot all be read hold the update.
- Old results clean themselves up: history files older than 14 days are
  deleted (the newest 10 runs always stay), and a log over 1 MB is moved
  to `<name>.1` before the next run. Nothing to configure.
- Setup questions share one layout: a title, one line of explanation,
  aligned options with a highlight (arrow keys or a number), and a hint
  line. Each answered question is replaced by a `✓ Title  answer` line,
  so a first run ends with a summary instead of a TOML preview. The
  package checklist uses the alternate screen, so earlier answers stay.
- Running setup again opens a settings menu with every current answer;
  one key changes a single setting, Enter saves, q leaves unchanged.
- Setup schedules the nightly run: one key picks the time (suggested
  3:00 am, another time, or none), saved as `[schedule] at`, and setup
  installs a per-user launchd job that runs `run` with the same config
  and state paths. A binary in a build folder is copied to
  `~/.local/bin` first.
- `run` updates: groups that passed the checks, plain tools first, then
  service groups; `brew upgrade`, a version check, restart and health
  check (two restarts) of affected services. The installed versions, not
  Homebrew's exit code, decide success; Homebrew's error lines are shown
  in the report. Packages left behind are held in `state.json`. No rollback yet; Hermes is skipped. State is
  saved after every group; runs in the same second keep separate history.
- Safety checks before an `auto` update, without AI: wait `wait_days`
  (default 2) after a version is first seen, hold big version jumps, and
  hold on warning words in GitHub release notes. Setup asks about each.
  Dry runs record first sight in `state.json`.
- Optional AI check of release notes through a local OpenAI-compatible
  server (Ollama, LM Studio or a network address), with a strict JSON
  verdict; it can only hold, and a failure holds. Setup finds local
  servers or takes any OpenAI-compatible endpoint with an optional API
  key (pasted hidden, saved to a 0600 file), lists models and runs a test
  call.
- Setup answers y/n and numbered questions with one keypress.
- `setup`: four questions, then a checklist of every package on four
  pages (restarts services, apps, tools, by hand), driven by arrow keys
  with a numbered fallback without a terminal. Only the default and the
  packages that differ from it are written to the overrides file (0600).
- `services.toml`: the saved launchd scan (program, venv, arguments and
  start-script links; services that are not loaded are skipped). Restart
  and health checks are derived from it at run time. `setup --rescan`
  refreshes it; `check`, `run` and `validate` say when it is out of date.
- `[services]` config overrides the scan per label; `validate` runs health checks; groups that touch a
  root service are held.
- `check`, `run --dry-run`, `validate` and `explain`. Detection and planning
  only; nothing is updated.
- Two-layer TOML config (base + overrides) with schema validation, mode 0600
  enforcement and per-key origin for `explain`.
- Providers: Homebrew formulas and casks (rebuild vs version, dependency
  groups from `brew upgrade --dry-run`, pkg casks reported as needing sudo),
  Hermes stable releases, versions pinned in git (PyPI or GitHub), and macOS
  (alert only).
- State file, one history file per run, and a single-instance lock.
- Redaction layer for every output path; JSON-lines logs; per-command
  timeouts; secret-looking environment variables withheld from children.
- Dependencies limited to `serde`, `serde_json` and `toml`; HTTPS through
  the system `curl`.
- Binary skeleton (`--version`, `--help`).
- CI: fmt, clippy with warnings as errors, and tests on aarch64-apple-darwin
  and aarch64-unknown-linux-gnu.
- Release workflow: tagged builds for both targets with SHA-256 checksums.
- ADR-0001 recording the design.
