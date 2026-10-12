# Changelog

All notable changes are listed here. Versions follow semantic versioning.

## [Unreleased]

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
