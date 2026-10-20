# ADR-0001: guarded-update design

Status: Accepted (2026-10-09, owner)
Source: the owner's approved design record (design revision r1). This ADR is the public copy; host-specific facts stay in the
owner's infrastructure repo.

## Context

Personal Macs and Raspberry Pis fall behind on updates because updating is
manual and occasionally breaks running services. Homebrew has no supported
downgrade, some casks need sudo, a single shared runtime upgrade (for example
a Node.js revision bump) can restart many services, and release notes are
untrusted text.

guarded-update must keep each host current overnight, screen changes against
that host's real setup before installing, recover from failures, and report.

## Decision

One Rust binary runs a single nightly pass per host: refresh, detect, screen,
apply one dependency group at a time, then report. Code performs every action
and renders every fixed line; a language model only judges release notes and
writes short summaries.

Tags: [discovery] verified on a real host; [research] from outside sources;
[assumed] to be proven by an implementation spike.

### Owner decisions

1. **Rollback where it is impossible:** casks keep no previous version and
   Hermes has no supported way back to an earlier release, so for those the
   recovery step is hold and alert immediately.
2. **Config:** two layers. An optional base file rendered by configuration
   management, plus a local overrides file that only the setup wizard writes.
   `explain` shows which layer each setting came from.
3. **Self-update:** through Homebrew only. Installed from the project's
   tap (`myers-gh1328/tap`), guarded-update is an ordinary Homebrew
   formula, so the nightly run updates it like any other tool, after the
   same safety checks; the schedule runs Homebrew's `bin` link, which
   follows each upgrade. A copy installed any other way is never replaced
   by the tool. (Amended: v1 originally had no self-update.)

### Run shape

- **D1 One scheduled run per night [discovery]:** a launchd job or systemd
  timer runs `guarded-update run`: refresh metadata, detect, screen, apply,
  report. For the whole run it sets `HOMEBREW_NO_AUTO_UPDATE=1` and
  `HOMEBREW_NO_INSTALL_CLEANUP=1`. A lock file stops a second copy. Rejected:
  screening and applying at separate times, because metadata can change in
  between and the installed version must equal the screened version.

  Amendment (2026-10-10, owner): the user picks the time in setup (one
  key; suggested 3:00 am, another time, or none), saved as
  `[schedule] at`, and setup installs the per-user launchd job itself
  (bootout, write, `plutil -lint`, bootstrap, `launchctl print`). The
  job passes the same config, overrides and state paths setup used, and
  a binary in a build folder is first copied to `~/.local/bin`.
  Configuration management can still install its own schedule. No week
  of dry runs is required before the first real run.
- **D2 Subcommands [assumed]:** setup, check, screen, apply, report, run,
  validate, explain, history, approve, auto, ignore. Every command takes
  `--dry-run`.
- **D3 The unit of change is a dependency group [discovery]:**
  `brew upgrade --dry-run` gives the full set an upgrade pulls in; it is
  screened and applied as one unit.
- **D4 Order [assumed]:** plain tools, then service groups, then remote-access
  software, with Hermes last. A run stops starting new groups once its window
  closes. Whenever Hermes is in that night's update set, failure alerts go
  straight to Slack for the whole run.

### What each kind of software can do

| Provider | Detect | Install | Restart | Roll back | Notes |
|---|---|---|---|---|---|
| Homebrew formula | yes | yes | yes | spike | Reinstall the previous bottle from the cache (cleanup is off during the run), then `brew pin`. |
| Homebrew cask (binary) | yes | yes | yes | no | No previous version is kept; hold and alert. |
| Homebrew cask (pkg installer) | yes | no | n/a | no | Needs sudo; reported, never attempted. |
| Hermes | yes | spike | yes | no | Follows `--channel stable`; no tag pin; hold and alert. |
| Pinned in git | yes | alert only | n/a | n/a | Compares the configured pin with PyPI or GitHub. |
| macOS | yes | alert only | n/a | n/a | Reads `softwareupdate -l`; never installs. |

- **D5 Sudo detection by rule [discovery]:** a cask with a `pkg` artifact, or a
  service defined in `/Library/LaunchDaemons` or a root systemd unit, is never
  attempted.
- **D6 Finding affected services [discovery]:** the wizard maps each package to
  services two ways: LaunchAgents whose program path (`ProgramArguments[0]`
  only) points into the Homebrew prefix's `bin` or `opt`; and virtual
  environments built on a Homebrew Python, which get an import check after any
  Python upgrade. `brew services` alone does not cover custom-labelled agents.

  Amendment (2026-10-09): two more link sources, both shown to the user
  with how they were found and confirmable as a group: Homebrew paths in a
  service's other arguments, and Homebrew paths inside a start script under
  the user's home that `ProgramArguments[0]` points at. From a script only
  `<prefix>/bin/<name>` and `<prefix>/opt/<name>` tokens are kept; nothing
  else is stored or printed. Services whose plist exists but is not loaded in
  launchd are listed and skipped. Plists are read with `plutil`, not a
  crate. A group that touches a `requires_root` service is held with
  "restart needs root".

  Amendment (2026-10-10, owner): the scan is saved to a
  generated `services.toml` next to the overrides file instead of being
  written into the overrides as `[services]` entries, and `setup --rescan`
  refreshes it. Restart and health commands are derived at run time, not
  stored. A `[services]` entry in the base config overrides the scan for
  its label. The wizard asks no per-service or per-package questions: four
  general questions, then one checklist of every package on four pages
  (restarts services, apps, tools, by hand). Only the default (suggested:
  `auto`) and the packages that differ from it are saved. Runs compare the
  launchd folders with the saved file (a directory listing, no `plutil`)
  and say when it is out of date.
- **D7 Version comparison per provider [discovery]:** Homebrew `_N` revision
  bumps count as rebuilds. For Hermes, only `vX.Y.Z` release tags count,
  ordered by GitHub release date (its scheme moved from calendar versions to
  `v0.x`).

### Screening

- **D8 Fixed rules first [research]:** user-configured limits run before the
  model, and the model can only hold an update they allowed, never release one
  they held. A "breaking" mention is a soft flag the model can clear with
  evidence.

  Amendment (2026-10-10, owner): the fixed rules are three, each able only
  to hold: wait `wait_days` (default 2) after the first run that saw a
  version; hold major jumps (minor below 1.0; calendar versions excluded);
  hold on configured words in the GitHub release notes between the
  installed and new version (rebuilds skipped; no notes found means the
  rule passes, noted in the plan). The tool works with these rules alone;
  the model check is optional and local-only in v1 (Ollama, LM Studio,
  Hermes, or an address on the network), with online providers after v1.
  Dry runs now write `state.json` to record first sight.

  Amendment (2026-10-10): the model check talks to an
  OpenAI-compatible endpoint the user chose (local or LAN; plain HTTP is
  allowed for it only) with a strict JSON schema, no streaming, a
  180-second timeout and the request passed through the redaction layer.
  `hermes chat` is not used: Hermes is an agent with tools, and release
  notes are untrusted input.

  Amendment (2026-10-11, owner): every AI answer is kept in full in the
  run's history, approvals included: verdict, reason, evidence, whether
  the evidence is really a quote from the notes, the model that answered,
  its raw answer, the notes it read and how long it took. Each answer is
  also logged (`ai_checked`) without the notes and raw answer. Nothing in
  a reason or a quoted line is shortened. Notes are never cut: longer
  notes are read in parts of 12,000 characters, any part that is not ok
  holds, and notes needing more than 16 parts hold without asking. Link
  addresses, bare URLs, commit hashes and author tags are removed first
  (2026-10-19: per-commit notes such as Hermes' were half links and
  held every time); every other word is kept.

  Amendment (2026-10-15, owner): AI now adjudicates host applicability of
  major jumps and warning words rather than running only after those
  flags pass. An explained `ok` may allow a breaking change that does not
  apply to this host; applicable or uncertain breaking changes hold.
  Operational restrictions (root, disabled/report-only, persisted failures,
  non-auto policy) and wait periods remain outside model authority.
  Without AI the conservative major/keyword rules remain unchanged. With
  AI, missing/incomplete/oversized notes or a failed/unexplained review
  hold. The target release needs notes and every published stable release
  in the range needs a nonempty body; unpublished GitHub releases cannot
  be detected. An absent review never clears an existing major flag.
- **D9 Release-note sources [discovery]:** GitHub releases first, then a
  repository CHANGELOG, found from `brew info` source and homepage URLs. Notes
  for every skipped version are joined. Config can name a notes URL per item.
  An optional GitHub token file raises the API rate limit.
  Amendment (2026-10-11): releases are read 100 per page until a page has
  nothing newer than the installed version (up to 10 pages), so prerelease
  floods and backports cannot hide older releases in the range. If the
  pages run out first, or a later page fails, the update is held: rules
  cannot vouch for notes nobody read.
- **D10 Context for the impact check [assumed]:** one redaction layer is the
  only path to the model; it masks secret-shaped values and exact matches of
  every value from referenced secret files. It feeds one of two modes:
  collected context (service arguments, environment variable names,
  allow-listed config files and dependents, assembled before the prompt) or
  read-only tools (the same data behind four tools: read service, read or
  search allow-listed config, list dependents, package info) with a per-item
  call cap and no shell or network. A screening experiment picks the default.
  Amendment (2026-10-13, owner): collected context; the model gets no
  tools. For each service that uses the package, the run reads the
  plist's arguments (read-only `plutil`), takes the config files they
  name (`-flag=/path`, `--flag /path` or a bare path with a config
  extension; file names that suggest secrets are skipped), masks the
  values of secret-named keys, private key blocks and URL passwords, and
  shows them with every part of the notes, at most 12,000 characters per
  file and 24,000 in all. A file that is too long or unreadable is named
  with the reason and the check goes on from the notes; it never holds by
  itself. The model is told to hold only if the change affects something
  the shown configuration uses or relies on by default. A quote from the
  configuration counts as evidence; the history records which files were
  shown, never their text.
  Amendment (2026-10-15): include host OS and architecture explicitly;
  OS version is unknown. No mapped services does not prove an unused CLI,
  and missing/partial/redacted configuration or absent keys do not prove
  feature nonuse. Each service without supplied configuration is marked
  unknown. The model must consider defaults and explain host applicability;
  an uncertain potentially applicable breaking change holds.
- **D11 Model call shape [research]:** fixed-format JSON through
  `response_format` (verdict, reason, evidence), enforced after any thinking
  block; a malformed answer means hold. The prompt includes a short service
  map. Requests stream, because some model routers have an idle timeout.
  Sampling settings are configurable. Destination: an OpenAI-compatible model
  router or `hermes chat -q`.

### Configuration and state

- **D12 Two-layer TOML config [assumed]:** base file plus wizard-only
  overrides; edited with `toml_edit` so comments survive; file mode 0600,
  because restart commands in it run as the user; secrets referenced by path
  or key name, never written in; schema-versioned and validated on every load.
  An invalid config raises an alert and installs nothing.
- **D13 State [assumed]:** one JSON state file (held items, approvals, last
  screened versions and verdicts) plus one history file per run.
  *Amended:* history is for recent runs, not an archive. Files older than
  14 days are deleted after each run, always keeping the newest 10; each
  log moves to `<name>.1` past 1 MB. Not configurable.

### Reporting and alerts

- **D14 Code writes the report [research]:** every fixed line is rendered by
  code; the model writes only one-line change summaries and failure diagnoses.
- **D15 Delivery [discovery]:** the report goes to Slack via
  `chat.postMessage`, or via `hermes send`. Failure alerts prefer direct Slack
  and fall back to Hermes. The token is read only at send time and never
  reaches child processes or logs. Slack buttons are deferred past v1.
- **D16 Logs [assumed]:** JSON lines labelled `service=guarded-update`, passed
  through the redaction layer, collected by the host's log shipper.

### Build and distribution

- **D17 Crates [discovery], amended below:** `toml`, `toml_edit`, `serde_json`, `inquire`,
  `plist`, `semver`, `versions`, `ureq`, `fs4`, `directories`. All MIT or
  Apache-2.0 licensed. `ureq` over `reqwest`: no async runtime is needed.
  Adding any other crate needs the owner's approval.

  Amendment (2026-10-09, owner): dependencies are kept to `serde` (with
  `derive`), `serde_json` and `toml`. Arguments are parsed by hand. HTTPS
  goes through the system `curl` (present on macOS and Debian) instead of
  `ureq`, which removed a TLS stack and its C build. Version comparison is
  in-house instead of `semver`/`versions`. The standard library's
  `File::try_lock` and `std::env::home_dir` replace `fs4` and
  `directories`. The setup wizard uses none of `inquire`, `plist` or
  `toml_edit` (owner decision): stdin prompts plus a checklist that
  puts the terminal in raw mode with `stty` (numbered fallback without a
  terminal), `plutil` for plists, and the overrides file is rewritten
  whole because only the wizard writes it.
- **D18 Releases:** this public repo; CI builds `aarch64-apple-darwin` and
  `aarch64-unknown-linux-gnu` natively on GitHub-hosted runners and attaches
  them to GitHub releases with SHA-256 checksums. The owner's infrastructure
  repo installs the binary and the base config; setup installs the
  schedule (D1).

## Threat model

| Threat | Control |
|---|---|
| Release notes written to trick the model | Verdict-only model, fixed-format output, user limits it cannot override, read-only redacted tools, health checks and rollback |
| Compromised upstream release | Minimum release age, health checks, hold and pin after a failure |
| Secret leakage | One redaction layer; secrets referenced by path; no secrets in child environments; config at 0600 |
| An update that keeps failing | Hold and pin after the first failure; one copy at a time; the time window |
| Privilege escalation | Runs as the normal user; never uses sudo; root-only items reported, never attempted |
| The tool or Hermes breaks | Alert path that skips Hermes; Hermes updated last; it updates itself only as a Homebrew formula, after the same checks |

## Spikes during implementation

- Homebrew rollback by reinstalling the cached bottle.
- Hermes `--channel stable` install, and any rollback path.
- `response_format` passing through a model router.
- Screening experiment: collected context vs read-only tools.

## Consequences

- Formulas whose rollback spike fails fall back to hold and alert, like casks.
- Group restarts can briefly disturb running services; the time window, avoid
  windows and health checks limit this.
- Release-note coverage is incomplete (revision-only bumps have no upstream
  notes), so those rely on fixed rules and health checks.

## Not decided here

- Slack buttons (deferred past v1).
- Model sampling defaults (tuning test in progress).
