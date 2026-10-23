# Minimal Linux packages

Build on Linux with an already installed Rust target, appropriate linker and
`dpkg-deb`:

```
bash scripts/package-apt.sh apt-agent armv7-unknown-linux-gnueabihf dist
bash scripts/package-apt.sh apt-remote armv7-unknown-linux-gnueabihf dist
bash scripts/package-apt.sh apt-executor armv7-unknown-linux-gnueabihf dist
```

Each mutually exclusive package contains one feature-selected Linux binary.
`apt-agent` contains no remote configuration or systemd units. Remote profiles add
only a polling service, timer and fictional configuration example. No macOS,
Windows, AI tools, private keys, maintainer scripts or automatic activation are
included. `dpkg -i` does not resolve missing prerequisites; inspect dependencies
before installation. CI builds against Ubuntu 24.04's glibc 2.39 baseline; target
systems must meet that baseline (Debian 13 does). ARMv7 packages are hard-float
`armhf`; confirm the device architecture before choosing an artifact.

Polling remains read-only until separately provisioned execution authorization.
The package never starts an executor or enables a timer. Provisioning must create
a persistent `guarded-update` system account, private configuration and device key
owned by that account (0600), plus the pinned controller public key. The service
requires that explicitly provisioned account. Do not place private keys
in this public repository or package staging tree. Register only the device public
key on the controller, and retain the controller private signing key there.

After verifying configuration, explicitly enable the polling timer using the
host's deployment tooling. Disabling the timer stops future polling; it does not
revoke already issued short-lived execution claims. Revoke controller approvals
and disable the separately configured executor when withdrawing execution access.

Only `apt-executor` also includes `/usr/lib/guarded-update/apt_executor.py` and an
unprivileged execution-claim broker service/timer (five-second polling). It uses
existing system Python and python3-apt; no Python runtime or additional libraries
are bundled. Both timers remain disabled until provisioning explicitly enables
them. The broker retrieves controller-signed claims; it cannot install packages.
Root preparation and application require separate explicit host provisioning.

The executor profile also contains a disabled root cycle service/timer. Explicit
provisioning supplies a root-owned nonempty package selection before activation.
It prepares one transaction, polls without consuming approval, and only attempts
installation after approved status. The mandatory hook remains the authority
boundary and obtains a fresh signed claim. A durable attempt never executes again;
terminal results are retried independently until acknowledged. Future batches
require deliberate new root-owned transaction state, not automatic replay.

APT may copy a selected archive into its cache before the mandatory hook runs.
The adapter inspects that actual unpack path using the same root ownership,
protected ancestry and no-symlink checks, and requires the exact approved package,
version, architecture and SHA-256. The Rust transaction gate still independently
validates the complete action set. A separate `execution-claimed.json` records
result correlation before validation; it is never installation authority or proof
of success. A rejected attempt can report interruption while its attempt marker
remains intact. Do not reset or replay it to repair result reporting.
Archive location is not an identity boundary: a relocated path may be anywhere
with protected root-controlled ancestry and a regular root-owned non-writable
file; symlinks and writable parents are rejected. The independently inspected
bytes and complete package identity must still match the approved manifest.
