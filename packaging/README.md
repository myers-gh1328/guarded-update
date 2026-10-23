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
