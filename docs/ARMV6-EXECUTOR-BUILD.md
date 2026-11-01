# ARMv6 APT executor build

The APT executor can be built for ARMv6 hard-float with the Rust
`arm-unknown-linux-musleabihf` target. It is a statically linked executable
packaged as an opt-in Debian `armhf` executor with the same disabled units,
adapter and dependencies as the existing ARMv7 package. It contains no keys,
installation hooks, configuration or automatic service activation.

Build the ARMv6 package into a separate output directory. The conventional
Debian filename, package name, version and architecture are the same as the
ARMv7 package; a filename or package version alone does not distinguish them.
Deployment must pin the exact verified artifact SHA-256 and its source/CI run.
Never mix output directories or infer CPU compatibility from `armhf` alone.

CI builds the release package, checks for an ELF interpreter and install
hooks, and runs it with `qemu-arm -cpu arm1176`. It also runs the synthetic
execution gate and claim tests on that emulator. Emulation is not a device
install, proof of actual-device compatibility, or authorization to upgrade
packages. Device rollout must separately verify the binary, Python/APT adapter,
disabled units, resource limits, preexisting schedules, signed polling and a
rollback before enabling it. An exact transaction still requires separate
review and approval; package installation never authorizes an update or reboot.
