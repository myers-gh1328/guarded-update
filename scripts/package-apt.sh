#!/usr/bin/env bash
# Build an explicit Linux-only package. Requires existing Rust target/linker and dpkg-deb.
set -euo pipefail
profile=${1:?Usage: package-apt.sh apt-agent|apt-remote|apt-executor target output-dir}
target=${2:?Rust Linux target required}
output=${3:?Output directory required}
case "$profile" in apt-agent|apt-remote|apt-executor) ;; *) echo 'Unsupported profile' >&2; exit 2;; esac
case "$target" in
 armv7-unknown-linux-gnueabihf) architecture=armhf;;
 aarch64-unknown-linux-gnu) architecture=arm64;;
 x86_64-unknown-linux-gnu) architecture=amd64;;
 *) echo 'Only supported Linux GNU targets can be packaged' >&2; exit 2;;
esac
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
command -v dpkg-deb >/dev/null
cargo build --release --locked --target "$target" --no-default-features --features "$profile"
mkdir -p "$output"
output=$(cd "$output" && pwd)
stage=$(mktemp -d)
# Build scratch remains for inspection; disposable CI tears it down.
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/doc/guarded-update-$profile"
install -m 0755 "${CARGO_TARGET_DIR:-target}/$target/release/guarded-update" "$stage/usr/bin/guarded-update"
dependencies='apt, libc6 (>= 2.39), libgcc-s1'
conflicts="guarded-update-apt-agent, guarded-update-apt-remote, guarded-update-apt-executor"
conflicts=$(printf '%s' "$conflicts" | sed "s/guarded-update-$profile, //; s/, guarded-update-$profile//")
if [[ $profile != apt-agent ]]; then
 dependencies+=', curl, openssl'
 mkdir -p "$stage/usr/lib/systemd/system" "$stage/usr/share/guarded-update/examples"
 install -m 0644 packaging/guarded-update-remote.service packaging/guarded-update-remote.timer "$stage/usr/lib/systemd/system/"
 install -m 0644 examples/remote/remote.toml "$stage/usr/share/guarded-update/examples/remote.toml"
fi
if [[ $profile = apt-executor ]]; then
 dependencies+=', python3, python3-apt, dpkg'
 mkdir -p "$stage/usr/lib/guarded-update"
 install -m 0755 scripts/apt_executor.py "$stage/usr/lib/guarded-update/apt_executor.py"
 install -m 0644 packaging/guarded-update-executor.service packaging/guarded-update-executor.timer packaging/guarded-update-broker.service packaging/guarded-update-broker.timer "$stage/usr/lib/systemd/system/"
fi
cat > "$stage/DEBIAN/control" <<CONTROL
Package: guarded-update-$profile
Version: $version
Architecture: $architecture
Maintainer: guarded-update maintainers <maintainers@example.invalid>
Depends: $dependencies
Conflicts: $conflicts
Replaces: $conflicts
Section: admin
Priority: optional
Description: Minimal Linux APT agent ($profile)
 Explicit opt-in artifact. No keys, provisioning, automatic service activation,
 or prerequisite installation is performed by this package.
CONTROL
install -m 0644 packaging/README.md "$stage/usr/share/doc/guarded-update-$profile/README"
dpkg-deb --build --root-owner-group "$stage" "$output/guarded-update-${profile}_${version}_${architecture}.deb"
