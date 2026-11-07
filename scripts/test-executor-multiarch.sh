#!/usr/bin/env bash
# Inspect packaged executors without installing or starting their services.
set -euo pipefail
directory=${1:?Package directory required}
architecture=${2:?Architecture required}
case "$architecture" in
  arm64) machine=AArch64 ;;
  amd64) machine='Advanced Micro Devices X86-64' ;;
  *) echo 'Unsupported architecture' >&2; exit 2 ;;
esac
shopt -s nullglob
packages=("$directory"/guarded-update-apt-executor_*_"$architecture".deb)
[[ ${#packages[@]} = 1 ]]
package=${packages[0]}
[[ $(dpkg-deb -f "$package" Package) = guarded-update-apt-executor ]]
[[ $(dpkg-deb -f "$package" Architecture) = "$architecture" ]]
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
[[ $(dpkg-deb -f "$package" Version) = "$version" ]]
control=$(dpkg-deb --ctrl-tarfile "$package" | tar -tf -)
[[ $control != *preinst* && $control != *postinst* && $control != *prerm* && $control != *postrm* ]]
contents=$(dpkg-deb -c "$package")
[[ $contents != *private.pem* && $contents != *node_modules* ]]
# Scratch remains in CI's temporary directory for post-failure inspection.
extracted=$(mktemp -d)
dpkg-deb -x "$package" "$extracted"
binary="$extracted/usr/bin/guarded-update"
readelf -h "$binary" | grep -F "Machine:" | grep -Fq "$machine"
readelf -l "$binary" | grep -Fq 'Requesting program interpreter'
readelf -d "$binary" | grep -F 'NEEDED' | grep -Fq '[libc.so.6]'
# Reject executables needing symbols newer than the declared glibc baseline.
max_glibc=$(readelf --version-info "$binary" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/^GLIBC_//' | sort -Vu | tail -n 1)
[[ -n "$max_glibc" ]]
printf '%s\n%s\n' "$max_glibc" 2.39 | sort -VC
[[ -x "$extracted/usr/lib/guarded-update/apt_executor.py" ]]
for unit in guarded-update-remote guarded-update-executor guarded-update-broker; do
  [[ -f "$extracted/usr/lib/systemd/system/$unit.service" ]]
  [[ -f "$extracted/usr/lib/systemd/system/$unit.timer" ]]
done
if [[ $architecture = arm64 ]]; then
  qemu-aarch64 -L /usr/aarch64-linux-gnu "$binary" --version
else
  "$binary" --version
fi
