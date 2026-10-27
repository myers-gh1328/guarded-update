#!/usr/bin/env bash
# Hosted/disposable build tooling only. Never installs or activates a target agent.
set -euo pipefail
output=${1:?Usage: build-inventory-linux.sh output-directory}
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl arm-unknown-linux-musleabihf
for target in aarch64-unknown-linux-musl x86_64-unknown-linux-musl arm-unknown-linux-musleabihf; do
 bash scripts/package-inventory.sh "$target" "$output"
 binary="${CARGO_TARGET_DIR:-target}/$target/release/command-center-inventory"
 if readelf -l "$binary" | grep -q INTERP; then
  echo 'Inventory artifact unexpectedly requires a dynamic loader' >&2; exit 1
 fi
 case "$target" in
  aarch64-unknown-linux-musl) qemu-aarch64 "$binary" --version;;
  x86_64-unknown-linux-musl) qemu-x86_64 "$binary" --version;;
  arm-unknown-linux-musleabihf) qemu-arm -cpu arm1176 "$binary" --version;;
 esac
 done
