#!/usr/bin/env bash
# Explicit reporting-only artifact. No install, activation, account creation or keys.
set -euo pipefail
target=${1:?Usage: package-inventory.sh aarch64-apple-darwin output-directory}
output=${2:?Output directory required}
case "$target" in aarch64-apple-darwin) ;; *) echo 'Unsupported inventory release target' >&2; exit 2;; esac
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
cargo build --release --locked --target "$target" --no-default-features --features inventory-agent --bin command-center-inventory
name="command-center-inventory-v${version}-${target}"
mkdir -p "$output/$name/examples"
install -m 0755 "${CARGO_TARGET_DIR:-target}/$target/release/command-center-inventory" "$output/$name/command-center-inventory"
install -m 0644 docs/inventory-agent.md LICENSE-MIT LICENSE-APACHE "$output/$name/"
install -m 0644 examples/inventory/* "$output/$name/examples/"
# A separate executable name prevents replacing any updater variant or Homebrew link.
test ! -e "$output/$name/guarded-update"
tar -C "$output" -czf "$output/$name.tar.gz" "$name"
if command -v sha256sum >/dev/null; then
  (cd "$output" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
else
  (cd "$output" && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
fi
tar -tzf "$output/$name.tar.gz" | grep -q "/command-center-inventory$"
