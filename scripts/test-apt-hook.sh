#!/usr/bin/env bash
# Root-only synthetic rejection test on a disposable GitHub-hosted Linux runner.
# No package is installed, no network sources are configured, and Cargo runs later
# as the ordinary runner user. Scratch is left for ephemeral runner teardown.
set -euo pipefail
if [[ $(uname -s) != Linux || $EUID != 0 || ${GUARDED_UPDATE_DISPOSABLE_TEST:-} != 1 || ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ]]; then
  echo 'Requires root on an explicitly opted-in disposable GitHub-hosted Linux runner.' >&2
  exit 2
fi
: "${RUNNER_TEMP:?GitHub runner temporary directory required}"
: "${GUARDED_UPDATE_HOOK_OUTPUT:?Synthetic output directory required}"
case "$GUARDED_UPDATE_HOOK_OUTPUT" in
  "$RUNNER_TEMP"/*) ;;
  *) echo 'Output must be a new child of RUNNER_TEMP.' >&2; exit 2 ;;
esac
[[ $RUNNER_TEMP = /* && $GUARDED_UPDATE_HOOK_OUTPUT != *'/../'* && $GUARDED_UPDATE_HOOK_OUTPUT != *'/./'* ]]
[[ $GUARDED_UPDATE_HOOK_OUTPUT =~ ^/[A-Za-z0-9_./-]+$ ]]
[[ ! -e $GUARDED_UPDATE_HOOK_OUTPUT && ! -L $GUARDED_UPDATE_HOOK_OUTPUT ]]
for tool in apt-get dpkg-deb sha256sum head; do command -v "$tool" >/dev/null; done
umask 022
mkdir -m 0755 -- "$GUARDED_UPDATE_HOOK_OUTPUT"
fixture_dir=$(mktemp -d /tmp/guarded-update-hook.XXXXXX)
mkdir -p "$fixture_dir/package/DEBIAN" "$fixture_dir/package/usr/share/guarded-update-hook-fixture" \
  "$fixture_dir/state/lists/partial" "$fixture_dir/cache/archives/partial" \
  "$fixture_dir/etc/parts" "$fixture_dir/etc/sources" "$fixture_dir/dpkg/info" "$fixture_dir/root"
cat > "$fixture_dir/package/DEBIAN/control" <<'CONTROL'
Package: guarded-update-hook-fixture
Version: 1
Architecture: all
Maintainer: Fixture <fixture@example.invalid>
Description: Synthetic rejection-only APT hook fixture
CONTROL
printf 'synthetic fixture\n' > "$fixture_dir/package/usr/share/guarded-update-hook-fixture/marker"
archive="$GUARDED_UPDATE_HOOK_OUTPUT/fixture.deb"
dpkg-deb --build --root-owner-group "$fixture_dir/package" "$archive"
: > "$fixture_dir/dpkg/status"
: > "$fixture_dir/etc/sources.list"
: > "$fixture_dir/etc/main.conf"
cat > "$fixture_dir/reject-hook" <<HOOK
#!/bin/sh
set -eu
[ "\${APT_HOOK_INFO_FD:-}" = 0 ]
[ "\${DPKG_FRONTEND_LOCKED:-}" = true ]
/bin/cat > '$GUARDED_UPDATE_HOOK_OUTPUT/hook-stream'
exit 73
HOOK
chmod 0700 "$fixture_dir/reject-hook"
cat > "$fixture_dir/apt.conf" <<CONFIG
Dir::State "$fixture_dir/state";
Dir::State::status "$fixture_dir/dpkg/status";
Dir::Cache "$fixture_dir/cache";
Dir::Log "$fixture_dir/log";
Dir::Etc::main "$fixture_dir/etc/main.conf";
Dir::Etc::parts "$fixture_dir/etc/parts";
Dir::Etc::sourcelist "$fixture_dir/etc/sources.list";
Dir::Etc::sourceparts "$fixture_dir/etc/sources";
APT::Sandbox::User "root";
Acquire::Retries "0";
DPkg::Options { "--root=$fixture_dir/root"; "--admindir=$fixture_dir/dpkg"; };
DPkg::Pre-Install-Pkgs { "$fixture_dir/reject-hook"; };
DPkg::Tools::Options::$fixture_dir/reject-hook::Version "3";
DPkg::Tools::Options::$fixture_dir/reject-hook::InfoFD "0";
CONFIG
system_before=$(sha256sum /var/lib/dpkg/status)
isolated_before=$(sha256sum "$fixture_dir/dpkg/status")
# Empty source lists permit acquisition of this local archive only. Do not use
# --no-download: it leaves the volatile local archive filename unset in APT.
set +e
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C APT_CONFIG="$fixture_dir/apt.conf" \
  /usr/bin/apt-get --yes install "$archive" > "$fixture_dir/apt-output" 2>&1
apt_result=$?
set -e
[[ $apt_result != 0 ]]
if [[ ! -s "$GUARDED_UPDATE_HOOK_OUTPUT/hook-stream" ]] || [[ $(head -n 1 "$GUARDED_UPDATE_HOOK_OUTPUT/hook-stream") != 'VERSION 3' ]]; then
  echo 'Expected APT protocol-v3 rejection hook was not captured:' >&2
  tail -n 60 "$fixture_dir/apt-output" >&2
  exit 1
fi
[[ $(sha256sum /var/lib/dpkg/status) = "$system_before" ]]
[[ $(sha256sum "$fixture_dir/dpkg/status") = "$isolated_before" ]]
[[ ! -e /usr/share/guarded-update-hook-fixture/marker ]]
[[ ! -e "$fixture_dir/root/usr/share/guarded-update-hook-fixture/marker" ]]
chmod 0644 "$archive" "$GUARDED_UPDATE_HOOK_OUTPUT/hook-stream"
printf 'APT v3 hook rejected before dpkg; isolated and host status unchanged.\n'
