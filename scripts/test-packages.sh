#!/usr/bin/env bash
set -euo pipefail
directory=${1:?Package directory required}
for profile in apt-agent apt-remote apt-executor; do
 package=("$directory"/guarded-update-"$profile"_*_armhf.deb)
 [[ ${#package[@]} = 1 && -f ${package[0]} ]]
 control=$(dpkg-deb --ctrl-tarfile "${package[0]}" | tar -tf -)
 [[ $control != *postinst* && $control != *preinst* && $control != *postrm* && $control != *prerm* ]]
 [[ $(dpkg-deb -f "${package[0]}" Architecture) = armhf ]]
 contents=$(dpkg-deb -c "${package[0]}")
 [[ $contents != *private.pem* && $contents != *node_modules* && $contents != *legacy* ]]
 extracted=$(mktemp -d)
 dpkg-deb -x "${package[0]}" "$extracted"
 file "$extracted/usr/bin/guarded-update" | tee /dev/stderr | grep -q 'ELF 32-bit LSB.*ARM'
 bytes=$(stat -c %s "$extracted/usr/bin/guarded-update")
 echo "$profile ARMv7 binary bytes: $bytes"
 if [[ $profile = apt-agent ]]; then
   [[ ! -e $extracted/usr/lib/systemd && ! -e $extracted/usr/share/guarded-update ]]
 else
   [[ -f $extracted/usr/lib/systemd/system/guarded-update-remote.timer ]]
   [[ -f $extracted/usr/share/guarded-update/examples/remote.toml ]]
   # Verify syntax using a synthetic executable path; the artifact is ARMv7.
   sed "s|ExecStart=/usr/bin/guarded-update |ExecStart=/usr/bin/true |" \
     "$extracted/usr/lib/systemd/system/guarded-update-remote.service" > "$extracted/guarded-update-remote.service"
   cp "$extracted/usr/lib/systemd/system/guarded-update-remote.timer" "$extracted/guarded-update-remote.timer"
   systemd-analyze verify "$extracted/guarded-update-remote.service" \
     "$extracted/guarded-update-remote.timer"
 fi
 if [[ $profile = apt-executor ]]; then
   [[ -x $extracted/usr/lib/guarded-update/apt_executor.py ]]
   [[ -f $extracted/usr/share/guarded-update/examples/dispatcher-policy.json ]]
   [[ -f $extracted/usr/lib/systemd/system/guarded-update-executor.timer ]]
   sed "s|ExecStart=.*|ExecStart=/usr/bin/true|" "$extracted/usr/lib/systemd/system/guarded-update-executor.service" > "$extracted/guarded-update-executor.service"
   cp "$extracted/usr/lib/systemd/system/guarded-update-executor.timer" "$extracted/guarded-update-executor.timer"
   systemd-analyze verify "$extracted/guarded-update-executor.service" "$extracted/guarded-update-executor.timer"
   sed "s|ExecStart=/usr/bin/guarded-update |ExecStart=/usr/bin/true |" \
     "$extracted/usr/lib/systemd/system/guarded-update-broker.service" > "$extracted/guarded-update-broker.service"
   cp "$extracted/usr/lib/systemd/system/guarded-update-broker.timer" "$extracted/guarded-update-broker.timer"
   systemd-analyze verify "$extracted/guarded-update-broker.service" \
     "$extracted/guarded-update-broker.timer"
 else
   [[ ! -e $extracted/usr/lib/systemd/system/guarded-update-executor.service ]]
   [[ ! -e $extracted/usr/lib/guarded-update/apt_executor.py ]]
   [[ ! -e $extracted/usr/share/guarded-update/examples/dispatcher-policy.json ]]
   [[ ! -e $extracted/usr/lib/systemd/system/guarded-update-broker.service ]]
 fi
done
