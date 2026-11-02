"""Fixed opt-in publisher unit properties; not a service launcher/activation API.

Root access to PID1's private socket confers broad unit-management authority.
The trusted fixed wrapper/data-only protocol is the boundary limiting operations;
capabilities/filesystem masks do not sandbox malicious code with that socket.
"""

CACHE='/var/cache/command-center-inventory-refresh'
STATE='/var/lib/command-center-inventory-refresh'
RUNTIME='/run/command-center-inventory-refresh'
POLICY='/etc/command-center-inventory-refresh'


def publisher_properties():
    writable=' '.join((CACHE,STATE,RUNTIME,POLICY+'/apt'))
    return ('User=0','Group=0','Type=exec','ExitType=main','RemainAfterExit=no','Restart=no',
        'KillMode=control-group','KillSignal=SIGKILL','SendSIGKILL=yes','TimeoutStopSec=1','OOMPolicy=kill',
        'MemoryAccounting=yes','TasksMax=8','NoNewPrivileges=yes',
        'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE','AmbientCapabilities=',
        'ProtectSystem=strict','ProtectHome=yes','ProtectControlGroups=yes','RestrictNamespaces=yes',
        'PrivateDevices=yes','PrivateTmp=yes','PrivateNetwork=yes',
        'InaccessiblePaths=/tmp /var/tmp /dev/shm -/opt -/srv -/var/opt -/usr/local/etc -/usr/local/var',
        'TemporaryFileSystem=/etc:ro /var/lib:ro /run:ro /run/systemd/system:ro,nodev,nosuid,noexec,size=4k,nr_inodes=16',
        'BindReadOnlyPaths='+POLICY+' /etc/passwd /etc/group /etc/nsswitch.conf /etc/hosts '+
            '/run/systemd/private /var/lib/dpkg /run/guarded-update-executor.lock',
        'BindPaths='+writable,'ReadWritePaths='+writable)
