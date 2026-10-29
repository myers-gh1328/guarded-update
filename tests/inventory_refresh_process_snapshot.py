"""Pure hosted fixture decoding; byte input is untrusted, never a PID witness."""
from inventory_refresh_cgroup_witness import process_start_ticks
from inventory_refresh_reporter_parent import validate_process_view
from inventory_refresh_resources import mount_rows
from inventory_refresh_worker import validate_kernel_identity

CGROUP=b'0::/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service\n'


def validate_snapshot(pid,stat,status,cgroup,mountinfo,device):
    try:
        assert type(device) is tuple and len(device)==2 and all(type(v) is int and v>=0 for v in device)
        start=process_start_ticks(stat,pid)
        validate_process_view(status,pid,None);validate_kernel_identity(status,60002,60002)
        assert type(cgroup) is bytes and cgroup==CGROUP
        rows=mount_rows(mountinfo).values()
        groups=[row for row in rows if row['fs']==b'cgroup2']
        assert groups and all(b'ro' in row['options'] and row['device']==device for row in groups)
        root=[row for row in groups if row['path']=='/sys/fs/cgroup' and row['root']=='/']
        assert len(root)==1
        assert not any(row['path'].startswith('/sys/fs/cgroup/') for row in rows)
        return start
    except BaseException:raise ValueError('Process profile unavailable') from None
