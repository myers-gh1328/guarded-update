"""Disposable, unprivileged reporter/SystemTools lock inheritance fixture."""
import fcntl
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from inventory_refresh_maintenance_lock import MaintenanceLock


def wait(child):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        result=child.poll()
        if result is not None:
            return result
        time.sleep(.01)
    raise RuntimeError('child exit unknown')


def contend(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return False
        return True
    finally:os.close(fd)


def main(binary):
    # The directory remains available on failure; no broad cleanup of unknown children.
    directory=Path(tempfile.mkdtemp(prefix='inventory-lock-exec-'))
    path=directory/'maintenance.lock';path.write_bytes(b'');path.chmod(0o644)
    parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    lock=MaintenanceLock.from_directory(parent,'participant',os.geteuid(),os.getegid())
    fd=lock.inheritable_fd();read_ready,write_ready=os.pipe();read_control,write_control=os.pipe()
    reporter_read,reporter_write=os.pipe()
    expected=os.fstat(fd)
    if contend(path):raise RuntimeError('shared lock missing before exec')
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C',
         'INVENTORY_LOCK_FIXTURE':','.join(map(str,(fd,write_ready,read_control,reporter_read)))}
    child=subprocess.Popen([binary,'--exact','inventory::process::tests::maintenance_inheritance_child','--ignored','--test-threads=1'],
        env=env,pass_fds=(fd,write_ready,read_control,reporter_read),stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    os.close(write_ready);os.close(read_control);os.close(reporter_read)
    if not select.select([read_ready],[],[],10)[0]:raise RuntimeError('descendant readiness unknown')
    data=os.read(read_ready,128)
    if data!=f'{expected.st_dev}:{expected.st_ino}\n'.encode():raise RuntimeError('wrong inherited lock')
    if contend(path):raise RuntimeError('shared lock missing during reporter')
    os.write(reporter_write,b'x');os.close(reporter_write)
    if wait(child)!=0:raise RuntimeError('reporter failed')
    lock.close()
    if contend(path):raise RuntimeError('descendant lost shared lock')
    os.write(write_control,b'x');os.close(write_control)
    # Natural descendant exit closes its ready writer; EOF confirms that pipe only.
    if not select.select([read_ready],[],[],10)[0] or os.read(read_ready,1)!=b'':
        raise RuntimeError('descendant completion unknown')
    os.close(read_ready)
    if not contend(path):raise RuntimeError('shared lock retained')
    os.close(parent);path.unlink();directory.rmdir()


if __name__=='__main__':main(sys.argv[1])
