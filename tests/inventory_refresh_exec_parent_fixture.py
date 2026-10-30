"""Fixed hosted wrapper contract; no production launch authority."""
import re

ERROR='Synthetic held-fd parent unavailable'
READY=b'EXEC-WRAPPER-READY\n'
ACK=b'EXEC-ACK\n'
PROGRAM=r'''import errno,fcntl,hashlib,os,select,stat,sys,time
if os.getresuid()!=(60002,60002,60002) or os.getresgid()!=(60002,60002,60002):sys.exit(74)
if os.execve not in os.supports_fd:sys.exit(74)
for n in os.listdir('/proc/self/fd'):
 if not n.isascii() or not n.isdigit():sys.exit(74)
 if int(n)>=3:
  try:os.close(int(n))
  except OSError as e:
   if e.errno!=errno.EBADF:raise
expected_dev,expected_ino,expected_size=int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]);expected_hash=sys.argv[4]
lock_dev,lock_ino=int(sys.argv[5]),int(sys.argv[6]);deadline=time.monotonic()+15
fds=[];links=[]
def ancestry(parts):
 parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(parent)
 for name in parts:
  child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(child)
  held=os.fstat(child);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
  ident=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid)
  if not stat.S_ISDIR(held.st_mode) or held.st_uid!=0 or held.st_mode&0o022 or ident(held)!=ident(named):sys.exit(74)
  links.append((parent,name,child,ident(held)));parent=child
 return parent
def recheck():
 for parent,name,fd,identity in links:
  for item in (os.fstat(fd),os.stat(name,dir_fd=parent,follow_symlinks=False)):
   if (item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid)!=identity:sys.exit(74)
 if time.monotonic()>=deadline:sys.exit(74)
parent=ancestry(('usr','local','libexec'))
source=os.open('command-center-inventory',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
first=os.fstat(source)
if (not stat.S_ISREG(first.st_mode) or (first.st_dev,first.st_ino,first.st_size)!=(expected_dev,expected_ino,expected_size) or
 (first.st_uid,first.st_gid)!=(0,0) or stat.S_IMODE(first.st_mode)!=0o555 or first.st_nlink!=1 or not 0<first.st_size<=134217728):sys.exit(74)
lockdir=ancestry(('run','inventory-held-fd-fixture'))
lock=os.open('maintenance.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=lockdir)
l=os.fstat(lock)
if (not stat.S_ISREG(l.st_mode) or (l.st_dev,l.st_ino)!=(lock_dev,lock_ino) or (l.st_uid,l.st_gid)!=(0,0) or stat.S_IMODE(l.st_mode)!=0o644 or l.st_nlink!=1 or l.st_size!=0):sys.exit(74)
fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB);os.set_inheritable(lock,True)
def source_check():
 os.lseek(source,0,os.SEEK_SET);h=hashlib.sha256();count=0;prefix=b''
 while True:
  chunk=os.read(source,65536)
  if not chunk:break
  count+=len(chunk)
  if count>expected_size:sys.exit(74)
  if len(prefix)<4:prefix+=chunk[:4-len(prefix)]
  h.update(chunk)
 named=os.stat('command-center-inventory',dir_fd=parent,follow_symlinks=False)
 def meta(x):return (x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
 if prefix!=b'\x7fELF' or count!=expected_size or h.hexdigest()!=expected_hash or meta(first)!=meta(os.fstat(source)) or meta(first)!=meta(named):sys.exit(74)
 named_lock=os.stat('maintenance.lock',dir_fd=lockdir,follow_symlinks=False)
 if meta(l)!=meta(named_lock) or meta(l)!=meta(os.fstat(lock)):sys.exit(74)
 recheck()
source_check();flags=fcntl.fcntl(2,fcntl.F_GETFL);fcntl.fcntl(2,fcntl.F_SETFL,flags|os.O_NONBLOCK)
marker=b'EXEC-WRAPPER-READY\n';offset=0
while offset<len(marker):
 remaining=deadline-time.monotonic()
 if remaining<=0 or not select.select([],[2],[],remaining)[1]:sys.exit(74)
 try:count=os.write(2,marker[offset:])
 except BlockingIOError:continue
 if count<=0:sys.exit(74)
 offset+=count
fcntl.fcntl(2,fcntl.F_SETFL,flags)
if fcntl.fcntl(2,fcntl.F_GETFL)!=flags:sys.exit(74)
ack=b''
while len(ack)<9:
 remaining=deadline-time.monotonic()
 if remaining<=0 or not select.select([0],[],[],remaining)[0]:sys.exit(74)
 data=os.read(0,9-len(ack))
 if not data:sys.exit(74)
 ack+=data
if ack!=b'EXEC-ACK\n':sys.exit(74)
source_check()
env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','GITHUB_ACTIONS':'true','GUARDED_UPDATE_NATIVE_RUST_PROOF':'1','GUARDED_UPDATE_NATIVE_BARRIER_PROOF':'1'}
os.execve(source,['/usr/local/libexec/command-center-inventory','--exact','inventory::reporter_obs::tests::hosted_real_reporter_rust_journal_sample','--ignored','--test-threads=1','--nocapture'],env)
'''


def wrapper_command(dev,ino,size,digest,lock_dev,lock_ino):
    if any(type(x) is not int or not 0<x<2**64 for x in (dev,ino,size,lock_dev,lock_ino)) or size>128*1024*1024 or type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None:raise ValueError(ERROR)
    return ['/usr/bin/python3','-I','-B','-S','-c',PROGRAM,str(dev),str(ino),str(size),digest,str(lock_dev),str(lock_ino)]
