"""Build-only reporter template; generate the admitted entry before execution.

Exclusive inherited stdio ownership forbids concurrent FD close/reuse or new
subprocess work during cleanup. Identity checks are not an ABA proof.
"""
import os
import stat
import sys
import types
import io
import fcntl

LIB_ROOT='/usr/local/libexec/command-center-inventory-refresh'
ENTRY=LIB_ROOT+'/reporter.py'
SELF_CGROUP='/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}

# @FIXED_SOURCE_MODULES@
# @FIXED_SOURCE_LOADER@


def _stdio_identity(info):
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid


class _Stdio:
    @classmethod
    def capture(cls):
        return cls._from_streams((sys.stdin,sys.stdout,sys.stderr),(0,1,2))

    @classmethod
    def _from_streams(cls,streams,descriptors):
        """Private owned-stream fixture seam, never runtime FD selection."""
        _require(cls is _Stdio and type(streams) is tuple and len(streams)==3 and type(descriptors) is tuple and len(descriptors)==3)
        value=cls();value._records=[];value._closed=False;value._attempted=False;failed=False
        for position,(stream,descriptor) in enumerate(zip(streams,descriptors)):
            record=dict(stream=stream,descriptor=descriptor,identity=None,raw=None,buffer=None,closefd=None)
            value._records.append(record)
            try:
                _require(type(descriptor) is int and descriptor>=0 and type(stream) is io.TextIOWrapper and not stream.closed)
                buffer=stream.buffer;raw=buffer.raw
                _require(type(buffer) is (io.BufferedReader if position==0 else io.BufferedWriter) and
                    type(raw) is io.FileIO and type(raw.closefd) is bool and stream.fileno()==descriptor and raw.fileno()==descriptor)
                record.update(identity=_stdio_identity(os.fstat(descriptor)),raw=raw,buffer=buffer,closefd=raw.closefd)
            except BaseException:failed=True
        if len(set(descriptors))!=3 or len({id(stream) for stream in streams})!=3:failed=True
        if failed:
            value.close();raise ValueError('Reporter stdio admission unavailable')
        return value

    def _verify(self,record):
        stream=record['stream'];descriptor=record['descriptor']
        _require(record['identity'] is not None and not stream.closed and stream.buffer is record['buffer'] and
            stream.buffer.raw is record['raw'] and record['raw'].closefd is record['closefd'] and
            stream.fileno()==descriptor and record['raw'].fileno()==descriptor and _stdio_identity(os.fstat(descriptor))==record['identity'])

    def nonblocking(self):
        try:
            _require(not self._closed and not self._attempted);self._attempted=True
            for record,direction in zip(self._records[:2],(os.O_RDONLY,os.O_WRONLY)):
                self._verify(record)
                _require(stat.S_ISFIFO(os.fstat(record['descriptor']).st_mode) and
                    fcntl.fcntl(record['descriptor'],fcntl.F_GETFL)&os.O_ACCMODE==direction)
            _require(self._records[0]['identity'][:2]!=self._records[1]['identity'][:2])
            # BOTH originals admitted before either shared OFD flag changes.
            for record in self._records[:2]:os.set_blocking(record['descriptor'],False)
            for record in self._records[:2]:
                self._verify(record);_require(fcntl.fcntl(record['descriptor'],fcntl.F_GETFL)&os.O_NONBLOCK)
        except BaseException:
            self.close();raise ValueError('Reporter stdio admission unavailable') from None

    def close(self):
        if self._closed:return
        self._closed=True;records,self._records=self._records,[];failed=False;seen_streams=set();seen_fds=set()
        for record in records:
            stream=record['stream'];descriptor=record['descriptor']
            if id(stream) in seen_streams or descriptor in seen_fds:failed=True;continue
            seen_streams.add(id(stream));seen_fds.add(descriptor)
            try:self._verify(record)  # Never flush buffered bytes to a replacement.
            except BaseException:failed=True;continue
            try:stream.close()
            except BaseException:failed=True
            if record['closefd'] is False:
                try:
                    _require(_stdio_identity(os.fstat(descriptor))==record['identity'])
                    os.close(descriptor)  # Wrapper borrowed this inherited FD.
                except BaseException:failed=True
            # closefd=True: wrapper owns the FD; NEVER retry raw close.
        if failed:raise ValueError('Reporter stdio cleanup unconfirmed')


def _proc(name,limit):
    fd=os.open('/proc/self/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        _require(stat.S_ISREG(os.fstat(fd).st_mode));raw=bytearray()
        while True:
            chunk=os.read(fd,min(65536,limit+1-len(raw)))
            if not chunk:break
            raw.extend(chunk);_require(len(raw)<=limit)
        return bytes(raw)
    finally:os.close(fd)


def admit_profile():
    _require(sys.platform=='linux' and sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site and sys.argv==[ENTRY])
    uids=os.getresuid();gids=os.getresgid()
    _require(len(uids)==len(gids)==3 and len(set(uids))==len(set(gids))==1 and
        all(type(value) is int and 0<value<2**32-1 for value in (*uids,*gids)) and
        os.getgroups() in ([],[gids[0]]))
    _require(_proc('cgroup',4096)==('0::'+SELF_CGROUP+'\n').encode('ascii'))
    wanted={'Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'};fields={}
    for line in _proc('status',65536).splitlines():
        name,separator,value=line.partition(b':');key=name.decode('ascii')
        if key in wanted:
            _require(separator and key not in fields);fields[key]=value.split()
    _require(set(fields)==wanted and fields['Uid']==[str(uids[0]).encode('ascii')]*4 and
        fields['Gid']==[str(gids[0]).encode('ascii')]*4 and fields['Groups'] in ([],[str(gids[0]).encode('ascii')]) and
        fields['NoNewPrivs']==[b'1'] and all(fields[key]==[b'0000000000000000'] for key in wanted if key.startswith('Cap')))


def _environment():
    os.environ.clear();os.environ.update(ENV)


def main():
    stdio=None;sources=None;runtime=None;channel=None;result=74
    try:
        stdio=_Stdio.capture();admit_profile();_environment()
        sources=RootSources.fixed();modules=sources.execute()
        closing,sources=sources,None;closing.close()
        stdio.nonblocking()
        runtime=modules['inventory_refresh_reporter_runtime'].ReporterRuntime.fixed()
        channel=modules['inventory_refresh_reporter_pipe'].PipeChannel.admit(0,1,runtime.clock)
        transferred_runtime,runtime=runtime,None;transferred_channel,channel=channel,None
        modules['inventory_refresh_reporter_dialogue'].run(transferred_runtime,transferred_channel)
        result=0
    except BaseException:result=74
    finally:
        for owned in (runtime,channel,sources,stdio):
            if owned is not None:
                try:owned.close()
                except BaseException:result=74
    return result


if __name__=='__main__':
    code=74
    try:
        candidate=main()
        if type(candidate) is int and candidate in (0,74):code=candidate
    except BaseException:pass
    os._exit(code)  # Explicit cleanup above; never retry flush/finalizer closes.
