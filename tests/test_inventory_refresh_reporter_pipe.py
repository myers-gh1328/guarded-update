"""Real pipe mechanics; fixtures do not establish native clock origin."""
from pathlib import Path
import os
import sys
import unittest
import fcntl
import select
import tempfile
import threading
import time
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_reporter_pipe as pipe


class Clock:
    def __init__(self):self.boot='11111111-1111-4111-8111-111111111111';self.now=1000
    def __call__(self):return self.boot,self.now


class PipeTests(unittest.TestCase):
    def setUp(self):
        self.input,self.remote_write=os.pipe();self.remote_read,self.output=os.pipe()
        self.fds=[self.input,self.remote_write,self.remote_read,self.output]
        for fd in self.fds:os.set_blocking(fd,False)
        self.clock=Clock();self.channel=None
        self.stop=threading.Event();self.threads=[];self.thread_errors=[]
    def tearDown(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(3);self.assertFalse(thread.is_alive())
        self.assertEqual(self.thread_errors,[])
        if self.channel:self.channel.close()
        for fd in self.fds:
            try:os.close(fd)
            except OSError:pass
    def admit(self):
        self.channel=pipe.PipeChannel.admit(self.input,self.output,self.clock)
        return self.channel

    def producer(self,data):
        def run():
            try:
                offset=0;deadline=time.monotonic()+3
                while offset<len(data) and not self.stop.is_set():
                    if time.monotonic()>deadline:raise AssertionError('fixture producer timed out')
                    try:offset+=os.write(self.remote_write,data[offset:])
                    except BlockingIOError:select.select([],[self.remote_write],[],0.01)
            except BaseException as exc:self.thread_errors.append(type(exc).__name__)
        thread=threading.Thread(target=run);self.threads.append(thread);thread.start()

    def test_coalesced_frames_roundtrip_preserves_borrowed_descriptors(self):
        channel=self.admit();os.write(self.remote_write,b'first\nsecond\n')
        self.assertEqual(channel.read_frame(),b'first\n')
        self.assertEqual(channel.read_frame(),b'second\n')
        self.assertIsNone(channel.write_frame(b'reply\n'))
        self.assertEqual(os.read(self.remote_read,100),b'reply\n')
        channel.close();channel.close()
        for fd in self.fds:os.fstat(fd)

    def test_exact_limit_frame_preserves_prefetched_next_frame(self):
        channel=self.admit();first=b'x'*(pipe.FRAME_LIMIT-1)+b'\n'
        self.producer(first+b'tail\n')
        self.assertEqual(channel.read_frame(),first)
        self.assertEqual(channel.read_frame(),b'tail\n')

    def test_oversize_and_partial_eof_poison_without_returning_prefix(self):
        channel=self.admit();self.producer(b'x'*pipe.FRAME_LIMIT+b'\n')
        with self.assertRaises(pipe.PipeError):channel.read_frame()
        with mock.patch.object(pipe.os,'read',side_effect=AssertionError('I/O after failure')):
            with self.assertRaises(pipe.PipeError):channel.read_frame()

    def test_partial_eof_and_empty_eof_are_fatal(self):
        for payload in (b'',b'partial'):
            with self.subTest(payload=payload):
                incoming,writer=os.pipe();os.set_blocking(incoming,False)
                try:
                    channel=pipe.PipeChannel.admit(incoming,self.output,self.clock)
                    os.write(writer,payload);os.close(writer);writer=None
                    with self.assertRaises(pipe.PipeError):channel.read_frame()
                    os.fstat(incoming)
                finally:
                    os.close(incoming)
                    if writer is not None:os.close(writer)

    def test_admission_rejects_blocking_wrong_direction_same_pipe_and_regular_file(self):
        os.set_blocking(self.input,True)
        with self.assertRaises(pipe.PipeError):self.admit()
        os.set_blocking(self.input,False)
        pairs=[(self.output,self.input),(self.input,self.input)]
        # Linux exposes the same pipe inode for opposite ends. Darwin does not;
        # these portable fixtures do not claim a cross-platform pairing oracle.
        if os.fstat(self.input).st_ino==os.fstat(self.remote_write).st_ino:
            pairs.append((self.input,self.remote_write))
        for incoming,outgoing in pairs:
            with self.subTest(pair=(incoming,outgoing)):
                with self.assertRaises(pipe.PipeError):pipe.PipeChannel.admit(incoming,outgoing,self.clock)
                os.fstat(incoming);os.fstat(outgoing)
        with tempfile.TemporaryFile() as regular:
            os.set_blocking(regular.fileno(),False)
            with self.assertRaises(pipe.PipeError):pipe.PipeChannel.admit(regular.fileno(),self.output,self.clock)
            os.fstat(regular.fileno())

    def test_original_shared_nonblocking_flags_must_remain_stable(self):
        channel=self.admit();before=fcntl.fcntl(self.input,fcntl.F_GETFL)
        self.assertTrue(before&os.O_NONBLOCK)
        os.set_blocking(self.input,True)
        with mock.patch.object(pipe.os,'read',side_effect=AssertionError('blocking read attempted')):
            with self.assertRaises(pipe.PipeError):channel.read_frame()
        self.assertFalse(fcntl.fcntl(self.input,fcntl.F_GETFL)&os.O_NONBLOCK)

    def test_clock_expiry_after_successful_read_does_not_expose_bytes(self):
        channel=self.admit();os.write(self.remote_write,b'synthetic\n');actual=os.read
        def expired(fd,size):
            raw=actual(fd,size);self.clock.now=121000;return raw
        with mock.patch.object(pipe.os,'read',side_effect=expired):
            with self.assertRaises(pipe.PipeError):channel.read_frame()
        with mock.patch.object(Clock,'__call__',side_effect=AssertionError('clock after failure')):
            with self.assertRaises(pipe.PipeError):channel.write_frame(b'no\n')

    def test_clock_expiry_after_successful_write_is_unknown_not_ack(self):
        channel=self.admit();actual=os.write
        def expired(fd,raw):
            count=actual(fd,raw);self.clock.now=121000;return count
        with mock.patch.object(pipe.os,'write',side_effect=expired):
            with self.assertRaises(pipe.PipeError):channel.write_frame(b'possibly delivered\n')
        self.assertEqual(os.read(self.remote_read,100),b'possibly delivered\n')

    def test_full_pipe_eagain_keeps_original_absolute_deadline(self):
        channel=self.admit()
        while True:
            try:os.write(self.output,b'x'*4096)
            except BlockingIOError:break
        actual=os.write;blocked=[]
        def expires_when_blocked(fd,raw):
            try:return actual(fd,raw)
            except BlockingIOError:
                blocked.append(True);self.clock.now=121000;raise
        with mock.patch.object(pipe.os,'write',side_effect=expires_when_blocked):
            with self.assertRaises(pipe.PipeError):channel.write_frame(b'no\n')
        self.assertEqual(blocked,[True])

    def test_reboot_rewind_and_malformed_clock_are_fatal_even_for_buffered_frames(self):
        for change in ('reboot','rewind','bool','badboot'):
            with self.subTest(change=change):
                channel=self.admit();os.write(self.remote_write,b'a\nb\n');self.assertEqual(channel.read_frame(),b'a\n')
                if change=='reboot':self.clock.boot='22222222-2222-4222-8222-222222222222'
                elif change=='rewind':self.clock.now=999
                elif change=='bool':self.clock.now=True
                else:self.clock.boot='invalid'
                with self.assertRaises(pipe.PipeError):channel.read_frame()
                self.clock=Clock()

    def test_deadline_tightens_without_reset_and_cannot_extend(self):
        channel=self.admit();channel.tighten(2000);self.clock.now=1999
        os.write(self.remote_write,b'a\n');self.assertEqual(channel.read_frame(),b'a\n')
        self.clock.now=2000
        with self.assertRaises(pipe.PipeError):channel.write_frame(b'b\n')
        self.clock=Clock();channel=self.admit()
        with self.assertRaises(pipe.PipeError):channel.tighten(121001)

    def test_close_attempts_both_owned_fds_after_failure_without_retry_or_borrowed_close(self):
        channel=self.admit();actual=os.close;closed=[]
        def uncertain(fd):
            closed.append(fd);actual(fd)
            if len(closed)==1:raise OSError('synthetic close uncertainty')
        with mock.patch.object(pipe.os,'close',side_effect=uncertain):
            with self.assertRaisesRegex(pipe.PipeError,'cleanup_unconfirmed'):channel.close()
            channel.close()
            with self.assertRaises(pipe.PipeError):channel.read_frame()
        self.assertEqual(len(closed),2);self.assertTrue(set(closed).isdisjoint(self.fds))
        for fd in self.fds:os.fstat(fd)

    def test_large_frame_partial_writes_reach_peer_without_renewing_budget(self):
        channel=self.admit();received=bytearray();frame=b'x'*(pipe.FRAME_LIMIT-1)+b'\n'
        def consume():
            try:
                deadline=time.monotonic()+3
                while len(received)<len(frame) and not self.stop.is_set():
                    if time.monotonic()>deadline:raise AssertionError('fixture consumer timed out')
                    try:received.extend(os.read(self.remote_read,4096))
                    except BlockingIOError:select.select([self.remote_read],[],[],0.01)
            except BaseException as exc:self.thread_errors.append(type(exc).__name__)
        thread=threading.Thread(target=consume);self.threads.append(thread);thread.start()
        channel.write_frame(frame);thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(received,frame)
        self.clock.now=121000
        with self.assertRaises(pipe.PipeError):channel.write_frame(b'late\n')

    def test_after_poll_clock_failure_returns_no_frame(self):
        channel=self.admit();actual=select.poll
        class Poll:
            def __init__(inner):inner.real=actual()
            def register(inner,*args):inner.real.register(*args)
            def poll(inner,*args):
                result=inner.real.poll(*args);self.clock.now=121000;return result
        with mock.patch.object(pipe.select,'poll',Poll):
            with self.assertRaises(pipe.PipeError):channel.read_frame()

    def test_second_dup_failure_closes_first_duplicate_only(self):
        actual=os.dup;owned=[];closed=[];actual_close=os.close
        def duplicate(fd):
            if owned:raise OSError('synthetic second dup failure')
            result=actual(fd);owned.append(result);return result
        def close(fd):closed.append(fd);actual_close(fd)
        with mock.patch.object(pipe.os,'dup',side_effect=duplicate),mock.patch.object(pipe.os,'close',side_effect=close):
            with self.assertRaises(pipe.PipeError):self.admit()
        self.assertEqual(closed,owned);self.assertEqual(len(closed),1)
        for fd in self.fds:os.fstat(fd)

    def test_invalid_frames_fail_before_any_write_and_do_not_retry(self):
        for raw in (b'',b'no newline',b'a\nb\n',b'x'*pipe.FRAME_LIMIT+b'\n','text\n'):
            with self.subTest(raw=str(raw)[:40]):
                channel=self.admit()
                with mock.patch.object(pipe.os,'write',side_effect=AssertionError('invalid frame write')):
                    with self.assertRaises(pipe.PipeError):channel.write_frame(raw)
                    with self.assertRaises(pipe.PipeError):channel.write_frame(b'valid\n')

    def test_original_closed_after_admission_fails_before_io(self):
        channel=self.admit();os.close(self.input);self.fds.remove(self.input)
        with mock.patch.object(pipe.os,'read',side_effect=AssertionError('read after borrowed close')):
            with self.assertRaises(pipe.PipeError):channel.read_frame()

    def test_metadata_check_crossing_deadline_withholds_buffered_read_and_final_write(self):
        for operation,last_check in (('read',8),('write',16)):
            with self.subTest(operation=operation):
                self.clock=Clock();channel=self.admit()
                if operation=='read':
                    os.write(self.remote_write,b'a\nb\n');self.assertEqual(channel.read_frame(),b'a\n')
                actual=pipe._identity;calls=[]
                def identity(fd,direction):
                    result=actual(fd,direction);calls.append(fd)
                    if len(calls)==last_check:self.clock.now=121000
                    return result
                with mock.patch.object(pipe,'_identity',side_effect=identity):
                    with self.assertRaises(pipe.PipeError):
                        if operation=='read':channel.read_frame()
                        else:channel.write_frame(b'possibly delivered\n')


if __name__=='__main__':unittest.main()
