"""Real pipe/Root-file fixtures; test threads are not native process witnesses."""
from pathlib import Path
import json
import os
import select
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import test_inventory_refresh_reporter_runtime as fixtures
from inventory_refresh_reporter_pipe import PipeChannel
from inventory_refresh_reporter_protocol import DataDecoder,FRAME_LIMIT
import inventory_refresh_reader_tools as tools
import inventory_refresh_reader_session as reader_session
import inventory_refresh_reporter_dialogue as dialogue


class DialogueTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.RuntimeTests(methodName='runTest');self.fixture.setUp()
        self.runtime=self.fixture.admit()
        self.incoming,self.peer_write=os.pipe();self.peer_read,self.outgoing=os.pipe()
        self.fds={self.incoming,self.peer_write,self.peer_read,self.outgoing}
        for fd in self.fds:os.set_blocking(fd,False)
        self.channel=PipeChannel.admit(self.incoming,self.outgoing,self.runtime.clock)
        self.pending=bytearray();self.identifier=0;self.thread=None;self.done=threading.Event();self.error=None
    def tearDown(self):
        if self.thread is not None:
            if not self.done.wait(1):
                self.fixture.fixture.now=120100
                if self.peer_write in self.fds:os.close(self.peer_write);self.fds.remove(self.peer_write)
            self.thread.join(3);self.assertFalse(self.thread.is_alive())
        self.runtime.close();self.channel.close()
        for fd in self.fds:os.close(fd)
        self.fixture.tearDown()
    def start(self):
        def serve():
            try:dialogue.run(self.runtime,self.channel)
            except BaseException as exc:self.error=type(exc)
            finally:
                # Caller owns original descriptors, after all library closes.
                for fd in (self.incoming,self.outgoing):os.close(fd);self.fds.remove(fd)
                self.done.set()
        self.thread=threading.Thread(target=serve,daemon=True);self.thread.start()
    def send_raw(self,raw):
        offset=0;deadline=time.monotonic()+3
        while offset<len(raw):
            self.assertLess(time.monotonic(),deadline)
            try:offset+=os.write(self.peer_write,raw[offset:])
            except BlockingIOError:select.select([],[self.peer_write],[],.01)
    def send(self,operation,**fields):
        self.identifier+=1
        self.send_raw((json.dumps(dict(schema_version=1,id=self.identifier,operation=operation,**fields))+'\n').encode())
        return self.identifier
    def raw(self):
        deadline=time.monotonic()+3
        while True:
            end=self.pending.find(b'\n')
            if end>=0:
                raw=bytes(self.pending[:end+1]);del self.pending[:end+1];return raw
            self.assertLessEqual(len(self.pending),FRAME_LIMIT);self.assertLess(time.monotonic(),deadline)
            if not select.select([self.peer_read],[],[],.01)[0]:continue
            try:value=os.read(self.peer_read,min(65536,FRAME_LIMIT+1-len(self.pending)))
            except BlockingIOError:continue
            self.assertTrue(value,'Reporter EOF before expected fixture frame');self.pending.extend(value)
    def read(self):return json.loads(self.raw())
    def result(self,success):
        self.assertTrue(self.done.wait(3));self.thread.join(3)
        if success:self.assertIsNone(self.error)
        else:self.assertIs(self.error,dialogue.DialogueError)
        self.assertFalse(self.pending);self.assertEqual(os.read(self.peer_read,1),b'')

    def proposal(self):
        self.start();self.assertEqual(self.read()['phase'],'pinned')
        self.send('publish_observation',nonce=fixtures.NONCE);self.assertEqual(self.read()['phase'],'published')
        self.fixture.status(lease=self.fixture.offer());self.fixture.fixture.now=120
        self.send('await_open');value=self.read();self.assertEqual(value['phase'],'scan_proposed')
        return value

    def scanning(self):
        self.proposal();self.send('scan_admitted',scan_started_boottime_ms=120)
        self.assertEqual(self.read()['phase'],'scanning')

    def prepared(self):
        self.scanning();self.fixture.fixture.now=130;self.send('freeze_scan');frozen=self.read()['scan']
        self.fixture.fixture.now=140;self.send('publish_release',nonce=fixtures.NONCE)
        self.assertEqual(self.read()['phase'],'published')
        self.fixture.status(receipt=self.fixture.receipt(frozen));self.fixture.fixture.now=150
        self.send('await_receipt');value=self.read();self.assertEqual(value['phase'],'prepared')
        return value

    def test_complete_dialogue_ack_before_scan_and_prepared_before_owned_close(self):
        with patch.object(tools,'_fixed_read',return_value='synthetic\n'+'x'*20000):
            self.start();initial=self.read()
            self.assertEqual((initial['id'],initial['operation'],initial['phase']),(0,'initialize','pinned'))
            self.send('publish_observation',nonce=fixtures.NONCE);self.assertEqual(self.read()['phase'],'published')
            self.assertEqual((self.fixture.inboxes/'observation'/'request').read_bytes(),fixtures.NONCE.encode())
            self.fixture.status(lease=self.fixture.offer());self.fixture.fixture.now=120
            self.send('await_open');proposal=self.read();self.assertEqual(proposal['phase'],'scan_proposed')
            self.assertEqual(proposal['scan_started_boottime_ms'],120)
            self.send('scan_admitted',scan_started_boottime_ms=120);self.assertEqual(self.read()['phase'],'scanning')
            identifier=self.send('installed');response=DataDecoder().start(identifier,'installed')
            while True:
                raw=self.raw();response.feed(raw)
                if json.loads(raw)['phase']=='data_complete':break
            self.assertEqual(response.take(),'synthetic\n'+'x'*20000)
            self.fixture.fixture.now=130;self.send('freeze_scan');frozen=self.read()['scan']
            self.fixture.fixture.now=140;self.send('publish_release',nonce=fixtures.NONCE)
            self.assertEqual(self.read()['phase'],'published')
            self.fixture.status(receipt=self.fixture.receipt(frozen));self.fixture.fixture.now=150
            self.send('await_receipt');prepared=self.read()
            self.assertEqual(prepared['phase'],'prepared');self.assertEqual(prepared['evidence']['scan_finished_boottime_ms'],130)
            self.result(True);self.fixture.fixture.parent.close.assert_called_once()

    def test_foreign_channel_clock_is_rejected_before_pin_or_publication(self):
        self.channel.close()
        self.channel=PipeChannel.admit(self.incoming,self.outgoing,lambda:('11111111-1111-4111-8111-111111111111',100))
        with patch.object(self.runtime,'pin_current',wraps=self.runtime.pin_current) as pin:
            with self.assertRaises(dialogue.DialogueError):dialogue.run(self.runtime,self.channel)
            pin.assert_not_called()
        self.assertFalse((self.fixture.inboxes/'observation'/'request').exists())
        for fd in self.fds:os.fstat(fd)

    def test_wrong_exact_start_ack_cannot_reach_first_fingerprint(self):
        with patch.object(reader_session,'installed_fingerprint',side_effect=AssertionError('hash before exact ACK')) as hashed:
            self.proposal();self.send('scan_admitted',scan_started_boottime_ms=119)
            self.result(False);hashed.assert_not_called()

    def test_bool_start_ack_cannot_reach_first_fingerprint(self):
        with patch.object(reader_session,'installed_fingerprint') as hashed:
            self.proposal();self.send('scan_admitted',scan_started_boottime_ms=True)
            self.result(False);hashed.assert_not_called()

    def test_nested_ack_cannot_reset_command_sequence(self):
        with patch.object(reader_session,'installed_fingerprint') as hashed:
            self.proposal();self.send_raw(b'{"schema_version":1,"id":2,"operation":"scan_admitted","scan_started_boottime_ms":120}\n')
            self.result(False);hashed.assert_not_called()

    def test_wrong_ack_operation_cannot_reach_first_fingerprint(self):
        with patch.object(reader_session,'installed_fingerprint') as hashed:
            self.proposal();self.send('freeze_scan')
            self.result(False);hashed.assert_not_called()

    def test_waiting_for_ack_observes_root_expiry_without_new_frame(self):
        with patch.object(reader_session,'installed_fingerprint') as hashed:
            self.proposal();self.fixture.fixture.now=1000
            self.result(False);hashed.assert_not_called()

    def test_scan_admitted_outside_nested_handshake_is_rejected(self):
        self.start();self.read();self.send('scan_admitted',scan_started_boottime_ms=100)
        self.result(False);self.assertFalse((self.fixture.inboxes/'observation'/'request').exists())

    def test_early_eof_closes_everything_without_success(self):
        self.start();self.read();os.close(self.peer_write);self.fds.remove(self.peer_write)
        self.result(False);self.fixture.fixture.parent.close.assert_called_once()

    def test_malformed_frame_does_not_publish_or_resynchronize(self):
        self.start();self.read();self.send_raw(b'{"id":1,"id":1}\n')
        self.result(False);self.assertFalse((self.fixture.inboxes/'observation'/'request').exists())

    def test_package_data_before_admitted_scan_is_rejected(self):
        with patch.object(tools,'_fixed_read') as fixed:
            self.start();self.read();self.send('installed');self.result(False);fixed.assert_not_called()

    def test_visible_publication_ack_write_error_does_not_return_success(self):
        actual=self.channel.write_frame
        def visible(raw):
            actual(raw)
            if json.loads(raw)['phase']=='published':raise OSError('synthetic visible ACK failure')
        with patch.object(self.channel,'write_frame',side_effect=visible):
            self.start();self.read();self.send('publish_observation',nonce=fixtures.NONCE)
            self.assertEqual(self.read()['phase'],'published');self.result(False)
        self.assertEqual((self.fixture.inboxes/'observation'/'request').read_bytes(),fixtures.NONCE.encode())

    def test_partial_data_then_eof_has_no_completed_result(self):
        actual=self.channel.write_frame
        def partial(raw):
            actual(raw)
            if json.loads(raw)['phase']=='data':raise OSError('synthetic partial data transport failure')
        with patch.object(tools,'_fixed_read',return_value='x'*20000),patch.object(self.channel,'write_frame',side_effect=partial):
            self.scanning();identifier=self.send('installed');response=DataDecoder().start(identifier,'installed')
            response.feed(self.raw());self.result(False)
            with self.assertRaises(ValueError):response.take()

    def test_runtime_close_failure_after_visible_prepared_frame_still_closes_channel_and_fails(self):
        actual=self.runtime.close;calls=[]
        def uncertain():calls.append('runtime');actual();raise OSError('synthetic terminal close uncertainty')
        with patch.object(self.runtime,'close',side_effect=uncertain),\
                patch.object(self.channel,'close',wraps=self.channel.close) as close:
            self.prepared();self.result(False);close.assert_called_once()
        self.assertEqual(calls,['runtime']);self.fixture.fixture.parent.close.assert_called_once()

    def test_channel_close_failure_after_visible_prepared_frame_is_not_success(self):
        actual=self.channel.close
        def uncertain():actual();raise OSError('synthetic terminal pipe close uncertainty')
        with patch.object(self.channel,'close',side_effect=uncertain),\
                patch.object(self.runtime,'close',wraps=self.runtime.close) as close:
            self.prepared();self.result(False);close.assert_called_once()


if __name__=='__main__':unittest.main()
