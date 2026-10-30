"""Bounded synthetic drain control; no peer or process-set authority."""
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_maintenance_control as control


class ControlTests(unittest.TestCase):
    def test_drain_and_close_precede_success(self):
        request_read,request_write=os.pipe();reply_read,reply_write=os.pipe()
        events=[];runtime=Mock();runtime.drain.side_effect=lambda:(events.append('drain') or {'state':'drained','poll':None,'release':None})
        runtime.close.side_effect=lambda:events.append('close')
        owner=Mock();owner.try_lifetime.side_effect=lambda:(events.append('lifetime') or True)
        thread=threading.Thread(target=control.serve,args=(runtime,request_read,reply_write,time.monotonic()+3))
        thread.start()
        self.assertTrue(control.request(owner,request_write,reply_read,time.monotonic()+3))
        thread.join(3);self.assertFalse(thread.is_alive())
        self.assertEqual(events,['drain','close','lifetime'])

    def test_non_drained_runtime_never_sends_success_or_closes(self):
        request_read,request_write=os.pipe();reply_read,reply_write=os.pipe()
        runtime=Mock();runtime.drain.return_value={'state':'draining','poll':None,'release':None};owner=Mock()
        errors=[]
        def serve():
            try:control.serve(runtime,request_read,reply_write,time.monotonic()+3)
            except ValueError:errors.append(1)
        thread=threading.Thread(target=serve);thread.start()
        with self.assertRaises(ValueError):control.request(owner,request_write,reply_read,time.monotonic()+3)
        thread.join(3);self.assertEqual(errors,[1]);runtime.close.assert_not_called();owner.try_lifetime.assert_not_called()

    def test_bad_reply_eof_and_extra_data_cannot_acquire_lifetime(self):
        for response in (b'',b'DRAINED_CLOSED',b'DRAINED_CLOSED\nextra'):
            with self.subTest(response=response):
                request_read,request_write=os.pipe();reply_read,reply_write=os.pipe()
                os.write(reply_write,response);os.close(reply_write);owner=Mock()
                with self.assertRaises(ValueError):control.request(owner,request_write,reply_read,time.monotonic()+2)
                owner.try_lifetime.assert_not_called();os.close(request_read)

    def test_held_open_reply_times_out_without_acquiring_lifetime(self):
        request_read,request_write=os.pipe();reply_read,reply_write=os.pipe();owner=Mock()
        os.write(reply_write,control.RESPONSE)
        with self.assertRaises(ValueError):control.request(owner,request_write,reply_read,time.monotonic()+.05)
        owner.try_lifetime.assert_not_called();os.close(request_read);os.close(reply_write)

    def test_close_failure_never_authorizes_lifetime(self):
        request_read,request_write=os.pipe();reply_read,reply_write=os.pipe();owner=Mock()
        os.write(reply_write,control.RESPONSE);os.close(reply_write);original=os.close
        def close(fd):
            original(fd)
            if fd==request_write:raise OSError('injected')
        with patch.object(control.os,'close',side_effect=close):
            with self.assertRaises(ValueError):control.request(owner,request_write,reply_read,time.monotonic()+2)
        owner.try_lifetime.assert_not_called();os.close(request_read)

    def test_runtime_close_failure_never_sends_success(self):
        request_read,request_write=os.pipe();reply_read,reply_write=os.pipe()
        runtime=Mock();runtime.drain.return_value={'state':'drained','poll':None,'release':None}
        runtime.close.side_effect=ValueError('uncertain');owner=Mock();errors=[]
        def serve():
            try:control.serve(runtime,request_read,reply_write,time.monotonic()+2)
            except ValueError:errors.append(1)
        thread=threading.Thread(target=serve);thread.start()
        with self.assertRaises(ValueError):control.request(owner,request_write,reply_read,time.monotonic()+2)
        thread.join(3);self.assertEqual(errors,[1]);owner.try_lifetime.assert_not_called()

    def test_partial_writes_are_reassembled_under_one_deadline(self):
        request_read,request_write=os.pipe();reply_read,reply_write=os.pipe()
        runtime=Mock();runtime.drain.return_value={'state':'drained','poll':None,'release':None};owner=Mock();owner.try_lifetime.return_value=True
        original=os.write
        with patch.object(control.os,'write',side_effect=lambda fd,data:original(fd,data[:1])):
            thread=threading.Thread(target=control.serve,args=(runtime,request_read,reply_write,time.monotonic()+3))
            thread.start();self.assertTrue(control.request(owner,request_write,reply_read,time.monotonic()+3));thread.join(3)
        self.assertFalse(thread.is_alive());runtime.close.assert_called_once()

    def test_replaced_fd_is_never_closed_as_owned(self):
        request_read,request_write=os.pipe();reply_read,reply_write=os.pipe()
        pipes=control._Pipes(request_read,reply_write,time.monotonic()+2)
        other_read,other_write=os.pipe();os.dup2(other_read,request_read)
        with self.assertRaises(ValueError):pipes.check()
        pipes.close();self.assertTrue(pipes.failed)
        os.fstat(request_read)
        for fd in (request_read,request_write,reply_read,other_read,other_write):os.close(fd)

    def test_status_flag_mutation_is_rejected(self):
        request_read,request_write=os.pipe();reply_read,reply_write=os.pipe()
        pipes=control._Pipes(request_read,reply_write,time.monotonic()+2)
        flags=control.fcntl.fcntl(request_read,control.fcntl.F_GETFL)
        control.fcntl.fcntl(request_read,control.fcntl.F_SETFL,flags & ~os.O_NONBLOCK)
        with self.assertRaises(ValueError):pipes.check()
        pipes.close();os.close(request_write);os.close(reply_read)


if __name__=='__main__':unittest.main()
