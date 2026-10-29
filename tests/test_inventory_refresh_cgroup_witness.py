"""Pure disposable fixture observations; no production completion authority."""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import inventory_refresh_cgroup_witness as witness


class CgroupWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'unit').mkdir();self.events=self.root/'unit'/'cgroup.events'
        self.events.write_bytes(b'populated 0\nfrozen 0\n')
        self.parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.group=os.open('unit',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.parent)
    def tearDown(self):
        os.close(self.group);os.close(self.parent);self.temp.cleanup()
    def observe(self):return witness.observe_empty(self.parent,'unit',self.group,time.monotonic()+1)
    def test_empty_and_strict_event_fields(self):
        self.observe()
        for raw in (b'populated 1\nfrozen 0\n',b'populated 0\npopulated 0\n',b'populated 0\nfrozen 0\nextra 0\n',b'populated 0\nfrozen x\n',b'populated 0',b''):
            self.events.write_bytes(raw)
            with self.assertRaises(ValueError):self.observe()
    def test_missing_replaced_or_symlinked_group_is_unknown(self):
        (self.root/'unit').rename(self.root/'old')
        with self.assertRaises(ValueError):self.observe()
        (self.root/'unit').symlink_to('old',target_is_directory=True)
        with self.assertRaises(ValueError):self.observe()
    def test_replacement_during_read_and_oversized_events_are_unknown(self):
        actual=os.read;changed=[]
        def replacing(fd,size):
            raw=actual(fd,size)
            if not changed:
                changed.append(True);self.events.rename(self.root/'old.events')
                self.events.write_bytes(b'populated 0\nfrozen 0\n')
            return raw
        with patch.object(witness.os,'read',side_effect=replacing):
            with self.assertRaises(ValueError):self.observe()
        self.events.write_bytes(b'x'*4097)
        with self.assertRaises(ValueError):self.observe()

    def test_event_symlink_and_read_error_are_unknown(self):
        self.events.unlink();self.events.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError):self.observe()
        self.events.unlink();self.events.write_bytes(b'populated 0\nfrozen 0\n')
        with patch.object(witness.os,'read',side_effect=OSError('read error')):
            with self.assertRaises(ValueError):self.observe()

    def test_expiry_and_close_failure_are_unknown(self):
        with self.assertRaises(ValueError):witness.observe_empty(self.parent,'unit',self.group,time.monotonic()-1)
        with self.assertRaises(ValueError):witness.observe_empty(self.parent,'unit',self.group,float('inf'))
        actual=os.close
        def uncertain(fd):actual(fd);raise OSError('unknown close')
        with patch.object(witness.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):self.observe()

    def test_singleton_process_sample_rejects_extra_pid_and_child_group(self):
        processes=self.root/'unit'/'cgroup.procs';processes.write_bytes(b'123\n')
        witness.observe_single_process(self.parent,'unit',self.group,123,time.monotonic()+1)
        for raw in (b'',b'123\n456\n',b'0123\n',b'123\n123\n',b'123',b'123\ninvalid\n'):
            processes.write_bytes(raw)
            with self.assertRaises(ValueError):witness.observe_single_process(self.parent,'unit',self.group,123,time.monotonic()+1)
        processes.write_bytes(b'123\n');(self.root/'unit'/'nested').mkdir()
        with self.assertRaises(ValueError):witness.observe_single_process(self.parent,'unit',self.group,123,time.monotonic()+1)

    def test_singleton_process_detects_mutation_and_uncertain_close(self):
        processes=self.root/'unit'/'cgroup.procs';processes.write_bytes(b'123\n')
        actual=os.read;calls=[]
        def mutate(fd,size):
            raw=actual(fd,size);calls.append(True)
            if len(calls)==1:processes.write_bytes(b'456\n')
            return raw
        with patch.object(witness.os,'read',side_effect=mutate):
            with self.assertRaises(ValueError):witness.observe_single_process(self.parent,'unit',self.group,123,time.monotonic()+1)
        processes.write_bytes(b'123\n');actual_close=os.close;closed=[]
        def uncertain(fd):closed.append(fd);actual_close(fd);raise OSError('uncertain close')
        with patch.object(witness.os,'close',side_effect=uncertain):
            with self.assertRaises(ValueError):witness.observe_single_process(self.parent,'unit',self.group,123,time.monotonic()+1)
        self.assertEqual(len(closed),1)
