"""Task credential/proc visibility contracts; synthetic public kernel text only."""
from pathlib import Path
import sys
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock,patch
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_writer_exclusion as exclusion
from inventory_refresh_writer_exclusion import task_identity,proc_mount,WriterExclusion


class WriterExclusionTests(unittest.TestCase):
    def status(self,ids='1000 1000 1000 1000'):
        return ('Name:\tsynthetic\nState:\tS (sleeping)\nTgid:\t100\nPid:\t101\nUid:\t'+ids+'\n').encode()

    def mount(self,options=b'rw,nosuid,nodev,noexec',super_options=b'rw',root=b'/'):
        return b'42 1 0:2 '+root+b' /proc '+options+b' - proc proc '+super_options+b'\n'

    def test_fixed_factory_admits_literal_dotted_slice_names_without_generic_path_options(self):
        proc=Mock();groups=Mock()
        def native_chain(root,parts):
            # The existing native-file helper intentionally disallows dots.
            # The cgroup factory must use the reviewed cgroup ancestry helper.
            if any('.' in part for part in parts):raise ValueError('native component grammar')
            return proc
        with patch.object(exclusion.sys,'platform','linux'),patch.object(exclusion.os,'getresuid',return_value=(0,0,0),create=True),patch.object(exclusion.os,'getresgid',return_value=(0,0,0),create=True),patch.object(exclusion._Ancestry,'open',side_effect=native_chain) as native,patch.object(exclusion,'_Chain',return_value=groups,create=True) as chain,patch.object(WriterExclusion,'check'):
            value=WriterExclusion.fixed(60001)
            try:
                chain.assert_called_once_with(('sys','fs','cgroup')+exclusion.SLICE)
                self.assertIs(value._cgroup,groups)
                self.assertEqual(native.call_args.args[1],('proc',))
            finally:value.close()

    def test_each_kernel_uid_column_is_checked_including_saved_and_fs(self):
        self.assertEqual(task_identity(self.status(),100,101,60001),(1000,)*4)
        for column in range(4):
            ids=[1000]*4;ids[column]=60001
            with self.subTest(column=column),self.assertRaises(ValueError):
                task_identity(self.status(' '.join(map(str,ids))),100,101,60001)

    def test_numeric_alias_wrong_thread_group_missing_and_duplicate_fields_fail(self):
        for raw in (self.status().replace(b'Tgid:\t100',b'Tgid:\t99'),
                    self.status().replace(b'Pid:\t101',b'Pid:\t0101'),
                    self.status()+b'Uid:\t1000 1000 1000 1000\n',
                    self.status().replace(b'Uid:',b'Gone:'),self.status('1000 1000 1000')):
            with self.subTest(raw=raw),self.assertRaises(ValueError):task_identity(raw,100,101,60001)

    def test_nonleader_thread_with_refresh_uid_and_unreadable_status_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);tasks=root/'100/task'
            for tid in ('100','101'):
                path=tasks/tid;path.mkdir(parents=True)
                raw=self.status().replace(b'Pid:\t101',('Pid:\t'+tid).encode())
                (path/'status').write_bytes(raw)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            def guard():
                value=WriterExclusion();value._uid=60001
                value._proc=SimpleNamespace(fds=[fd]);value._scope=Mock()
                return value
            try:
                value=guard();value.check();self.assertEqual(value._scope.call_count,2)
                (tasks/'101/status').write_bytes(self.status('1000 1000 60001 1000'))
                with self.assertRaises(ValueError):guard().check()
                (tasks/'101/status').write_bytes(self.status())
                original=os.open
                def unavailable(name,*args,**kwargs):
                    if name=='status':raise PermissionError('synthetic hidden task')
                    return original(name,*args,**kwargs)
                with patch('inventory_refresh_writer_exclusion.os.open',side_effect=unavailable):
                    with self.assertRaises(ValueError):guard().check()
            finally:os.close(fd)

    def test_empty_task_directory_of_still_present_group_is_not_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'100/task').mkdir(parents=True)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                value=WriterExclusion();value._uid=60001
                value._proc=SimpleNamespace(fds=[fd]);value._scope=Mock()
                with self.assertRaises(ValueError):value.check()
            finally:os.close(fd)

    def test_numeric_proc_overmounts_cannot_hide_task_credentials(self):
        for path in ('/proc/100','/proc/100/task','/proc/100/task/101/status','/proc/self','/proc/thread-self/fdinfo'):
            extra=('43 42 0:3 / '+path+' ro - tmpfs tmpfs ro\n').encode()
            with self.subTest(path=path),self.assertRaises(ValueError):
                proc_mount(self.mount()+extra,mount_id=42,device=(0,2))

    def test_task_directory_close_failure_still_attempts_parent_close(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'100/task/101').mkdir(parents=True)
            (root/'100/task/101/status').write_bytes(self.status())
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);opened={};closed=[]
            original_open=os.open;original_close=os.close
            def tracked_open(name,*args,**kwargs):
                result=original_open(name,*args,**kwargs)
                if name in ('100','task'):opened[name]=result
                return result
            def uncertain_close(number):
                closed.append(number);original_close(number)
                if number==opened.get('task'):raise OSError('synthetic close uncertainty')
            try:
                value=WriterExclusion();value._uid=60001
                value._proc=SimpleNamespace(fds=[fd]);value._scope=Mock()
                with patch('inventory_refresh_writer_exclusion.os.open',side_effect=tracked_open),patch('inventory_refresh_writer_exclusion.os.close',side_effect=uncertain_close):
                    with self.assertRaises(ValueError):value.check()
                self.assertIn(opened['100'],closed)
            finally:
                for number in opened.values():
                    try:original_close(number)
                    except OSError:pass
                original_close(fd)

    def test_missing_status_is_not_a_confirmed_task_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'100/task/101').mkdir(parents=True)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                value=WriterExclusion();value._uid=60001
                value._proc=SimpleNamespace(fds=[fd]);value._scope=Mock()
                with self.assertRaises(ValueError):value.check()
            finally:os.close(fd)

    def test_only_full_proc_root_and_actual_fd_mount_identity_are_supported(self):
        proc_mount(self.mount(),mount_id=42,device=(0,2))
        for raw in (self.mount(root=b'/100'),self.mount(super_options=b'rw,hidepid=2'),
                    self.mount(super_options=b'rw,subset=pid'),self.mount(options=b'rw,hidepid=invisible'),
                    self.mount()+self.mount().replace(b'42 ',b'43 ',1)):
            with self.subTest(raw=raw),self.assertRaises(ValueError):proc_mount(raw,mount_id=42,device=(0,2))
        with self.assertRaises(ValueError):proc_mount(self.mount(),mount_id=43,device=(0,2))
        with self.assertRaises(ValueError):proc_mount(self.mount(),mount_id=42,device=(0,3))


if __name__=='__main__':unittest.main()
