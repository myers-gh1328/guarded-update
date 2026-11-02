"""Current readonly reporter resource admission; no fit or startup claim."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch
from contextlib import contextmanager
from types import SimpleNamespace
import os

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_resources as root_resources
import inventory_refresh_reporter_resources as reporter

CACHE='/var/cache/command-center-inventory-refresh'
RW=('10 1 0:10 / '+CACHE+' rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=131072k,nr_inodes=32768\n'
    '20 1 0:20 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n').encode()
RO=RW.replace(b'rw,nosuid,nodev,noexec',b'ro,nosuid,nodev,noexec',1)
STATUS=(b'Uid:\t60002 60002 60002 60002\nGid:\t60002 60002 60002 60002\nGroups:\t60002\n'
    b'NoNewPrivs:\t1\n'+b''.join(name+b':\t0000000000000000\n' for name in (b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb')))


class ReporterResourceTests(unittest.TestCase):
    def mounts(self,raw=RO,cache_id=10):
        return reporter.validate_mounts(raw,cache_device=(0,10),cache_mount_id=cache_id,cgroup_device=(0,20),cgroup_mount_id=20)

    def test_reporter_and_root_require_their_distinct_visible_mount_modes(self):
        self.assertEqual(self.mounts(),(10,20))
        self.assertEqual(root_resources.validate_mounts(RW,cache_device=(0,10),cache_mount_id=10,cgroup_device=(0,20),cgroup_mount_id=20),(10,20))
        with self.assertRaises(ValueError):self.mounts(RW)
        with self.assertRaises(ValueError):root_resources.validate_mounts(RO,cache_device=(0,10),cache_mount_id=10,cgroup_device=(0,20),cgroup_mount_id=20)

    def test_current_numeric_identity_requires_all_ids_caps_and_nnp(self):
        self.assertEqual(reporter.validate_identity(STATUS,60002,60002),(60002,60002))
        self.assertEqual(reporter.validate_identity(STATUS.replace(b'Groups:\t60002',b'Groups:\t'),60002,60002),(60002,60002))
        for raw in (b'',b'x'*65537,STATUS.replace(b'60002 60002 60002 60002',b'60002 60002 60002 0',1),
            STATUS.replace(b'Groups:\t60002',b'Groups:\t60002 0'),STATUS.replace(b'Groups:\t60002',b'Groups:\t60002 60002'),
            STATUS.replace(b'NoNewPrivs:\t1',b'NoNewPrivs:\t0'),STATUS+b'CapEff:\t0000000000000000\n',
            STATUS.replace(b'CapBnd:\t0000000000000000',b'CapBnd:\t0000000000000001')):
            with self.subTest(raw=raw[:50]),self.assertRaises(ValueError):reporter.validate_identity(raw,60002,60002)
        for uid,gid in ((0,60002),(60002,0),(True,60002),(60002,True)):
            with self.subTest(uid=uid,gid=gid),self.assertRaises(ValueError):reporter.validate_identity(STATUS,uid,gid)

    def test_default_or_coordinator_membership_fails_before_any_cache_open(self):
        for group in ('/system.slice/command-center-inventory.service',root_resources.SELF_CGROUP):
            with patch.object(reporter.sys,'platform','linux'),patch.object(reporter,'_profile',return_value=(60002,60002)),\
                patch.object(reporter,'_proc',return_value=('0::'+group+'\n').encode()),patch.object(reporter,'_Chain') as chain:
                with self.assertRaises(ValueError):reporter.ReporterResources.fixed()
                chain.assert_not_called()

    @contextmanager
    def kernel(self,readonly=True,ancestor=b'max\n'):
        cache=Mock();cache.fds=[1,2,3,4]
        groups=Mock();groups.fds=[10,11,12,13,14,15,16,17]
        parent={'memory.max':b'268435456\n','memory.swap.max':b'0\n','pids.max':b'64\n'}
        def read(fd,name,maximum=4096):
            if name=='cgroup.controllers':return b'memory pids\n'
            if name=='cgroup.type':return b'domain\n'
            if name=='memory.current':return b'1048576\n'
            if name=='pids.current':return b'2\n'
            return parent[name] if fd==16 else ancestor
        def proc(name,maximum):return ('0::'+reporter.SELF_CGROUP+'\n').encode() if name=='cgroup' else RO
        capacity=SimpleNamespace(f_blocks=32768,f_frsize=4096,f_files=32768,f_bavail=100,f_favail=100,
            f_flag=os.ST_RDONLY if readonly else 0)
        with patch.object(reporter.sys,'platform','linux'),patch.object(reporter,'_profile',return_value=(60002,60002)),\
            patch.object(reporter,'_proc',side_effect=proc),patch.object(reporter,'_Chain',side_effect=[cache,groups]),\
            patch.object(reporter,'_read',side_effect=read),patch.object(reporter,'_mount_id',side_effect=lambda fd:10 if fd==4 else 20),\
            patch.object(reporter.os,'fstat',side_effect=lambda fd:SimpleNamespace(st_dev=os.makedev(0,10 if fd==4 else 20),st_ino=fd)),\
            patch.object(reporter.os,'fstatvfs',return_value=capacity):
            yield cache,groups,capacity

    def test_current_resource_sample_uses_readonly_fd_and_exact_shared_profile(self):
        with self.kernel() as (cache,groups,_):
            value=reporter.ReporterResources.fixed();metrics=value.sample()
            self.assertEqual(metrics['memory_limit_bytes'],268435456)
            self.assertEqual(metrics['memory_current_bytes'],1048576)
            self.assertEqual(metrics['tasks_current'],2)
            value.close();value.close()
            cache.close.assert_called_once();groups.close.assert_called_once()
            with self.assertRaises(ValueError):value.sample()

    def test_nonreadonly_fd_or_stricter_ancestor_fails_and_closes_both_roots(self):
        for readonly,ancestor in ((False,b'max\n'),(True,b'134217728\n')):
            with self.subTest(readonly=readonly),self.kernel(readonly,ancestor) as (cache,groups,_):
                with self.assertRaises(ValueError):reporter.ReporterResources.fixed()
                cache.close.assert_called_once();groups.close.assert_called_once()

    def test_readonly_stack_preserves_whole_root_and_alias_constraints(self):
        for lower_mode in ('rw','ro'):
            lower=RW.replace(b'10 1 0:10',b'9 1 0:10').replace(b'rw,nosuid,nodev,noexec',(lower_mode+',nosuid,nodev,noexec').encode(),1)
            top=('10 9 0:10 / '+CACHE+' ro,nosuid,nodev,noexec - tmpfs tmpfs rw\n').encode()
            stack=lower+top
            self.assertEqual(self.mounts(stack),(10,20))
            self.assertEqual(self.mounts(b'\n'.join(reversed(stack.splitlines()))+b'\n'),(10,20))
            for raw in (stack.replace(b'10 9 0:10',b'10 1 0:10'),stack.replace(b'9 1 0:10',b'9 10 0:10'),
                stack.replace(b'9 1 0:10 / ',b'9 1 0:10 /subtree '),
                stack+('30 10 0:10 / '+CACHE+' ro,nosuid,nodev,noexec - tmpfs tmpfs rw\n').encode()):
                with self.subTest(lower_mode=lower_mode),self.assertRaises(ValueError):self.mounts(raw)
            with self.assertRaises(ValueError):self.mounts(stack,cache_id=9)
        for path,root in (('/alias','/'),('/alias','/subtree'),(CACHE+'/child','/')):
            raw=RO+('30 10 0:10 '+root+' '+path+' ro,nosuid,nodev,noexec - tmpfs tmpfs rw\n').encode()
            with self.subTest(path=path,root=root),self.assertRaises(ValueError):self.mounts(raw)

    def test_unsafe_or_foreign_mounts_share_root_rejections(self):
        for before,after in ((b'- tmpfs ',b'- ext4 '),(b'/ /sys/fs/cgroup',b'/delegated /sys/fs/cgroup'),
            (b'ro,nosuid,nodev,noexec',b'ro,nosuid,nodev'),(b'0:10',b'0:11')):
            with self.subTest(before=before),self.assertRaises(ValueError):self.mounts(RO.replace(before,after))
        for identifier in (9,11):
            with self.assertRaises(ValueError):self.mounts(cache_id=identifier)

    def test_failed_resample_is_poisoned_and_stale_metrics_cannot_return(self):
        with self.kernel() as (_,_,capacity):
            value=reporter.ReporterResources.fixed();capacity.f_flag=0
            with self.assertRaises(ValueError):value.sample()
            capacity.f_flag=os.ST_RDONLY
            with patch.object(reporter,'_profile') as profile:
                with self.assertRaises(ValueError):value.sample()
                profile.assert_not_called()
            value.close()

    def test_changed_current_identity_fails_before_touching_cache_again(self):
        with self.kernel() as (cache,_,_):
            value=reporter.ReporterResources.fixed();cache.verify.reset_mock()
            with patch.object(reporter,'_profile',return_value=(60003,60003)):
                with self.assertRaises(ValueError):value.sample()
            cache.verify.assert_not_called();value.close()

    def test_uncertain_close_attempts_both_roots_and_never_retries(self):
        with self.kernel() as (cache,groups,_):
            value=reporter.ReporterResources.fixed();groups.close.side_effect=OSError('synthetic close')
            with self.assertRaises(ValueError) as caught:value.close()
            self.assertEqual(caught.exception.reason,'cleanup_unconfirmed')
            cache.close.assert_called_once();groups.close.assert_called_once();value.close()
            cache.close.assert_called_once();groups.close.assert_called_once()


if __name__=='__main__':unittest.main()
