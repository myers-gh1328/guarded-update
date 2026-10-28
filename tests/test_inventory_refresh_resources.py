"""Synthetic read-only resource admission contracts; no pressure or limit writes."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_resources as resources

CACHE='/var/cache/command-center-inventory-refresh'
MOUNTS=('10 1 0:10 / '+CACHE+' rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=131072k,nr_inodes=32768\n'
        '20 1 0:20 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n').encode()

class ResourceTests(unittest.TestCase):
    def mounts(self,raw=MOUNTS):
        return resources.validate_mounts(raw,cache_device=(0,10),cache_mount_id=10,
                                         cgroup_device=(0,20),cgroup_mount_id=20)

    def test_exact_current_mounts_require_dedicated_tmpfs_and_full_cgroup_root(self):
        self.assertEqual(self.mounts(),(10,20))
        for before,after in [(b'- tmpfs ',b'- ext4 '),(b'/ /sys/fs/cgroup',b'/delegated /sys/fs/cgroup'),
                             (b'rw,nosuid,nodev,noexec',b'rw,nosuid,nodev'),
                             (b'rw,nosuid,nodev,noexec',b'ro,nosuid,nodev,noexec')]:
            with self.subTest(before=before),self.assertRaises(ValueError):self.mounts(MOUNTS.replace(before,after))

    def test_unrelated_mount_source_may_itself_be_a_hyphen(self):
        self.assertEqual(self.mounts(MOUNTS+b'30 1 0:30 / /unrelated rw - tmpfs - rw\n'),(10,20))

    def test_duplicate_nested_or_device_mismatched_mounts_rejected(self):
        for raw in (MOUNTS+MOUNTS.splitlines(keepends=True)[0].replace(b'10 1',b'11 1'),
                    MOUNTS+('30 10 0:30 / '+CACHE+'/child rw - tmpfs tmpfs rw\n').encode(),
                    MOUNTS.replace(b'0:10',b'0:11')):
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.mounts(raw)

    def test_cache_filesystem_bind_aliases_are_not_admitted(self):
        for root in ('/','/subtree'):
            raw=MOUNTS+('30 1 0:10 '+root+' /alias rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n').encode()
            with self.subTest(root=root),self.assertRaises(ValueError):self.mounts(raw)

    def test_kernel_escapes_are_decoded_exactly_once(self):
        self.assertEqual(resources.mount_path(b'/a\\040b\\134040c\\011d\\012e'),'/a b\\040c\td\ne')
        for raw in (b'/a\\041b',b'/a\\',b'relative'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):resources.mount_path(raw)

    def test_malformed_or_oversize_mountinfo_fails_closed(self):
        for raw in (b'',b'x'*(1024*1024+1),MOUNTS.replace(b' - ',b' '),MOUNTS.replace(b'10 1 0:10',b'x 1 0:10')):
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):self.mounts(raw)

    def test_configured_profile_and_ancestor_bounds_not_free_headroom(self):
        parent={'memory.max':b'268435456\n','memory.swap.max':b'0\n','pids.max':b'64\n'}
        unlimited={key:b'max\n' for key in parent}
        resources.validate_profile(parent,[unlimited])
        for key,bad in [('memory.max',b'134217728\n'),('pids.max',b'32\n')]:
            with self.subTest(key=key),self.assertRaises(ValueError) as caught:
                resources.validate_profile(parent,[dict(unlimited,**{key:bad})])
            self.assertEqual(caught.exception.reason,'resource_limit')
        for key,bad in [('memory.max',b'max\n'),('memory.swap.max',b'1\n'),('pids.max',b'128\n')]:
            with self.subTest(key=key),self.assertRaises(ValueError):resources.validate_profile(dict(parent,**{key:bad}),[])

    def test_limit_parser_requires_canonical_bounded_kernel_values(self):
        self.assertIsNone(resources.limit(b'max\n'));self.assertEqual(resources.limit(b'0\n'),0)
        for raw in (b'true\n',b'-1\n',b'01\n',b'1\n2\n',b'99999999999999999999\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):resources.limit(raw)

    def test_membership_must_be_exact_current_coordinator_group(self):
        resources.validate_membership(('0::'+resources.SELF_CGROUP+'\n').encode())
        for raw in (b'0::/\n',('0::'+resources.SELF_CGROUP+'\n1:cpu:/other\n').encode(),
                    ('0::'+resources.SELF_CGROUP+'/child\n').encode()):
            with self.subTest(raw=raw),self.assertRaises(ValueError):resources.validate_membership(raw)

class ResourceOwnershipTests(unittest.TestCase):
    def context(self):
        value=object.__new__(resources.RuntimeResources)
        value._closed=False;value._poisoned=False;value._cache=Mock();value._groups=Mock();value._identity=None
        return value

    def test_cleanup_attempts_both_owned_roots_after_one_failure(self):
        value=self.context();cache=value._cache;groups=value._groups
        groups.close.side_effect=OSError('uncertain close')
        with self.assertRaises(resources.ResourceError) as caught:value.close()
        self.assertEqual(caught.exception.reason,'cleanup_unconfirmed')
        cache.close.assert_called_once();groups.close.assert_called_once()
        value.close();self.assertIsNone(value._cache);self.assertIsNone(value._groups)

    def test_failed_current_membership_poison_cannot_return_stale_metrics(self):
        value=self.context()
        with patch.object(resources,'_proc',return_value=b'0::/other\n'):
            with self.assertRaises(resources.ResourceError):value.sample()
        self.assertTrue(value._poisoned)
        with patch.object(resources,'_proc') as proc:
            with self.assertRaises(resources.ResourceError):value.sample()
            proc.assert_not_called()
        value.close()

    def test_fd_mount_id_requires_one_canonical_kernel_field(self):
        with patch.object(resources,'_proc',return_value=b'pos: 0\nmnt_id:\t20\nino: 1\n'):
            self.assertEqual(resources._mount_id(5),20)
        for raw in (b'mnt_id: 20\nmnt_id: 21\n',b'mnt_id: -1\n',b'ino: 20\n'):
            with self.subTest(raw=raw),patch.object(resources,'_proc',return_value=raw):
                with self.assertRaises(resources.ResourceError):resources._mount_id(5)

if __name__=='__main__':unittest.main()
