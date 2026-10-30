"""Private read-only marker fixture; no enrollment authority."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_enrollment_marker as marker


class EnrollmentMarkerTests(unittest.TestCase):
    def fixture(self,root):
        directory=root/'var'/'lib'/'command-center-inventory'
        directory.mkdir(parents=True)
        path=directory/'initialized-enrollment'
        path.write_bytes(b'00000000-0000-4000-8000-000000000001\n');path.chmod(0o644)
        return path

    def test_reads_fixed_historical_marker_without_modification(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            directory=root/'var'/'lib'/'command-center-inventory'
            directory.mkdir(parents=True)
            path=directory/'initialized-enrollment'
            raw=b'00000000-0000-4000-8000-000000000001\n'
            path.write_bytes(raw);path.chmod(0o644)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                value=marker._read_from(fd,os.getuid(),os.getgid(),time.monotonic()+5)
                self.assertEqual(value,'00000000-0000-4000-8000-000000000001')
                self.assertEqual(path.read_bytes(),raw)
            finally:os.close(fd)

    def test_rejects_unsafe_files_and_ancestry(self):
        for fault in ('symlink','hardlink','mode','directory','truncated','extra','uppercase'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);path=self.fixture(root)
                if fault=='symlink':
                    path.unlink();path.symlink_to('missing')
                elif fault=='hardlink':os.link(path,path.with_name('other'))
                elif fault=='mode':path.chmod(0o666)
                elif fault=='directory':path.parent.chmod(0o777)
                elif fault=='truncated':path.write_bytes(b'bad\n')
                elif fault=='extra':path.write_bytes(path.read_bytes()+b'x')
                else:path.write_bytes(b'00000000-0000-4000-8000-00000000000A\n')
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    with self.assertRaises(marker.MarkerError):marker._read_from(fd,os.getuid(),os.getgid(),time.monotonic()+5)
                finally:os.close(fd)

    def test_replacement_expiry_and_uncertain_close_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=self.fixture(root)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.assertRaises(marker.MarkerError):marker._read_from(fd,os.getuid(),os.getgid(),time.monotonic()-1)
                read=os.read;changed=[]
                def replace_during_read(file,size):
                    data=read(file,size)
                    if data and not changed:
                        replacement=path.with_name('replacement')
                        replacement.write_bytes(path.read_bytes());replacement.chmod(0o644)
                        os.replace(replacement,path);changed.append(True)
                    return data
                with patch.object(marker.os,'read',side_effect=replace_during_read):
                    with self.assertRaises(marker.MarkerError):marker._read_from(fd,os.getuid(),os.getgid(),time.monotonic()+5)
                close=marker._Ancestry.close
                def close_uncertain(ancestry):
                    close(ancestry);raise OSError('synthetic close uncertainty')
                with patch.object(marker._Ancestry,'close',close_uncertain):
                    with self.assertRaises(marker.MarkerError):marker._read_from(fd,os.getuid(),os.getgid(),time.monotonic()+5)
            finally:os.close(fd)

    def test_rejects_wrong_owner_group_and_nonfinite_clock(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                for owner,group in ((os.getuid()+1,os.getgid()),(os.getuid(),os.getgid()+1)):
                    with self.assertRaises(marker.MarkerError):marker._read_from(fd,owner,group,time.monotonic()+5)
                with self.assertRaises(marker.MarkerError):marker._read_from(fd,os.getuid(),os.getgid(),float('inf'))
                with self.assertRaises(marker.MarkerError):marker._read_from(fd,os.getuid(),os.getgid(),5,clock=lambda:float('nan'))
            finally:os.close(fd)

if __name__=='__main__':unittest.main()
