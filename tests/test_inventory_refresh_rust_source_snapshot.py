"""Synthetic Git object snapshots; no build or production provenance."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from inventory_refresh_rust_source_snapshot import snapshot
import inventory_refresh_rust_source_snapshot as source


class SourceSnapshotTests(unittest.TestCase):
    def setup_repo(self,root,extra=None):
        repo=root/'repo';repo.mkdir();subprocess.run(['/usr/bin/git','init','-q',str(repo)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        files={'Cargo.toml':b'[package]\n','Cargo.lock':b'lock\n','rust-toolchain.toml':b'toolchain\n',
            'src/inventory_main.rs':b'fn main() {}\n','src/inventory/mod.rs':b'// committed\n'}
        files.update(extra or {})
        for name,raw in files.items():
            path=repo/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        subprocess.run(['/usr/bin/git','-C',str(repo),'add','.'],check=True)
        subprocess.run(['/usr/bin/git','-C',str(repo),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture'],check=True)
        return repo,files
    def test_reads_committed_blob_bytes_even_when_worktree_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo,files=self.setup_repo(Path(temporary))
            (repo/'src/inventory/mod.rs').write_bytes(b'// uncommitted\n')
            result=snapshot(repo)
            self.assertEqual(result['files']['src/inventory/mod.rs'],b'// committed\n')
            self.assertEqual(set(result['files']),set(files))
            self.assertEqual(len(result['source_commit']),40)

    def test_unsupported_build_config_and_oversized_blob_are_rejected(self):
        for extra in [{'.cargo/config.toml':b'[build]\n'},{'src/build.rs':b'fn main(){}'}, {'large.bin':b'x'*(1024*1024+1)}]:
            with tempfile.TemporaryDirectory() as temporary:
                repo,_=self.setup_repo(Path(temporary),extra)
                with self.assertRaises(ValueError):snapshot(repo)

    def test_tracked_symlink_is_not_a_committed_source_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo,_=self.setup_repo(Path(temporary));(repo/'link').symlink_to('Cargo.toml')
            subprocess.run(['/usr/bin/git','-C',str(repo),'add','link'],check=True)
            subprocess.run(['/usr/bin/git','-C',str(repo),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','symlink'],check=True)
            with self.assertRaises(ValueError):snapshot(repo)

    def test_truncated_or_missing_git_objects_never_produce_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo,_=self.setup_repo(Path(temporary));real=source.git
            for mode in ('commit','tree','blob','missing'):
                def altered(path,args,maximum,deadline):
                    if mode=='missing' and args[:2]==('cat-file','blob'):raise OSError('synthetic missing object')
                    data=real(path,args,maximum,deadline)
                    if args[:2]==('cat-file',mode):return data[:-1]
                    return data
                with patch.object(source,'git',side_effect=altered):
                    with self.assertRaises(ValueError,msg=mode):snapshot(repo)

    def test_expired_git_read_and_unsafe_environment_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo,_=self.setup_repo(Path(temporary))
            with self.assertRaises(ValueError):source.git(repo,('rev-parse','HEAD'),128,time.monotonic()-1)
            self.assertEqual(source.ENV['GIT_NO_LAZY_FETCH'],'1')
            self.assertNotIn('GIT_ALTERNATE_OBJECT_DIRECTORIES',source.ENV)
            self.assertNotIn('GIT_CONFIG_COUNT',source.ENV)
