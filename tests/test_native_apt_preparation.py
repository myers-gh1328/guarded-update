"""Native APT dependency solving against a temporary synthetic package universe.

No installed host package is read or changed; no network source is contacted.
"""
import importlib.util
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

try:
    import apt
except ImportError:
    apt = None

SPEC = importlib.util.spec_from_file_location('adapter', Path(__file__).resolve().parents[1]/'scripts/apt_executor.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


@unittest.skipUnless(sys.platform.startswith('linux') and os.environ.get('GITHUB_ACTIONS') == 'true', 'Native APT fixture runs on disposable hosted Linux CI')
class NativePreparationTests(unittest.TestCase):
    def test_all_roots_resolve_one_complete_native_dependency_transaction(self):
        self.assertIsNotNone(apt, 'Hosted native fixture requires system python-apt')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root/'repo'
            repo.mkdir()
            for name in ['etc/apt/sources.list.d','var/lib/apt/lists/partial','var/cache/apt/archives/partial','var/lib/dpkg']:
                (root/name).mkdir(parents=True, exist_ok=True)
            names = ['selected', 'dependency', 'held', 'excluded']
            def paragraph(name, version, installed=False):
                text = f'Package: fixture-{name}\nVersion: {version}\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Synthetic test only\n'
                if installed:
                    text += 'Status: install ok installed\n'
                else:
                    text += f'Filename: fixture-{name}.deb\nSize: 1\nSHA256: '+('a'*64)+'\n'
                    if name == 'selected':
                        text += 'Depends: fixture-dependency (>= 2)\n'
                return text+'\n'
            (root/'var/lib/dpkg/status').write_text(''.join(paragraph(n,'1',True) for n in names))
            (repo/'Packages').write_text(''.join(paragraph(n,'2') for n in names))
            (root/'etc/apt/sources.list').write_text(f'deb [trusted=yes] file:{repo} ./\n')
            # All APT destinations and sources are inside this disposable directory.
            args=['/usr/bin/apt-get','-o',f'Dir={root}','-o',f'Dir::State::status={root}/var/lib/dpkg/status','-o','Dir::Etc::sourcelist=sources.list','-o','Dir::Etc::sourceparts=sources.list.d','-o','APT::Sandbox::User=root','-o','Acquire::Languages=none','update']
            subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            cache = apt.Cache(rootdir=str(root))
            roots = helper.preparation_roots(cache, {'mode':'all_eligible'}, ['fixture-held','fixture-selected'], ['fixture-held'])
            self.assertEqual(roots,['fixture-selected'])
            changes = helper.select_changes(cache, roots)
            self.assertEqual(sorted(p.name for p in changes), ['fixture-dependency','fixture-selected'])
            self.assertTrue(all(not p.marked_delete for p in changes))
            self.assertEqual(cache['fixture-excluded'].installed.version,'1')
            self.assertFalse(cache['fixture-held'].marked_upgrade)
