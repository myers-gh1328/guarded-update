"""Fixtures only; no production wrapper or process-cleanup authority."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import inventory_refresh_exec_parent_fixture as fixture


class ExecParentFixtureTests(unittest.TestCase):
    def test_only_fixed_identity_and_test_are_accepted(self):
        command=fixture.wrapper_command(1,2,3,'a'*64,4,5)
        self.assertEqual(command[:4],['/usr/bin/python3','-I','-B','-S'])
        self.assertNotIn('/bin/sh',command)
        compile(fixture.PROGRAM,'fixed-wrapper','exec')
        self.assertIn('inventory::reporter_obs::tests::hosted_real_reporter_rust_journal_sample',fixture.PROGRAM)
        for arguments in ((0,2,3,'a'*64,4,5),(1,2,3,'x'*64,4,5),(True,2,3,'a'*64,4,5),(2**64,2,3,'a'*64,4,5)):
            with self.assertRaises(ValueError):fixture.wrapper_command(*arguments)
