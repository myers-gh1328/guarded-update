"""Typed failed-unit bookkeeping is not cleanup or publication authority."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from inventory_refresh_unit_status import terminal_status,inert


class UnitStatusTests(unittest.TestCase):
    def terminal(self,**changes):
        value={'ActiveState':'failed','SubState':'failed','MainPID':'0','ExecMainCode':'1','ExecMainStatus':'90','Result':'exit-code'}
        value.update(changes);return value

    def test_supported_guardian_statuses_remain_raw_failed_unit_data(self):
        for code in (90,74,75,76):
            self.assertEqual(terminal_status(self.terminal(ExecMainStatus=str(code))),code)
            self.assertTrue(inert(self.terminal(ExecMainStatus=str(code))))

    def test_running_or_stopping_main_is_not_completed_even_if_launcher_finished(self):
        for state in ('active','activating','deactivating'):
            self.assertIsNone(terminal_status(self.terminal(ActiveState=state,SubState='running',MainPID='100')))

    def test_zero_success_signal_unknown_or_noncanonical_data_cannot_mint_completion(self):
        for changes in ({'ActiveState':'inactive','SubState':'dead','Result':'success','ExecMainStatus':'0'},
                        {'MainPID':'100'},{'ExecMainCode':'2'},{'ExecMainStatus':'0'},
                        {'ExecMainStatus':'090'},{'Result':'success'},{'ExecMainStatus':'91'}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):terminal_status(self.terminal(**changes))


if __name__=='__main__':unittest.main()
