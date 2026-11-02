"""Synthetic child protocol tests; no Root, APT or durable admission authority."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_reporter_controller as controller

BOOT='11111111-1111-4111-8111-111111111111'
NONCE='0000000000000008'+'f'*16
CONTEXT=dict(cache_generation='a'*32,policy_generation='b'*64,successful_checked_at='2026-01-01T00:00:00Z',boot_id=BOOT)
OFFER=dict(nonce=NONCE,boot_id=BOOT,cache_generation='a'*32,policy_generation='b'*64,lock_open_boottime_ms=120,expires_boottime_ms=1000)
SCAN=dict(scan_started_boottime_ms=130,scan_finished_boottime_ms=140,installed_before_sha256='c'*64,installed_after_sha256='c'*64)
RECEIPT=dict(OFFER,lock_held_until_boottime_ms=150,released_boottime_ms=160,outcome='released',installed_before_sha256='c'*64,installed_after_sha256='c'*64)

CHILD=r'''
import json,sys
context,offer,scan,receipt=json.loads(sys.argv[1])
def write(value):print(json.dumps(value,separators=(',',':')),flush=True)
def command(identifier,operation):
 value=json.loads(sys.stdin.readline());assert value['id']==identifier and value['operation']==operation
 return value
def response(identifier,operation,phase,**fields):write(dict(schema_version=1,id=identifier,operation=operation,phase=phase,**fields))
response(0,'initialize','pinned',context=dict(context,pinned_boottime_ms=100))
assert command(1,'publish_observation')['nonce']==offer['nonce'];response(1,'publish_observation','published')
command(2,'await_open');response(2,'await_open','scan_proposed',offer=offer,scan_started_boottime_ms=130)
assert command(3,'scan_admitted')['scan_started_boottime_ms']==130;response(3,'scan_admitted','scanning',scan_started_boottime_ms=130)
for identifier,operation,text in ((4,'installed','synthetic installed\n'),(5,'architecture','arm64\n'),(6,'holds',''),(7,'policy','  Candidate: 1.0\n  1.0 123\n')):
 value=command(identifier,operation)
 if operation=='policy':assert value['packages']==['inventory-proof']
 if text:response(identifier,operation,'data',chunk_index=0,text=text)
 response(identifier,operation,'data_complete',chunks=int(bool(text)),utf8_bytes=len(text.encode()))
command(8,'freeze_scan');response(8,'freeze_scan','scan_frozen',scan=scan)
assert command(9,'publish_release')['nonce']==offer['nonce'];response(9,'publish_release','published')
command(10,'await_receipt');response(10,'await_receipt','prepared',evidence=dict(schema_version=1,scan_started_boottime_ms=130,scan_finished_boottime_ms=140,successful_checked_at=context['successful_checked_at'],observation_receipt=receipt))
'''


class ControllerTests(unittest.TestCase):
    def launch(self,program=CHILD):
        process=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,json.dumps([CONTEXT,OFFER,SCAN,RECEIPT])],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        os.set_blocking(process.stdin.fileno(),False);os.set_blocking(process.stdout.fileno(),False)
        self.addCleanup(self.close_child,process)
        return process

    def close_child(self,process):
        process.stdin.close();process.stdout.close();process.wait(timeout=3)

    def run_controller(self,process,**options):
        arguments=dict(expected_context=CONTEXT,read_root_status=lambda:dict(observation_lease=OFFER,observation_receipt=RECEIPT),
            nonce=NONCE,deadline=time.monotonic()+2)
        arguments.update(options)
        return controller.run_reporter_controller(process,**arguments)

    def altered(self,condition,change):
        return CHILD.replace("def write(value):print(json.dumps(value,separators=(',',':')),flush=True)",
            "def write(value):\n if "+condition+":\n  "+change+"\n print(json.dumps(value,separators=(',',':')),flush=True)")

    def rejected(self,program,**options):
        process=self.launch(program)
        with self.assertRaises(controller.ControllerError):self.run_controller(process,**options)
        os.fstat(process.stdin.fileno());os.fstat(process.stdout.fileno())
        return process

    def test_exact_synthetic_dialogue_returns_prepared_data_after_eof_and_exit(self):
        process=self.launch();result=self.run_controller(process)
        self.assertEqual(result['evidence']['observation_receipt'],RECEIPT)
        self.assertEqual(result['scan'],SCAN);self.assertEqual(result['data']['architecture'],'arm64\n')
        self.assertTrue(result['mechanics_only']);self.assertEqual(process.returncode,0)
        self.assertFalse(process.stdin.closed);self.assertFalse(process.stdout.closed)

    def test_bool_initial_pin_is_not_a_safe_timestamp(self):
        self.rejected(self.altered("value['phase']=='pinned'","value['context']['pinned_boottime_ms']=True"))

    def test_initial_context_must_match_root_generation(self):
        self.rejected(self.altered("value['phase']=='pinned'","value['context']['cache_generation']='d'*32"))

    def test_extra_metadata_fields_are_rejected(self):
        self.rejected(self.altered("value['phase']=='published'","value['extra']='unexpected'"))

    def test_bool_ack_id_cannot_equal_one(self):
        self.rejected(self.altered("value['phase']=='published' and value['id']==1","value['id']=True"))

    def test_proposal_must_match_fresh_root_offer_before_admission(self):
        self.rejected(self.altered("value['phase']=='scan_proposed'","value['offer']['policy_generation']='d'*64"))

    def test_bool_proposed_start_is_not_admitted(self):
        self.rejected(self.altered("value['phase']=='scan_proposed'","value['scan_started_boottime_ms']=True"))

    def test_scanning_ack_cannot_change_proposed_start(self):
        self.rejected(self.altered("value['phase']=='scanning'","value['scan_started_boottime_ms']=131"))

    def test_data_chunk_id_order_and_final_totals_are_strict(self):
        for change in ("value['id']=99","value['chunk_index']=1","value['utf8_bytes']=999"):
            phase='data_complete' if 'utf8_bytes' in change else 'data'
            with self.subTest(change=change):self.rejected(self.altered("value['phase']=='"+phase+"'",change))

    def test_frozen_scan_must_keep_exact_start_and_equal_hashes(self):
        for change in ("value['scan']['scan_started_boottime_ms']=131","value['scan']['installed_after_sha256']='d'*64"):
            with self.subTest(change=change):self.rejected(self.altered("value['phase']=='scan_frozen'",change))

    def test_prepared_evidence_must_match_root_receipt_and_frozen_bounds(self):
        for change in ("value['evidence']['scan_finished_boottime_ms']=141", "value['evidence']['schema_version']=True",
                "value['evidence']['observation_receipt']['installed_before_sha256']='d'*64"):
            with self.subTest(change=change):self.rejected(self.altered("value['phase']=='prepared'",change))

    def test_fresh_root_receipt_must_match_prepared_evidence(self):
        wrong=dict(RECEIPT,released_boottime_ms=161)
        self.rejected(CHILD,read_root_status=lambda:dict(observation_lease=OFFER,observation_receipt=wrong))

    def test_truncated_json_and_early_eof_are_not_partial_success(self):
        self.rejected("import sys;sys.stdout.write('{\"schema_version\":1');sys.stdout.flush()")

    def test_duplicate_json_fields_are_not_accepted(self):
        self.rejected("print('{\"schema_version\":1,\"schema_version\":1}',flush=True)")

    def test_oversized_frame_is_bounded_and_original_streams_remain_owned(self):
        self.rejected("import sys;sys.stdout.write('x'*262145);sys.stdout.flush()")

    def test_prepared_prefix_followed_by_surplus_is_not_success(self):
        self.rejected(CHILD+"\nprint('unexpected surplus',flush=True)\n")

    def test_exit_nonzero_after_valid_prepared_frame_is_not_success(self):
        self.rejected(CHILD+"\nraise SystemExit(9)\n")

    def test_held_stdout_after_parent_exit_is_bounded_without_signals(self):
        child=CHILD+"\nimport subprocess;subprocess.Popen([sys.executable,'-I','-B','-S','-c','import time;time.sleep(.2)'])\n"
        started=time.monotonic();self.rejected(child,deadline=time.monotonic()+.08)
        self.assertLess(time.monotonic()-started,.5)

    def test_no_output_timeout_does_not_close_originals_or_kill_child(self):
        process=self.rejected("import time;time.sleep(.2)",deadline=time.monotonic()+.03)
        self.assertIsNone(process.poll())

    def test_nonblocking_is_required_without_mutating_original_flags(self):
        process=self.launch();os.set_blocking(process.stdin.fileno(),True)
        with self.assertRaises(controller.ControllerError):self.run_controller(process)
        self.assertTrue(os.get_blocking(process.stdin.fileno()))

    def test_duplicate_descriptor_close_failure_withholds_returned_success(self):
        process=self.launch();actual=os.close;closed=[]
        def uncertain(fd):
            closed.append(fd);actual(fd)
            if len(closed)==1:raise OSError('synthetic duplicate close uncertainty')
        with patch.object(controller.os,'close',side_effect=uncertain):
            with self.assertRaises(controller.ControllerError):self.run_controller(process)
        self.assertEqual(len(closed),2)
        os.fstat(process.stdin.fileno());os.fstat(process.stdout.fileno())


if __name__=='__main__':unittest.main()
