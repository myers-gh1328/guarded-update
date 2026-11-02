"""Pure local framing, not origin, transport acknowledgement or Root authority."""
from pathlib import Path
import sys
import unittest
import json

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import inventory_refresh_reporter_protocol as protocol


class FramingTests(unittest.TestCase):
    def frame(self,value):return (json.dumps(value,separators=(',',':'))+'\n').encode()

    def test_commands_are_fixed_fields_sequenced_and_do_not_accept_options(self):
        decoder=protocol.CommandDecoder()
        value=decoder.decode(self.frame({'schema_version':1,'id':1,'operation':'publish_observation','nonce':'0000000000000001'+'a'*16}))
        self.assertEqual(value.operation,'publish_observation')
        value=decoder.decode(self.frame({'schema_version':1,'id':2,'operation':'policy','packages':['synthetic:arm64']}))
        self.assertEqual(value.packages,('synthetic:arm64',))
        with self.assertRaises(ValueError):decoder.decode(self.frame({'schema_version':1,'id':3,'operation':'installed','options':[]}))
        with self.assertRaises(ValueError):decoder.decode(self.frame({'schema_version':1,'id':3,'operation':'installed'}))

    def test_bounded_chunk_roundtrip_yields_only_a_complete_one_use_result(self):
        text='synthetic\n'+('x'*20000)+'\U0001f680'
        sender=protocol.DataEncoder();receiver=protocol.DataDecoder()
        frames=sender.encode(2,'policy',text);assembly=receiver.start(2,'policy')
        count=0
        for frame in frames:
            self.assertLessEqual(len(frame),256*1024)
            self.assertEqual(frame.count(b'\n'),1)
            self.assertIsNone(assembly.feed(frame));count+=1
        self.assertGreater(count,2);self.assertEqual(assembly.take(),text)
        with self.assertRaises(ValueError):assembly.take()

    def test_command_bad_encoding_fields_aliases_and_duplicates_poison_decoder(self):
        valid={'schema_version':1,'id':1,'operation':'installed'}
        invalid=[b'[]\n',b'{}\nextra\n',b'\xff\n',b'x'*(256*1024+1),
            b'{"schema_version":1,"id":1,"id":1,"operation":"installed"}\n',
            b'{"schema_version":NaN,"id":1,"operation":"installed"}\n',
            self.frame(dict(valid,schema_version=True)),self.frame(dict(valid,id=True)),self.frame(dict(valid,id=2)),
            self.frame(dict(valid,operation='install')),self.frame(dict(valid,path='/tmp/other')),
            self.frame(dict(valid,operation='policy',packages=['--help'])),
            self.frame(dict(valid,operation='policy',packages=['a','a'])),
            self.frame(dict(valid,operation='publish_release',nonce='0'*32)),
            self.frame(dict(valid,operation='scan_admitted',scan_started_boottime_ms=True))]
        for raw in invalid:
            with self.subTest(raw=raw[:100]):
                decoder=protocol.CommandDecoder()
                with self.assertRaises(ValueError):decoder.decode(raw)
                with self.assertRaises(ValueError):decoder.decode(self.frame(valid))

    def test_control_frame_can_carry_all_300_maximum_binary_and_architecture_ids(self):
        packages=[('p'+str(index)+'a'*256)[:256]+':'+'b'*256 for index in range(300)]
        raw=self.frame({'schema_version':1,'id':1,'operation':'policy','packages':packages})
        self.assertLess(len(raw),256*1024)
        self.assertEqual(protocol.CommandDecoder().decode(raw).packages,tuple(packages))

    def test_astral_and_control_text_stay_bounded_without_literal_newlines(self):
        for text in ('\U0001f680'*16384,'\x00\n'*16384):
            sender=protocol.DataEncoder();frames=list(sender.encode(1,'policy',text))
            self.assertTrue(all(len(raw)<=256*1024 and raw.count(b'\n')==1 for raw in frames))
            owner=protocol.DataDecoder();response=owner.start(1,'policy')
            for raw in frames:response.feed(raw)
            self.assertEqual(response.take(),text)
        owner=protocol.DataEncoder()
        with self.assertRaises(ValueError):owner.encode(1,'policy','\ud800')
        with self.assertRaises(ValueError):owner.encode(2,'policy','safe')

    def test_exact_policy_limit_uses_1024_data_chunks_and_overflow_never_returns_iterator(self):
        text='a'*(16*1024*1024);owner=protocol.DataEncoder()
        count=sum(1 for _ in owner.encode(1,'policy',text))
        self.assertEqual(count,1025)
        bad=protocol.DataEncoder()
        with self.assertRaises(ValueError):bad.encode(1,'policy',text+'a')
        with self.assertRaises(ValueError):bad.encode(2,'holds','')

    def test_reservation_happens_before_iteration_and_abandoned_stream_never_replays(self):
        owner=protocol.DataEncoder();old=owner.encode(1,'installed','synthetic')
        with self.assertRaises(ValueError):owner.encode(2,'holds','')
        with self.assertRaises(ValueError):next(old)
        owner=protocol.DataEncoder();old=owner.encode(1,'policy','synthetic');old.close()
        with self.assertRaises(ValueError):owner.encode(2,'policy','synthetic')
        owner=protocol.DataDecoder();old=owner.start(1,'policy')
        with self.assertRaises(ValueError):owner.start(2,'policy')
        with self.assertRaises(ValueError):old.take()

    def test_empty_output_is_valid_but_not_a_refund_or_second_fixed_operation(self):
        sender=protocol.DataEncoder();receiver=protocol.DataDecoder();response=receiver.start(1,'holds')
        frames=list(sender.encode(1,'holds',''));self.assertEqual(len(frames),1)
        response.feed(frames[0]);self.assertEqual(response.take(),'')
        with self.assertRaises(ValueError):sender.encode(2,'holds','')
        with self.assertRaises(ValueError):receiver.start(2,'holds')

    def test_partial_final_mismatch_extra_and_bool_indices_return_no_partial_data(self):
        base={'schema_version':1,'id':1,'operation':'policy','phase':'data','chunk_index':0,'text':'synthetic'}
        bad=[dict(base,id=2),dict(base,chunk_index=True),dict(base,chunk_index=1),dict(base,text=''),dict(base,unknown=1),
            dict(schema_version=1,id=1,operation='policy',phase='data_complete',chunks=0,utf8_bytes=1)]
        for value in bad:
            with self.subTest(value=value):
                owner=protocol.DataDecoder();response=owner.start(1,'policy')
                with self.assertRaises(ValueError):response.feed(self.frame(value))
                with self.assertRaises(ValueError):response.take()
                with self.assertRaises(ValueError):owner.start(2,'policy')
        owner=protocol.DataDecoder();response=owner.start(1,'policy');response.feed(self.frame(base))
        with self.assertRaises(ValueError):response.take()
        owner=protocol.DataDecoder();response=owner.start(1,'policy')
        for frame in protocol.DataEncoder().encode(1,'policy','synthetic'):response.feed(frame)
        with self.assertRaises(ValueError):owner.start(2,'policy')  # Final not consumed.
        with self.assertRaises(ValueError):response.take()

    def test_whole_session_budget_and_policy_count_do_not_reset(self):
        owner=protocol.DataEncoder();text='a'*(16*1024*1024)
        for identifier in range(1,5):
            for _ in owner.encode(identifier,'policy',text):pass
        with self.assertRaises(ValueError):owner.encode(5,'policy','a')
        owner=protocol.DataEncoder()
        for identifier in range(1,68):list(owner.encode(identifier,'policy',''))
        with self.assertRaises(ValueError):owner.encode(68,'policy','')

    def test_receiver_bounds_decoded_utf8_not_escaped_length_and_rejects_final_aliases(self):
        base={'schema_version':1,'id':1,'operation':'architecture','phase':'data','chunk_index':0,'text':'a'*128}
        receiver=protocol.DataDecoder();response=receiver.start(1,'architecture');response.feed(self.frame(base))
        with self.assertRaises(ValueError):response.feed(self.frame(dict(base,chunk_index=1,text='a')))
        receiver=protocol.DataDecoder();response=receiver.start(1,'architecture')
        with self.assertRaises(ValueError):response.feed(self.frame(dict(base,text='\u00e9'*80)))
        receiver=protocol.DataDecoder();response=receiver.start(1,'holds')
        with self.assertRaises(ValueError):response.feed(self.frame(dict(schema_version=1,id=1,operation='holds',phase='data_complete',chunks=False,utf8_bytes=0)))
        receiver=protocol.DataDecoder();response=receiver.start(1,'holds')
        response.feed(self.frame(dict(schema_version=1,id=1,operation='holds',phase='data_complete',chunks=0,utf8_bytes=0)))
        with self.assertRaises(ValueError):response.feed(self.frame(base))
        with self.assertRaises(ValueError):response.take()

    def test_receiver_shared_total_and_aborted_response_cannot_restart(self):
        sender=protocol.DataEncoder();receiver=protocol.DataDecoder();text='a'*(16*1024*1024)
        for identifier in range(1,5):
            response=receiver.start(identifier,'policy')
            for raw in sender.encode(identifier,'policy',text):response.feed(raw)
            self.assertEqual(len(response.take()),len(text))
        response=receiver.start(5,'policy')
        raw=self.frame(dict(schema_version=1,id=5,operation='policy',phase='data',chunk_index=0,text='a'))
        with self.assertRaises(ValueError):response.feed(raw)
        with self.assertRaises(ValueError):receiver.start(6,'policy')
        receiver=protocol.DataDecoder();response=receiver.start(1,'policy');response.close()
        with self.assertRaises(ValueError):receiver.start(2,'policy')


if __name__=='__main__':unittest.main()
