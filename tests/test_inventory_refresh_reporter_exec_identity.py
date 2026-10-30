"""Unregistered held-FD exec fixture helpers."""
import os
import select
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ReporterExecIdentityTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='linux','Linux /proc descriptor enumeration')
    def test_unrelated_inherited_descriptor_is_closed(self):
        script=Path(__file__).with_name('inventory_reporter_exec_identity.py')
        program="import importlib.util,os,sys\ns=importlib.util.spec_from_file_location('fixture',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nf=int(sys.argv[2]);m.close_inherited()\ntry:os.fstat(f)\nexcept OSError:os.write(1,b'closed');sys.exit(0)\nsys.exit(1)"
        with tempfile.TemporaryFile() as stream:
            child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',program,str(script),str(stream.fileno())],
                pass_fds=(stream.fileno(),),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            self.assertTrue(select.select([child.stdout],[],[],5)[0])
            output=os.read(child.stdout.fileno(),16);child.stdout.close()
            self.assertEqual(child.wait(timeout=5),0);self.assertEqual(output,b'closed')
