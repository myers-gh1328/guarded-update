"""Disposable synthetic peer using the actual runtime and real journal lock."""
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_inventory_refresh_runtime import RuntimeTests
from inventory_refresh_maintenance_lock import MaintenanceAdmission
import inventory_refresh_maintenance_control as control

path,ready,request,response,mode=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]),sys.argv[5]
case=RuntimeTests();case.setUp()
# Preserve the synthetic durable state even on an uncertain child outcome.
case.f.temp._finalizer.detach()
case.f.lock.__exit__(None,None,None);case.f.journal.exclusive=case.original_exclusive
directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
guard=MaintenanceAdmission.participant(directory,os.getuid(),os.getgid())
case.runtime=__import__('inventory_refresh_runtime').FixedRuntime._with_maintenance_for_test(guard)
case.runtime._observation._clock=case.f.clock
if mode=='active':
    case.f.journal.receive('refresh','0000000000000002'+'a'*16,case.f.boot,200,case.f.policy.generation)
os.write(ready,b'r');os.close(ready)
try:
    if mode=='lost':
        with patch.object(control._Pipes,'send',side_effect=OSError('synthetic lost reply')):
            control.serve(case.runtime,request,response,time.monotonic()+5)
    else:control.serve(case.runtime,request,response,time.monotonic()+5)
except ValueError:os._exit(24)
os._exit(0)
