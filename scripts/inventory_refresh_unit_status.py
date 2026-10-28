"""Pure retained failed-unit status parsing, never publication authority.

Guardian success uses internal90 so PID1 stops the group and retains failed
bookkeeping. Only physical cleanup/current guards can make it eligible to seal.
"""
import re

PROPERTIES=('LoadState','ActiveState','Transient','Description','InvocationID','MainPID','ControlGroup',
            'SubState','ExecMainCode','ExecMainStatus','Result')
RESULTS=frozenset(('resources','protocol','timeout','exit-code','signal','core-dump','watchdog',
                  'start-limit-hit','oom-kill','exec-condition'))


def _require(value):
    if not value:raise ValueError('Inventory retained unit status unavailable')


def inert(value):
    number=value.get('ExecMainStatus')
    return (value.get('ActiveState')=='failed' and value.get('SubState')=='failed' and
        value.get('MainPID')=='0' and value.get('ExecMainCode') in ('0','1','2','3') and
        type(number) is str and re.fullmatch('(0|[1-9][0-9]{0,2})',number) is not None and int(number)<=255 and
        value.get('Result') in RESULTS)


def teardown(value):
    return (value.get('ActiveState')=='deactivating' and value.get('MainPID')=='0' and
        value.get('ExecMainCode')=='1' and value.get('ExecMainStatus') in ('90','74','75','76') and
        value.get('Result')=='exit-code' and value.get('SubState') in (
            'stop','stop-watchdog','stop-sigterm','stop-sigkill','stop-post',
            'final-watchdog','final-sigterm','final-sigkill'))


def terminal_status(value):
    if value.get('ActiveState') in ('active','activating','deactivating'):return None
    _require(inert(value) and value['ExecMainCode']=='1' and value['Result']=='exit-code')
    number=int(value['ExecMainStatus']);_require(number in (90,74,75,76))
    return number
