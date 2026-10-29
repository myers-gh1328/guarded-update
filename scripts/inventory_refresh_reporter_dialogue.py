"""Private managed pipe dialogue; prepared evidence is never completion.

No executable/factory is activated here. The caller transfers fixed admitted
Runtime/Channel owners but retains original pipe descriptors and process cleanup.
"""
import json
from inventory_refresh_reporter_protocol import CommandDecoder,DataEncoder,_encode
from inventory_refresh_reporter_runtime import ReporterRuntime
from inventory_refresh_reporter_pipe import PipeChannel


class DialogueError(ValueError):
    def __init__(self):super().__init__('Private reporter dialogue unavailable')


def _require(condition):
    if not condition:raise DialogueError()


def _response(channel,command,phase,**fields):
    channel.write_frame(_encode(dict(schema_version=1,id=command.identifier,operation=command.operation,phase=phase,**fields)))


def run(runtime,channel):
    failed=False
    try:
        _require(type(runtime) is ReporterRuntime and type(channel) is PipeChannel)
        clock=channel._clock_source
        _require(getattr(clock,'__self__',None) is runtime and getattr(clock,'__func__',None) is ReporterRuntime.clock)
        decoder=CommandDecoder();encoder=DataEncoder()
        context=runtime.pin_current()
        channel.write_frame(_encode(dict(schema_version=1,id=0,operation='initialize',phase='pinned',context=context)))
        while True:
            command=decoder.decode(channel.read_frame())
            operation=command.operation
            if operation=='publish_observation':
                runtime.publish_observation(command.nonce);_response(channel,command,'published')
            elif operation=='await_open':
                acknowledgment=None
                def admitted(started,offer):
                    nonlocal acknowledgment
                    _response(channel,command,'scan_proposed',offer=offer,scan_started_boottime_ms=started)
                    acknowledgment=decoder.decode(channel.read_frame())
                    _require(acknowledgment.operation=='scan_admitted' and acknowledgment.scan_started_boottime_ms==started)
                    return True
                started=runtime.begin_scan(admitted)
                _require(acknowledgment is not None)
                _response(channel,acknowledgment,'scanning',scan_started_boottime_ms=started)
            elif operation in ('installed','architecture','holds','policy'):
                methods={'installed':runtime.installed,'architecture':runtime.native_architecture,'holds':runtime.holds,'policy':runtime.policy}
                text=methods[operation](command.packages) if operation=='policy' else methods[operation]()
                frames=encoder.encode(command.identifier,operation,text)
                try:
                    for raw in frames:channel.write_frame(raw)
                finally:frames.close()
            elif operation=='freeze_scan':
                _response(channel,command,'scan_frozen',scan=runtime.freeze_scan())
            elif operation=='publish_release':
                runtime.publish_release(command.nonce);_response(channel,command,'published')
            elif operation=='await_receipt':
                evidence=json.loads(runtime.prepare_evidence())
                _response(channel,command,'prepared',evidence=evidence)
                break  # No further reads/tools/effects after prepared bytes.
            else:raise DialogueError()  # scan_admitted belongs only to callback.
    except BaseException:failed=True
    finally:
        for owned in (runtime,channel):
            try:owned.close()
            except BaseException:failed=True
    if failed:raise DialogueError() from None
