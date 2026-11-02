"""Pure bounded local framing; no transport, timing, phases or Root authority."""
import json
from dataclasses import dataclass

FRAME_LIMIT=256*1024
CHUNK_CHARS=16384
CHUNK_BYTES=65536
SESSION_BYTES=64*1024*1024
MAX_SAFE=9007199254740991
CAPS={'installed':8*1024*1024,'architecture':128,'holds':1024*1024,'policy':16*1024*1024}


class ProtocolError(ValueError):
    def __init__(self):super().__init__('Invalid private reporter frame')


def _require(condition):
    if not condition:raise ProtocolError()


def _integer(value,positive=False):
    return type(value) is int and (1 if positive else 0)<=value<=MAX_SAFE


def _load(raw):
    _require(type(raw) is bytes and 0<len(raw)<=FRAME_LIMIT and raw.endswith(b'\n') and raw.count(b'\n')==1)
    def unique(pairs):
        value={}
        for key,item in pairs:_require(key not in value);value[key]=item
        return value
    def invalid(_):raise ProtocolError()
    try:
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=unique,parse_constant=invalid)
        _require(type(value) is dict)
        return value
    except (ValueError,UnicodeError,RecursionError):raise ProtocolError() from None


def _encode(value):
    raw=(json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':'))+'\n').encode('ascii')
    _require(len(raw)<=FRAME_LIMIT)
    return raw


def _utf8(text):
    try:return len(text.encode('utf-8'))
    except UnicodeError:raise ProtocolError() from None


@dataclass(frozen=True)
class Command:
    identifier:int
    operation:str
    nonce:str|None=None
    packages:tuple|None=None
    scan_started_boottime_ms:int|None=None


class CommandDecoder:
    def __init__(self):self._next=1;self._poisoned=False
    def decode(self,raw):
        try:
            _require(not self._poisoned)
            value=_load(raw);operation=value.get('operation')
            extra={
                'publish_observation':{'nonce'},'await_open':set(),'scan_admitted':{'scan_started_boottime_ms'},
                'installed':set(),'architecture':set(),'holds':set(),'policy':{'packages'},'freeze_scan':set(),
                'publish_release':{'nonce'},'await_receipt':set(),
            }
            _require(type(operation) is str and operation in extra and
                set(value)=={'schema_version','id','operation'}|extra[operation] and
                type(value['schema_version']) is int and value['schema_version']==1 and
                _integer(value['id'],True) and value['id']==self._next)
            nonce=None;packages=None;started=None
            if 'nonce' in value:
                from inventory_refresh_protocol import correlator
                nonce=value['nonce'];_require(type(nonce) is str and len(nonce)==32)
                _require(correlator(nonce.encode('ascii'))[0]==nonce)
            if operation=='policy':
                from inventory_refresh_reader_tools import _ids
                _require(type(value['packages']) is list)
                packages=_ids(value['packages'])
            if operation=='scan_admitted':
                started=value['scan_started_boottime_ms'];_require(_integer(started))
            self._next+=1
            return Command(value['id'],operation,nonce,packages,started)
        except BaseException:
            self._poisoned=True
            raise ProtocolError() from None


class _Budget:
    def __init__(self):
        self._poisoned=False;self._active=None;self._last=0;self._used=0;self._fixed=set();self._policies=0

    def _reserve(self,identifier,operation):
        _require(not self._poisoned and self._active is None and _integer(identifier,True) and identifier>self._last and
            type(operation) is str and operation in CAPS)
        _require(self._policies<67 if operation=='policy' else operation not in self._fixed)
        self._last=identifier
        if operation=='policy':self._policies+=1
        else:self._fixed.add(operation)
        token=object();self._active=token
        return token

    def _charge(self,size):
        _require(_integer(size) and self._used+size<=SESSION_BYTES)
        self._used+=size

    def _fail(self):
        self._poisoned=True
        raise ProtocolError() from None


class DataEncoder(_Budget):
    def encode(self,identifier,operation,text):
        # A normal function, not a generator: admission/whole-byte charging
        # happens even if its returned iterator is never advanced.
        try:
            token=self._reserve(identifier,operation)
            _require(type(text) is str and len(text)<=CAPS[operation])
            total=0
            for offset in range(0,len(text),CHUNK_CHARS):
                total+=_utf8(text[offset:offset+CHUNK_CHARS])
                _require(total<=CAPS[operation])
            self._charge(total)
            return _EncodedData(self,token,identifier,operation,text,total)
        except BaseException:self._fail()


class _EncodedData:
    def __init__(self,owner,token,identifier,operation,text,total):
        self._owner=owner;self._token=token;self._id=identifier;self._op=operation;self._text=text;self._total=total
        self._offset=0;self._index=0;self._finished=False
    def __iter__(self):return self
    def __next__(self):
        if self._finished:raise StopIteration
        try:
            _require(not self._owner._poisoned and self._owner._active is self._token)
            base={'schema_version':1,'id':self._id,'operation':self._op}
            if self._offset<len(self._text):
                text=self._text[self._offset:self._offset+CHUNK_CHARS]
                _require(0<_utf8(text)<=CHUNK_BYTES and self._index<1024)
                raw=_encode(dict(base,phase='data',chunk_index=self._index,text=text))
                self._offset+=len(text);self._index+=1
                return raw
            raw=_encode(dict(base,phase='data_complete',chunks=self._index,utf8_bytes=self._total))
            self._owner._active=None;self._finished=True;self._text=None
            return raw  # Local encoding completion is NOT a transport ACK.
        except BaseException:self._owner._fail()
    def close(self):
        if not self._finished:
            self._text=None;self._owner._poisoned=True


class DataDecoder(_Budget):
    def start(self,identifier,operation):
        try:return _DataAssembly(self,self._reserve(identifier,operation),identifier,operation)
        except BaseException:self._fail()


class _DataAssembly:
    def __init__(self,owner,token,identifier,operation):
        self._owner=owner;self._token=token;self._id=identifier;self._op=operation
        self._parts=[];self._bytes=0;self._done=False;self._taken=False
    def feed(self,raw):
        try:
            _require(not self._owner._poisoned and self._owner._active is self._token and not self._done)
            value=_load(raw)
            _require(type(value.get('schema_version')) is int and value['schema_version']==1 and
                _integer(value.get('id'),True) and value['id']==self._id and value.get('operation')==self._op)
            if value.get('phase')=='data':
                _require(set(value)=={'schema_version','id','operation','phase','chunk_index','text'} and
                    _integer(value['chunk_index']) and value['chunk_index']==len(self._parts) and len(self._parts)<1024 and
                    type(value['text']) is str and 0<len(value['text'])<=CHUNK_CHARS)
                size=_utf8(value['text'])
                _require(size<=CHUNK_BYTES and self._bytes+size<=CAPS[self._op])
                self._owner._charge(size);self._bytes+=size;self._parts.append(value['text'])
            else:
                _require(set(value)=={'schema_version','id','operation','phase','chunks','utf8_bytes'} and
                    value['phase']=='data_complete' and _integer(value['chunks']) and value['chunks']==len(self._parts) and
                    _integer(value['utf8_bytes']) and value['utf8_bytes']==self._bytes)
                self._done=True  # Ownership stays active until take(), not final.
        except BaseException:
            self._parts=[];self._owner._fail()
    def take(self):
        try:
            _require(not self._owner._poisoned and self._owner._active is self._token and self._done and not self._taken)
            self._taken=True;parts,self._parts=self._parts,[];self._owner._active=None
            return ''.join(parts)
        except BaseException:self._owner._fail()
    def close(self):
        self._parts=[]
        if not self._taken:self._owner._poisoned=True
