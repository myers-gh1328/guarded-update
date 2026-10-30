"""Bounded internal inbox dispatch, not an executable or activation interface.

Caller supplies fixed admitted inputs and retains the same journal lock. This
object takes exclusive observation lifecycle ownership from a fresh idle object;
all journal/guard/inbox objects remain borrowed. No running scope is adopted.
"""
from inventory_refresh_io import IOErrorState
from inventory_refresh_protocol import correlator


CAPABILITIES=('release','observation','refresh')
CONTEXT=('journal','publisher','policy','resources','store','writers')


class RootDispatcher:
    def __init__(self,journal,inboxes,refresh,observation):
        self._journal=journal;self._inboxes=dict(inboxes);self._refresh=refresh
        self._observation=observation;self._closed=False;self._owned=False;self._draining=False
        self._verify()
        if observation.pristine is not True:
            raise ValueError('Inventory dispatcher requires a fresh observation lifecycle')
        observation._claim_dispatcher(self)

    def _verify(self):
        self._journal._locked()
        if set(self._inboxes)!=set(CAPABILITIES):raise ValueError('Invalid fixed inventory inboxes')
        for name in CONTEXT:
            if getattr(self._refresh,'_'+name) is not getattr(self._observation,'_'+name):
                raise ValueError('Inventory dispatcher contexts differ')
        if self._refresh._journal is not self._journal or self._refresh._publisher._journal is not self._journal:
            raise ValueError('Inventory dispatcher journal differs')
        for name,inbox in self._inboxes.items():
            if inbox._capability!=name:raise ValueError('Inventory dispatcher capability differs')

    def _read(self,inbox):
        try:value=inbox.read()
        except IOErrorState as error:
            if error.reason=='invalid_request':return None,'invalid_request'
            raise
        if value is None:return None,None
        if type(value) is not tuple or len(value)!=2 or type(value[0]) is not str or type(value[1]) is not int:
            raise ValueError('Invalid trusted inventory inbox result')
        try:parsed=correlator(value[0].encode('ascii'))
        except (ValueError,UnicodeError):raise ValueError('Invalid trusted inventory correlator') from None
        if parsed!=value:raise ValueError('Invalid trusted inventory sequence')
        return value[0],None

    def _fatal(self):
        self._closed=True
        if self._owned:
            try:self._observation.close()
            except BaseException:pass
        try:self._journal.fence_external()
        except BaseException:pass

    def step(self):
        if self._draining:return self.drain()
        result={'state':'closed' if self._closed else 'ready','poll':None,
                'release':None,'observation':None,'refresh':None}
        if self._closed:return result
        try:
            self._verify()
            if self._journal.snapshot()['unconfirmed']:raise ValueError('Inventory dispatcher unconfirmed')
            if self._observation.owns_scope and not self._owned:
                raise ValueError('Inventory dispatcher cannot adopt observation ownership')
            result['poll']=self._observation.poll()
            if not self._observation.owns_scope:self._owned=False
            requests={}
            for name in CAPABILITIES:
                requests[name],result[name]=self._read(self._inboxes[name])
            if requests['release'] is not None:
                result['release']=self._observation.release(requests['release'])
            if requests['observation'] is not None:
                result['observation']=self._observation.begin(requests['observation'])
                if result['observation']=='dispatched':self._owned=True
            if (requests['refresh'] is not None and not self._observation.owns_scope and
                    result['observation']!='dispatched'):
                result['refresh']=self._refresh.refresh(requests['refresh'])
            return result
        except BaseException:
            self._fatal();raise ValueError('Inventory dispatcher unconfirmed') from None

    def drain(self):
        """Absorb new admissions and poll owned work; no shutdown authority."""
        self._draining=True
        result={'state':'closed' if self._closed else 'draining','poll':None,'release':None}
        if self._closed:return result
        try:
            self._verify()
            if self._journal.snapshot()['unconfirmed']:raise ValueError('Inventory dispatcher unconfirmed')
            if self._observation.owns_scope and not self._owned:
                raise ValueError('Inventory dispatcher cannot adopt observation ownership')
            self._observation._context()
            result['poll']=self._observation.poll()
            if result['poll']=='unconfirmed':raise ValueError('Inventory observation unconfirmed')
            if not self._observation.owns_scope:self._owned=False
            requests={};invalid=False
            for name in CAPABILITIES:
                requests[name],error=self._read(self._inboxes[name])
                invalid=invalid or error is not None
            if self._observation.owns_scope:
                job=self._observation._job
                if not self._owned or job is None:raise ValueError('Inventory observation ownership unavailable')
                if requests['release']==job.operation_nonce:
                    result['release']=self._observation.release(requests['release'])
                    if result['release']=='unconfirmed':raise ValueError('Inventory release unconfirmed')
            self._observation._context()
            snapshot=self._journal.snapshot()
            if snapshot['unconfirmed']:raise ValueError('Inventory dispatcher unconfirmed')
            active=any(value['active'] is not None for value in snapshot['capabilities'].values())
            if not invalid and not active and not self._observation.owns_scope and self._observation._pin is None:
                result['state']='drained'
            return result
        except BaseException:
            self._fatal();raise ValueError('Inventory dispatcher drain unconfirmed') from None

    def close(self):
        if self._closed:return
        self._closed=True
        if self._owned:self._observation.close()
