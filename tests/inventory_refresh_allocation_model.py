"""Abstract two-journal allocation contract, never production authority.

The caller must consume each returned state. Locks, writes and effect checks
are modeled symbols: this code proves no OS-level durability or cleanup.
The injected lock order is a hypothesis, not a chosen runtime lock order.
"""
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Model:
    epoch:str
    boot:str
    nonce:str
    order:tuple
    phase:int=0
    unknown:bool=False
    superseded:bool=False
    holder:str|None=None
    locks:tuple=()

    def __post_init__(self):
        if self.order not in (('agent','root'),('root','agent')):
            raise ValueError('A test lock-order hypothesis is required')

    def advance(self, action, epoch, boot, nonce):
        # Every observed reply or persistence result must replace the old state.
        actions=('intent','receive','submit','start')
        if (self.unknown or self.superseded or len(self.locks)!=2 or not self.holder
                or (epoch,boot,nonce)!=(self.epoch,self.boot,self.nonce)
                or self.phase>=len(actions) or action!=actions[self.phase]):
            return self.uncertain()
        return replace(self,phase=self.phase+1)

    def uncertain(self):
        return replace(self,unknown=True)

    def supersede(self):
        return replace(self,superseded=True,unknown=True)

    def may_effect(self):
        # This is a model predicate, not permission to launch a real process.
        return self.phase==4 and not self.unknown and not self.superseded

    def acquire(self,client,lock):
        if (self.unknown or not client or lock not in self.order or
                self.holder not in (None,client) or lock in self.locks or
                len(self.locks)>=2 or self.order[len(self.locks)]!=lock):
            raise ValueError('Modeled lock admission rejected')
        return replace(self,holder=client,locks=self.locks+(lock,))
