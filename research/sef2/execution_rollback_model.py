"""Bounded model for single-use execution under broker rollback.

The independent witness is monotonic. The broker's local effect/challenge state
may roll back. Safe protocol consumes the witness before the local effect.
A broken protocol that trusts only local effect state exposes double execution.
"""
from collections import deque
from dataclasses import dataclass

@dataclass(frozen=True)
class State:
    witness_consumed:bool=False
    local_effect:bool=False
    challenge_available:bool=True
    external_effect_count:int=0

def successors(state,broken=False):
    out=[]
    w,l,c,count=state.witness_consumed,state.local_effect,state.challenge_available,state.external_effect_count
    if c and not l:
        if broken:
            out.append(("execute",State(w,True,False,count+1)))
        elif not w:
            out.append(("consume_witness",State(True,l,c,count)))
    if w and c and not l and not broken:
        out.append(("commit_effect",State(w,True,False,count+1)))
    if l or not c:
        out.append(("rollback_broker",State(w,False,True,count)))
    return out

def explore(depth=8,broken=False):
    start=State()
    queue=deque([(start,())]); seen={(start,0)}; violations=[]
    while queue:
        state,path=queue.popleft()
        if state.external_effect_count>1:
            violations.append(path); continue
        if len(path)>=depth: continue
        for action,nxt in successors(state,broken):
            marker=(nxt,len(path)+1)
            if marker in seen: continue
            seen.add(marker); queue.append((nxt,path+(action,)))
    return violations
