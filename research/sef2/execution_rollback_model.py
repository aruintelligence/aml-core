"""Bounded model for single-use execution under broker rollback.

Persistent witness consumption and the one-shot in-flight commit permit are
modeled separately. Broker rollback can restore local effect/challenge state,
but cannot restore a consumed witness permit.
"""
from collections import deque
from dataclasses import dataclass

@dataclass(frozen=True)
class State:
    witness_consumed:bool=False
    commit_permit:bool=False
    local_effect:bool=False
    challenge_available:bool=True
    external_effect_count:int=0

def successors(state,broken=False):
    out=[]
    w,permit,l,c,count=(state.witness_consumed,state.commit_permit,
                        state.local_effect,state.challenge_available,
                        state.external_effect_count)
    if c and not l:
        if broken:
            out.append(("execute",State(w,permit,True,False,count+1)))
        elif not w:
            out.append(("consume_witness",State(True,True,l,c,count)))
    if permit and c and not l and not broken:
        out.append(("commit_effect",State(w,False,True,False,count+1)))
    if l or not c:
        # Rollback restores broker-local effect/challenge state only. It cannot
        # recreate the already-spent independent witness permit.
        out.append(("rollback_broker",State(w,False,False,True,count)))
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
