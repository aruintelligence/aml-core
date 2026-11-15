"""Bounded explicit-state model for anchored session revocation.

This is model checking over a finite state space, not proof of the Python/SQLite
implementation. It exists to search for rollback-resurrection counterexamples.
"""
from collections import deque
from dataclasses import dataclass

@dataclass(frozen=True)
class State:
    local_epoch:int=0
    anchor_epoch:int=0
    challenge_epoch:int|None=None
    old_cap_committed_after_revocation:bool=False

def transitions(state,broken_execute=False,max_epoch=2):
    out=[]
    l,a,c=state.local_epoch,state.anchor_epoch,state.challenge_epoch
    if l==a:
        out.append(("issue_challenge",State(l,a,l,state.old_cap_committed_after_revocation)))
    if l<max_epoch:
        out.append(("revoke_local",State(l+1,a,c,state.old_cap_committed_after_revocation)))
    if l==a+1:
        out.append(("anchor_commit",State(l,l,c,state.old_cap_committed_after_revocation)))
    if l<a:
        out.append(("sync_local_up",State(a,a,c,state.old_cap_committed_after_revocation)))
    if l>0:
        out.append(("rollback_local",State(0,a,c,state.old_cap_committed_after_revocation)))
    if c is not None:
        out.append(("rollback_challenge",State(l,a,0,state.old_cap_committed_after_revocation)))
    old_cap_epoch=0
    allowed=(c==old_cap_epoch and l==old_cap_epoch)
    if not broken_execute:
        allowed=allowed and a==old_cap_epoch
    if allowed:
        violated=state.old_cap_committed_after_revocation or a>old_cap_epoch
        out.append(("execute_old_capability",State(l,a,c,violated)))
    return out

def explore(depth=8,broken_execute=False):
    start=State()
    queue=deque([(start,())]); seen={(start,0)}
    violations=[]
    while queue:
        state,path=queue.popleft()
        if state.old_cap_committed_after_revocation:
            violations.append(path); continue
        if len(path)>=depth: continue
        for action,nxt in transitions(state,broken_execute):
            item=(nxt,len(path)+1)
            if item in seen: continue
            seen.add(item)
            queue.append((nxt,path+(action,)))
    return violations
