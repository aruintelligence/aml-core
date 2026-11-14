"""Exhaustive bounded state exploration for synthetic revoke/consume protocol.

This is an explicit-state model, not a formal proof of the Python/SQLite
implementation. Each transition models one atomic broker DB transaction.
"""
from collections import deque

def successors(state):
    epoch,issued,committed=state
    # issue a capability at the current epoch; revocation is monotonic.
    if issued is None:
        yield "issue", (epoch,epoch,committed)
    if epoch<2:
        yield "revoke", (epoch+1,issued,committed)
    # Commit is possible only for an unconsumed operation and a capability
    # whose signed epoch equals the durable current policy epoch.
    if issued==epoch and not committed:
        yield "commit", (epoch,issued,True)

def explore():
    initial=(0,None,False)
    queue=deque([(initial,())])
    visited={initial}
    edges=0
    while queue:
        state,trace=queue.popleft()
        epoch,issued,committed=state
        if epoch<0 or epoch>2 or (issued is not None and issued>epoch):
            raise AssertionError(("invalid state",trace,state))
        for event,next_state in successors(state):
            edges+=1
            if event=="commit":
                if state[2] or state[1]!=state[0] or not next_state[2]:
                    raise AssertionError(("unauthorized commit",trace,event,state))
            if next_state[0]<epoch or (committed and not next_state[2]):
                raise AssertionError(("rollback or double consume",trace,event,state))
            if next_state not in visited:
                visited.add(next_state)
                queue.append((next_state,trace+(event,)))
    return len(visited),edges
