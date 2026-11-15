"""Bounded explicit-state model for session-bound capability execution.

State:
(epoch, capability_epoch, challenge_epoch, challenge_live, holder_key_present, committed)

Events model issuance, challenge creation, holder-key loss/copy, revocation, proof
attempt, and commit. Authorization may commit only when the capability and
challenge match the current epoch, challenge is live, holder key is present,
and the effect has not committed.

This is an abstract bounded model, not proof of the Python/SQLite or OS-key
custody implementation.
"""
from collections import deque

def successors(state):
    epoch,cap_epoch,challenge_epoch,live,holder,committed=state
    if cap_epoch is None:
        yield "issue_capability",(epoch,epoch,challenge_epoch,live,holder,committed)
    if cap_epoch is not None and not live and not committed:
        yield "issue_challenge",(epoch,cap_epoch,epoch,True,holder,committed)
    if holder:
        yield "holder_key_lost",(epoch,cap_epoch,challenge_epoch,live,False,committed)
    else:
        # Copying public history/token does not recreate the private holder key.
        yield "copy_public_context",(epoch,cap_epoch,challenge_epoch,live,False,committed)
    if epoch<2:
        yield "revoke",(epoch+1,cap_epoch,challenge_epoch,live,holder,committed)
    can_commit=(not committed and holder and live and cap_epoch==epoch
        and challenge_epoch==epoch)
    if can_commit:
        yield "commit",(epoch,cap_epoch,challenge_epoch,False,holder,True)
    else:
        yield "proof_attempt_denied",state

def explore():
    initial=(0,None,None,False,True,False)
    queue=deque([(initial,())]); seen={initial}; edges=0; commits=[]
    while queue:
        state,trace=queue.popleft()
        epoch,cap_epoch,challenge_epoch,live,holder,committed=state
        if epoch<0 or epoch>2:
            raise AssertionError(("epoch out of bounds",trace,state))
        if committed and live:
            raise AssertionError(("committed state retains live challenge",trace,state))
        for event,next_state in successors(state):
            edges+=1
            if event=="commit":
                if (committed or not holder or not live or cap_epoch!=epoch
                    or challenge_epoch!=epoch or not next_state[-1]):
                    raise AssertionError(("unauthorized commit",trace,event,state))
                commits.append(trace+(event,))
            if next_state[-1] and not committed and event!="commit":
                raise AssertionError(("implicit commit",trace,event,state))
            if next_state not in seen:
                seen.add(next_state); queue.append((next_state,trace+(event,)))
    return {"states":len(seen),"edges":edges,"commit_traces":commits}

def commit_allowed(epoch,capability_epoch,challenge_epoch,challenge_live,
                   holder_key_present,committed):
    values=(epoch,capability_epoch,challenge_epoch)
    if type(epoch) is not int or any(v is not None and type(v) is not int for v in values[1:]):
        return False
    return (not committed and holder_key_present is True and challenge_live is True
        and capability_epoch==epoch and challenge_epoch==epoch)
