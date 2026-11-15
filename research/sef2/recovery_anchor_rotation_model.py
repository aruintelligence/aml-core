"""Bounded exhaustive model for recovery anchor council succession.

A conflicting state transfer must obtain both an outgoing quorum and an
incoming quorum. Honest identities in either council refuse to sign two
conflicting transfers for the same target/generation. The model enumerates all
quorum-pair combinations and Byzantine placements by overlap cardinality.
"""
from itertools import combinations

def analyze_anchor_succession(n_old,q_old,f_old,n_new,q_new,f_new):
    vals=(n_old,q_old,f_old,n_new,q_new,f_new)
    if any(type(x) is not int for x in vals) or min(n_old,q_old,n_new,q_new)<1 or min(f_old,f_new)<0:
        raise ValueError("invalid bounds")
    if q_old>n_old or q_new>n_new: raise ValueError("threshold exceeds membership")
    old=list(combinations(range(n_old),q_old))
    new=list(combinations(range(n_old,n_old+n_new),q_new))
    old_conflicts=[]; new_conflicts=[]
    for a,b in combinations(old,2):
        overlap=set(a)&set(b)
        if len(overlap)<=f_old: old_conflicts.append((a,b,tuple(sorted(overlap))))
    for a,b in combinations(new,2):
        overlap=set(a)&set(b)
        if len(overlap)<=f_new: new_conflicts.append((a,b,tuple(sorted(overlap))))
    old_safe=not old_conflicts; new_safe=not new_conflicts
    old_bft=n_old>=3*f_old+1; new_bft=n_new>=3*f_new+1
    old_live=q_old<=n_old-f_old; new_live=q_new<=n_new-f_new
    return {"old_safe":old_safe,"new_safe":new_safe,
        "old_bft_bound":old_bft,"new_bft_bound":new_bft,
        "old_liveness":old_live,"new_liveness":new_live,
        "safe":old_safe and new_safe and old_bft and new_bft and old_live and new_live,
        "old_counterexample":old_conflicts[0] if old_conflicts else None,
        "new_counterexample":new_conflicts[0] if new_conflicts else None}

def state_transfer_commit_allowed(current_rotation_generation,proof_generation,
        current_sequence,current_pin,proof_sequence,proof_pin,
        old_approvals,new_approvals,old_members,new_members,q_old,q_new):
    ints=(current_rotation_generation,proof_generation,current_sequence,proof_sequence,q_old,q_new)
    if any(type(x) is not int for x in ints): return False
    if type(current_pin) is not str or type(proof_pin) is not str: return False
    if any(type(s) is not set for s in (old_approvals,new_approvals,old_members,new_members)): return False
    return (proof_generation==current_rotation_generation
        and proof_sequence==current_sequence and proof_pin==current_pin
        and old_approvals<=old_members and new_approvals<=new_members
        and len(old_approvals)>=q_old and len(new_approvals)>=q_new)
