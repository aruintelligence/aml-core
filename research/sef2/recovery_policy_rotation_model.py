"""Bounded exhaustive model for dual-consent recovery-policy rotation.

Abstract model:
* The outgoing council is the authority that can authorize a successor.
* Every committed rotation also requires a threshold acceptance from the
  successor council, proving the recipient's consent.
* At most f outgoing authorities are Byzantine and may sign conflicting
  proposals. Honest authorities durably sign at most one proposal per
  (current policy, generation).
* Commit certificates contain q distinct signers from each council.

This enumerates quorum subsets and Byzantine placements. It does not model
cryptographic implementation, network timing, policy distribution, or durable
storage rollback; those are separate assumptions and tests.
"""
from itertools import combinations

def _integer(value):
    return type(value) is int

def check_rotation_model(n, q, f):
    if not all(_integer(x) for x in (n,q,f)) or n < 1 or f < 0 or q < 1 or q > n:
        raise ValueError("invalid rotation model bounds")
    old_members=tuple(range(n))
    old_quorums=list(combinations(old_members,q))
    new_members=tuple(range(n,2*n))
    new_quorums=list(combinations(new_members,q))
    intersections=[len(set(a)&set(b)) for a,b in combinations(old_quorums,2)]
    minimum_intersection=min(intersections) if intersections else n
    conflict=None
    for left,right in combinations(old_quorums,2):
        overlap=set(left)&set(right)
        if len(overlap)<=f:
            conflict={"first_old_quorum":list(left),"second_old_quorum":list(right),
                "intersection":sorted(overlap),"byzantine_intersection":sorted(overlap)}
            break
    fault_bound_valid=n>=3*f+1
    liveness=q<=n-f
    old_intersection_safe=conflict is None
    # Incoming council consent is an independent commit precondition. If up
    # to f recipients are unavailable, q<=n-f permits a certificate.
    incoming_consent_available=liveness
    return {"n":n,"q":q,"f":f,"old_quorum_count":len(old_quorums),
        "incoming_quorum_count":len(new_quorums),
        "old_quorum_pair_count":len(intersections),
        "minimum_old_intersection":minimum_intersection,
        "fault_bound_valid":fault_bound_valid,"liveness":liveness,
        "old_council_conflict_free":old_intersection_safe,
        "incoming_consent_available":incoming_consent_available,
        "safe":fault_bound_valid and liveness and old_intersection_safe,
        "conflict_counterexample":conflict}

def dual_consent_commit_allowed(old_approvals,new_approvals,n,q):
    if not all(_integer(x) for x in (n,q)) or n<1 or q<1 or q>n:
        raise ValueError("invalid dual-consent bounds")
    if type(old_approvals) is not set or type(new_approvals) is not set:
        return False
    if any(type(identity) is not int for identity in old_approvals | new_approvals):
        return False
    old=set(range(n)); new=set(range(n,2*n))
    return (len(old_approvals)>=q and old_approvals<=old
        and len(new_approvals)>=q and new_approvals<=new)
