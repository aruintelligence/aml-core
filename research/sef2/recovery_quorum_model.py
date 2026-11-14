"""Bounded exhaustive model for threshold recovery quorum intersection.

Model assumptions: authority identities are fixed and authenticated; at most
f identities are Byzantine; every honest authority signs at most one recovery
payload per (policy, witness, generation); Byzantine authorities may sign both.
This checks quorum-intersection safety, not network consensus or implementation
correctness.
"""
from itertools import combinations

def find_equivocation_counterexample(n,q,f):
    if any(type(x) is not int for x in (n,q,f)) or n<1 or f<0 or q<1 or q>n:
        raise ValueError("invalid model bounds")
    identities=tuple(range(n))
    quorums=list(combinations(identities,q))
    candidates=[]
    for left,right in combinations(quorums,2):
        intersection=set(left)&set(right)
        candidates.append((len(intersection),left,right,intersection))
    if not candidates:
        return None
    minimum=min(item[0] for item in candidates)
    if minimum>f:
        return None
    _,left,right,intersection=min(
        (item for item in candidates if item[0]==minimum),
        key=lambda item:(item[1],item[2]))
    byzantine=sorted(intersection)
    return {"first_quorum":list(left),"second_quorum":list(right),
        "intersection":byzantine,"byzantine_set":byzantine,
        "honest_first":sorted(set(left)-intersection),
        "honest_second":sorted(set(right)-intersection)}

def exhaustively_check(n,q,f):
    counterexample=find_equivocation_counterexample(n,q,f)
    quorums=list(combinations(range(n),q))
    intersections=[len(set(a)&set(b)) for a,b in combinations(quorums,2)]
    minimum=min(intersections) if intersections else n
    fault_bound_valid=(n>=3*f+1)
    liveness=(q<=n-f)
    intersection_safe=(counterexample is None)
    return {"n":n,"q":q,"f":f,"quorum_count":len(quorums),
        "pair_count":len(intersections),"minimum_intersection":minimum,
        "fault_bound_valid":fault_bound_valid,"liveness":liveness,
        "intersection_safe":intersection_safe,
        "safe":fault_bound_valid and liveness and intersection_safe,
        "counterexample":counterexample}
