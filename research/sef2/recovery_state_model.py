"""Bounded exhaustive model for threshold witness-key recovery safety."""
from itertools import combinations
def analyze_recovery_quorums(n,q,f):
    if any(type(x) is not int for x in (n,q,f)) or n<1 or q<1 or q>n or f<0:
        raise ValueError("invalid bounds")
    members=tuple(range(n)); quorums=list(combinations(members,q))
    counterexample=None; minimum=n
    for left,right in combinations(quorums,2):
        overlap=set(left)&set(right); minimum=min(minimum,len(overlap))
        if len(overlap)<=f and counterexample is None:
            counterexample={"first":left,"second":right,"overlap":tuple(sorted(overlap))}
    fault_bound=n>=3*f+1; liveness=q<=n-f; honest_intersection=counterexample is None
    return {"n":n,"q":q,"f":f,"quorums":len(quorums),
        "minimum_intersection":minimum if len(quorums)>1 else q,
        "fault_bound_valid":fault_bound,"liveness":liveness,
        "conflicting_commit_impossible":honest_intersection,
        "safe":fault_bound and liveness and honest_intersection,
        "counterexample":counterexample}
def recovery_commit_allowed(current_generation,current_parent,proposal_generation,
        proposal_parent,approvals,enrolled,n,q):
    if any(type(x) is not int for x in (current_generation,proposal_generation,n,q)): return False
    if type(current_parent) is not str or type(proposal_parent) is not str: return False
    if type(approvals) is not set or type(enrolled) is not set: return False
    return (proposal_generation==current_generation+1 and proposal_parent==current_parent
        and approvals<=enrolled and len(approvals)>=q and len(enrolled)==n)
def explore_recovery_sequence(steps=3):
    if type(steps) is not int or steps<1 or steps>8: raise ValueError("invalid steps")
    initial=(0,"genesis"); states={initial}; frontier=[initial]; edges=0
    for _ in range(steps):
        nxt=[]
        for generation,parent in frontier:
            candidates=[(generation+1,parent),(generation,parent),(generation+2,parent),(generation+1,"stale")]
            for proposal_generation,proposal_parent in candidates:
                edges+=1
                if proposal_generation==generation+1 and proposal_parent==parent:
                    state=(proposal_generation,f"h{proposal_generation}")
                    if state not in states: states.add(state); nxt.append(state)
        frontier=nxt
    return {"states":len(states),"edges":edges,"max_generation":max(g for g,_ in states)}
