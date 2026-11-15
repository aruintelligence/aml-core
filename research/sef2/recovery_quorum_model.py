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


def model_check_conflicting_commits(n,q,f):
    """Exhaustively search Byzantine sets and quorum pairs for two conflicting commits.

    Honest authorities are constrained to sign at most one payload per
    (policy, witness, generation); Byzantine authorities may sign both.
    Returns a concrete counterexample when two distinct payloads can each
    gather q signatures. This is a bounded authorization-safety model, not
    a network-consensus or implementation proof.
    """
    from itertools import combinations
    if any(type(x) is not int for x in (n,q,f)) or n<1 or f<0 or q<1 or q>n:
        raise ValueError("invalid model bounds")
    members=tuple(range(n))
    quorums=list(combinations(members,q))
    for fault_count in range(min(f,n)+1):
        for faulty_tuple in combinations(members,fault_count):
            faulty=set(faulty_tuple)
            for left in quorums:
                for right in quorums:
                    if left==right:
                        continue
                    intersection=set(left)&set(right)
                    if intersection.issubset(faulty):
                        return {
                            "byzantine":sorted(faulty),
                            "first_payload":"A",
                            "second_payload":"B",
                            "first_quorum":list(left),
                            "second_quorum":list(right),
                            "equivocating_honest":[],
                            "intersection":sorted(intersection),
                        }
    return None

def bounded_recovery_state_check(n,q,f):
    """Check quorum safety plus sequential recovery state invariants."""
    conflict=model_check_conflicting_commits(n,q,f)
    quorum=exhaustively_check(n,q,f)
    # Abstract successful transitions must advance exactly one generation,
    # bind to the current head, replace the current key, and revoke its predecessor.
    state={"generation":0,"key":"K0","revoked":frozenset(),"head":"H0"}
    good={"generation":1,"previous_head":"H0","old_key":"K0","new_key":"K1","new_head":"H1"}
    accepted=(good["generation"]==state["generation"]+1
        and good["previous_head"]==state["head"] and good["old_key"]==state["key"]
        and good["new_key"] not in state["revoked"])
    next_state={"generation":good["generation"],"key":good["new_key"],
        "revoked":state["revoked"]|{state["key"]},"head":good["new_head"]} if accepted else state
    replay=(good["generation"]==next_state["generation"]+1
        and good["previous_head"]==next_state["head"])
    stale={"generation":1,"previous_head":"H0","old_key":"K0","new_key":"K2","new_head":"H2"}
    stale_accepted=(stale["generation"]==next_state["generation"]+1
        and stale["previous_head"]==next_state["head"] and stale["old_key"]==next_state["key"])
    return {
        "quorum":quorum,
        "conflicting_commit_counterexample":conflict,
        "conflicting_commits_excluded":conflict is None,
        "sequential_transition_accepted":accepted,
        "generation_advanced_once":next_state["generation"]==1,
        "predecessor_revoked":state["key"] in next_state["revoked"],
        "replay_excluded":not replay,
        "stale_fork_excluded":not stale_accepted,
        "safe":quorum["safe"] and conflict is None and accepted
            and next_state["generation"]==1 and state["key"] in next_state["revoked"]
            and not replay and not stale_accepted,
    }
