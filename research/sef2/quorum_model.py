"""Explicit Byzantine fault bounds for witness checkpoint quorums.

Safety assumes at most f Byzantine witness identities, independently pinned
keys, and every honest witness refuses to sign conflicting checkpoints at an
epoch. Liveness assumes at least q witnesses remain available.
"""
from itertools import combinations

def validate_bft_quorum(witness_count,threshold,max_faults):
    values=(witness_count,threshold,max_faults)
    if any(type(value) is not int for value in values):
        raise ValueError("quorum parameters must be integers, not booleans")
    n,q,f=values
    if n<2 or f<0 or n<3*f+1:
        raise ValueError("witness count cannot support declared Byzantine fault bound")
    if q<max(2,2*f+1) or q>n-f or q>n:
        raise ValueError("threshold violates Byzantine safety or liveness bounds")
    intersection=2*q-n
    if intersection<f+1:
        raise ValueError("quorum intersection may contain only Byzantine witnesses")
    return {"witness_count":n,"threshold":q,"max_byzantine_faults":f,
            "minimum_quorum_intersection":intersection,
            "minimum_honest_intersection":intersection-f}

def enumerate_quorum_intersections(witness_ids,threshold):
    ids=tuple(witness_ids)
    if len(set(ids))!=len(ids):
        raise ValueError("witness identities must be unique")
    if type(threshold) is not int or threshold<1 or threshold>len(ids):
        raise ValueError("invalid threshold")
    quorums=list(combinations(ids,threshold))
    return [len(set(left).intersection(right))
            for index,left in enumerate(quorums)
            for right in quorums[index+1:]]
