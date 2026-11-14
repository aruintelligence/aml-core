"""Validate witness administrative failure-domain separation.

This is an explicit, pinned configuration audit, not proof that the declared
operators or infrastructure are genuinely independent. Each dimension models
one compromise domain at a time; simultaneous cross-domain collusion is out of
scope and must be stated in the system threat model.
"""
import hashlib
from signed_receipt import canonical

DIMENSIONS=("operator","hosting","key_custody","network_path","recovery_admin")

def independence_digest(manifest):
    return hashlib.sha256(canonical(manifest)).hexdigest()

def verify_independence(witness_domains,expected_witness_ids,pinned_digest):
    if type(witness_domains) is not dict or type(expected_witness_ids) not in (list,tuple):
        return False
    if any(type(name) is not str or not name for name in expected_witness_ids):
        return False
    if len(set(expected_witness_ids))!=len(expected_witness_ids) or set(witness_domains)!=set(expected_witness_ids):
        return False
    if len(expected_witness_ids)<2:
        return False
    if type(pinned_digest) is not str or len(pinned_digest)!=64:
        return False
    if any(c not in "0123456789abcdef" for c in pinned_digest):
        return False
    if independence_digest(witness_domains)!=pinned_digest:
        return False
    columns={dimension:set() for dimension in DIMENSIONS}
    for identity,domains in witness_domains.items():
        if type(identity) is not str or not identity or type(domains) is not dict or set(domains)!=set(DIMENSIONS):
            return False
        for dimension in DIMENSIONS:
            value=domains[dimension]
            if type(value) is not str or not value.strip() or len(value)>256:
                return False
            if value in columns[dimension]:
                return False
            columns[dimension].add(value)
    return True
