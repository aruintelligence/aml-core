"""Validate pinned witness keys and administrative failure-domain separation.

The manifest must be pinned out of band. Declared domains are assertions, not
proof of organizational independence. The fault model covers one compromised
domain in one dimension at a time; cross-dimension collusion remains out of scope.
"""
import hashlib
from signed_receipt import canonical

DIMENSIONS=("operator","hosting","key_custody","network_path","recovery_admin")

def independence_digest(manifest):
    return hashlib.sha256(canonical(manifest)).hexdigest()

def verify_independence(manifest,expected_witness_ids,pinned_digest,witness_public_keys):
    if (type(manifest) is not dict or set(manifest)!={"witnesses"}
        or type(manifest["witnesses"]) is not dict
        or type(expected_witness_ids) not in (list,tuple)
        or type(witness_public_keys) is not dict):
        return False
    if any(type(name) is not str or not name for name in expected_witness_ids):
        return False
    ids=set(expected_witness_ids)
    if len(ids)!=len(expected_witness_ids) or len(ids)<2:
        return False
    records=manifest["witnesses"]
    if set(records)!=ids or set(witness_public_keys)!=ids:
        return False
    if type(pinned_digest) is not str or len(pinned_digest)!=64:
        return False
    if any(c not in "0123456789abcdef" for c in pinned_digest):
        return False
    if independence_digest(manifest)!=pinned_digest:
        return False
    columns={dimension:set() for dimension in DIMENSIONS}
    for identity,record in records.items():
        if type(record) is not dict or set(record)!=(set(DIMENSIONS)|{"public_key_sha256"}):
            return False
        raw=witness_public_keys[identity]
        if type(raw) is not str or len(raw)!=64:
            return False
        try:
            key=bytes.fromhex(raw)
        except ValueError:
            return False
        if len(key)!=32:
            return False
        fingerprint=hashlib.sha256(key).hexdigest()
        if record["public_key_sha256"]!=fingerprint:
            return False
        for dimension in DIMENSIONS:
            value=record[dimension]
            if type(value) is not str or not value.strip() or len(value)>256:
                return False
            if value in columns[dimension]:
                return False
            columns[dimension].add(value)
    return True
