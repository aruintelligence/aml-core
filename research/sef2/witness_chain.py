"""SEF/2 synthetic witness checkpoint chain, offline fork and omission detection.

A hash chain detects modifications against a previously trusted checkpoint.
It does NOT independently prevent equivocation, rollback, or witness collusion.
"""
import hashlib
import json

DOMAIN = b"AML-SEF2-WITNESS-CHAIN-V1\x00"
GENESIS = "0" * 64

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")

def hash_entry(entry):
    return hashlib.sha256(DOMAIN + canonical(entry)).hexdigest()

def append(chain, receipt_digest):
    if type(receipt_digest) is not str or len(receipt_digest) != 64 or any(
        c not in "0123456789abcdef" for c in receipt_digest):
        raise ValueError("invalid receipt digest")
    previous = chain[-1]["hash"] if chain else GENESIS
    entry = {"sequence": len(chain) + 1, "previous": previous,
        "receipt_sha256": receipt_digest}
    return {**entry, "hash": hash_entry(entry)}

def verify(chain, trusted_checkpoint=None):
    previous = GENESIS
    if type(chain) is not list:
        return False
    for i, row in enumerate(chain, 1):
        if type(row) is not dict or set(row) != {"sequence", "previous",
            "receipt_sha256", "hash"}:
            return False
        if type(row["sequence"]) is not int or row["sequence"] != i:
            return False
        if row["previous"] != previous:
            return False
        if type(row["receipt_sha256"]) is not str or len(row["receipt_sha256"]) != 64:
            return False
        if any(c not in "0123456789abcdef" for c in row["receipt_sha256"]):
            return False
        entry = {k: row[k] for k in ("sequence", "previous", "receipt_sha256")}
        if type(row["hash"]) is not str or row["hash"] != hash_entry(entry):
            return False
        previous = row["hash"]
    if trusted_checkpoint is not None:
        if type(trusted_checkpoint) is not dict or set(trusted_checkpoint) != {"size", "head"}:
            return False
        size, head = trusted_checkpoint["size"], trusted_checkpoint["head"]
        if type(size) is not int or size < 0 or size > len(chain):
            return False
        if type(head) is not str:
            return False
        expected = chain[size - 1]["hash"] if size else GENESIS
        if expected != head:
            return False
    return True

def checkpoint(chain):
    if not verify(chain):
        raise ValueError("invalid chain")
    return {"size": len(chain), "head": chain[-1]["hash"] if chain else GENESIS}

def fork_detected(left, right):
    """Detect conflicting heads at the same size, not hidden forks at different sizes."""
    if any(type(c) is not dict or set(c) != {"size", "head"} for c in (left, right)):
        raise ValueError("invalid checkpoint")
    return left["size"] == right["size"] and left["head"] != right["head"]
