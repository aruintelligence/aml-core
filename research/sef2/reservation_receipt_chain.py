"""Research-only append-only reservation receipt chain.

A chain can detect modification when its latest head is retained by an
independent witness. A local chain alone CANNOT detect rollback of its entire
database. This module does not anchor or verify external witness receipts.
"""
import hashlib
import json

DOMAIN = b"AML-SEF2-RESERVATION-CHAIN-V1\x00"
GENESIS = "0" * 64

def reservation_chain_hash(previous, authority_id, operation_id, digest, generation):
    """Return a domain-separated hash for one strictly validated reservation."""
    if (type(previous) is not str or len(previous) != 64
        or any(c not in "0123456789abcdef" for c in previous)
        or type(authority_id) is not str or not 1 <= len(authority_id) <= 128
        or not authority_id.isascii() or not authority_id.isprintable()
        or type(operation_id) is not str or not 1 <= len(operation_id) <= 128
        or not operation_id.isascii() or not operation_id.isprintable()
        or type(digest) is not str or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
        or type(generation) is not int or generation < 0):
        raise ValueError("invalid reservation chain input")
    payload = json.dumps(
        [previous, authority_id, operation_id, digest, generation],
        separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(DOMAIN + payload).hexdigest()

def verify_reservation_chain(entries, expected_head, expected_count):
    """Verify ordered evidence against an independently supplied head and count.

    Caller must authenticate expected_head/expected_count out-of-band. This
    function is intentionally pure; it never grants effect execution.
    """
    if type(expected_count) is not int or expected_count < 0:
        return False
    if (type(expected_head) is not str or len(expected_head) != 64
        or any(c not in "0123456789abcdef" for c in expected_head)):
        return False
    head = GENESIS
    count = 0
    seen = set()
    try:
        for authority_id, operation_id, digest, generation in entries:
            identity = (authority_id, operation_id)
            if identity in seen:
                return False
            seen.add(identity)
            head = reservation_chain_hash(
                head, authority_id, operation_id, digest, generation)
            count += 1
            if count > expected_count:
                return False
        return count == expected_count and head == expected_head
    except (TypeError, ValueError):
        return False
