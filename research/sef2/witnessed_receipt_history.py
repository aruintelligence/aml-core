"""Pure checkpoint comparison for independently anchored SEF2 receipt history.

The caller must authenticate the witness head and count out of band. This
module cannot establish that a witness is independent or that its state is
durable. No result here authorizes effect execution.
"""
from reservation_receipt_chain import verify_reservation_chain

def classify_witnessed_history(entries, local_head, witness_head):
    """Return MATCH, BEHIND, DIVERGED, or UNKNOWN.

    Both heads are (sequence, hash) pairs. BEHIND is a hard deny condition,
    not an invitation to retry a stranded effect.
    """
    try:
        if (type(local_head) not in (tuple, list) or len(local_head) != 2
            or type(witness_head) not in (tuple, list) or len(witness_head) != 2):
            return "UNKNOWN"
        local_count, local_hash = local_head
        witness_count, witness_hash = witness_head
        if (type(local_count) is not int or local_count < 0
            or type(witness_count) is not int or witness_count < 0):
            return "UNKNOWN"
        if (type(witness_hash) is not str or len(witness_hash) != 64
            or any(c not in "0123456789abcdef" for c in witness_hash)):
            return "UNKNOWN"
        if not verify_reservation_chain(entries, local_hash, local_count):
            return "DIVERGED"
        if local_count < witness_count:
            return "BEHIND"
        if local_count == witness_count:
            return "MATCH" if local_hash == witness_hash else "DIVERGED"
        # Local history is ahead of last witnessed checkpoint. The prefix
        # must match; otherwise this is a fork, not merely an unanchored tail.
        from reservation_receipt_chain import GENESIS, reservation_chain_hash
        cursor = GENESIS
        for index, entry in enumerate(entries, 1):
            cursor = reservation_chain_hash(cursor, *entry)
            if index == witness_count:
                return "AHEAD_UNANCHORED" if cursor == witness_hash else "DIVERGED"
        return "AHEAD_UNANCHORED" if witness_count == 0 and witness_hash == GENESIS else "DIVERGED"
    except (TypeError, ValueError):
        return "UNKNOWN"
