"""Witness advancement against independently read committed reservation evidence.

The witness must read evidence from a reservation authority it trusts; caller-
supplied entries alone are not proof of committed authorization. This adapter
fails closed unless the authoritative snapshot is exactly one entry beyond the
last witnessed checkpoint and the prefix is anchored.
"""
from reservation_receipt_chain import GENESIS, reservation_chain_hash, verify_reservation_chain

def advance_from_committed_evidence(witness, reservation_store, *, evidence_guard=None):
    """Advance witness only after validating an independently obtained snapshot.

    Both objects must be provisioned under separate access-control boundaries.
    The caller must not control reservation_store.evidence() or its database.
    """
    try:
        if witness.authority_id != reservation_store.authority_id:
            return False
        current = witness.inspect()
        if current is None:
            return False
        sequence, previous_head = current
        if type(sequence) is not int or sequence < 0:
            return False
        snapshot_head, entries = reservation_store.evidence()
        if (type(snapshot_head) not in (tuple, list) or len(snapshot_head) != 2
            or type(snapshot_head[0]) is not int
            or snapshot_head[0] != sequence + 1
            or type(entries) not in (tuple, list)
            or len(entries) != sequence + 1):
            return False
        if not verify_reservation_chain(entries, snapshot_head[1], sequence + 1):
            return False
        prefix = GENESIS
        for entry in entries[:-1]:
            prefix = reservation_chain_hash(prefix, *entry)
        if prefix != previous_head:
            return False
        entry = entries[-1]
        if entry[0] != witness.authority_id:
            return False
        if evidence_guard is not None and evidence_guard() is not True:
            return False
        return witness.observe(sequence + 1, snapshot_head[1],
                               sequence, previous_head, entry) is True
    except (AttributeError, IndexError, OSError, TypeError, ValueError):
        return False
