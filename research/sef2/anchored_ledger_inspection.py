"""Witness-anchored ledger inspection for SEF2 synthetic research.

The witness checkpoint must come from a separately protected witness store.
Local integrity checks alone cannot detect a whole-ledger rollback that
recreates a valid historical hash chain.
"""
from witnessed_receipt_history import classify_witnessed_history

def inspect_anchored_ledger(witness, pinned_bridge):
    """Return strict classification; fail closed for missing/unreadable evidence."""
    try:
        if witness.authority_id != pinned_bridge.authority_id:
            return "UNKNOWN"
        witness_head = witness.inspect()
        if witness_head is None:
            return "UNKNOWN"
        if not pinned_bridge.source_is_current():
            return "UNKNOWN"
        local_head, entries = pinned_bridge.ledger.evidence()
        if not pinned_bridge.source_is_current():
            return "UNKNOWN"
        if witness.inspect() != witness_head:
            return "UNKNOWN"
        return classify_witnessed_history(entries, local_head, witness_head)
    except (OSError, ValueError, TypeError, AttributeError):
        return "UNKNOWN"

def anchored_ledger_is_current(witness, pinned_bridge):
    return inspect_anchored_ledger(witness, pinned_bridge) == "MATCH"
