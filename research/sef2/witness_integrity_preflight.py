"""Fail-closed, read-only authorization preflight for SEF2 ledger integrity.

This is a prerequisite check, NEVER an effect-execution permit. The effect
boundary must separately verify the full authorization and idempotency policy.
"""
from anchored_ledger_inspection import inspect_anchored_ledger

DENY_REASONS = {
    "BEHIND": "LEDGER_ROLLBACK",
    "DIVERGED": "LEDGER_FORK_OR_CORRUPTION",
    "AHEAD_UNANCHORED": "UNWITNESSED_COMMIT",
    "UNKNOWN": "EVIDENCE_UNAVAILABLE",
}

def preflight_witness_integrity(witness, pinned_bridge):
    """Return an immutable (ready, reason) pair; deny on all uncertainty."""
    try:
        status = inspect_anchored_ledger(witness, pinned_bridge)
    except Exception:
        # Security boundary: unexpected storage/provider failures deny as well.
        return False, "EVIDENCE_UNAVAILABLE"
    if status == "MATCH":
        return True, "WITNESSED_HISTORY_MATCH"
    return False, DENY_REASONS.get(status, "EVIDENCE_UNAVAILABLE")
