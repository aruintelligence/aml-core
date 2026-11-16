"""Strict authority-bound evidence source for the SEF2 witness bridge.

This wrapper opens a pre-provisioned, existing ledger path, rather than taking
an arbitrary caller-provided object. Its security still depends on deployment
permissions: the caller must not control the ledger directory or the witness.
"""
import os
import stat
from atomic_receipt_reservations import AtomicReceiptReservations
from committed_witness_bridge import advance_from_committed_evidence

class PinnedLedgerWitnessBridge:
    def __init__(self, ledger_path, authority_id, *, expected_uid=None):
        if type(expected_uid) is not int and expected_uid is not None:
            raise ValueError("invalid expected owner")
        self.ledger_path = str(ledger_path)
        self.authority_id = authority_id
        self.expected_uid = expected_uid
        info = os.stat(self.ledger_path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("ledger path is not a regular file")
        if expected_uid is not None and info.st_uid != expected_uid:
            raise ValueError("ledger owner mismatch")
        self.identity = (info.st_dev, info.st_ino)
        self.ledger = AtomicReceiptReservations(
            self.ledger_path, authority_id, require_existing=True)

    def source_is_current(self):
        try:
            info = os.stat(self.ledger_path, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                return False
            if (info.st_dev, info.st_ino) != self.identity:
                return False
            if self.expected_uid is not None and info.st_uid != self.expected_uid:
                return False
            return True
        except (OSError, TypeError, ValueError, AttributeError):
            return False

    def advance(self, witness):
        if not self.source_is_current():
            return False
        if witness.authority_id != self.authority_id:
            return False
        # Recheck path identity after the evidence read.
        # This is not a race-free descriptor-based filesystem boundary.
        result = advance_from_committed_evidence(
            witness, self.ledger, evidence_guard=self.source_is_current)
        return bool(result and self.source_is_current())
