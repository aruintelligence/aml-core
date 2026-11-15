"""Fail-closed reconciliation for an interrupted recovery-ledger anchor CAS.

A signer commits a signed event locally before advancing its external anchor.
If the process stops or a quorum CAS is partially applied, this routine can
complete exactly one pending head transition when the caller supplies the
independently retained predecessor pin. It never creates a new signature or
edits the local ledger.
"""
import hashlib,sqlite3
from cryptography.exceptions import InvalidSignature
from threshold_recovery import RecoveryAuthoritySigner,verify_approval_ledger

def reconcile_recovery_authority_anchor(authority_id,private_key,ledger_path,
        head_anchor,expected_previous_head):
    if (type(authority_id) is not str or not authority_id
        or type(expected_previous_head) is not str or len(expected_previous_head)!=64
        or any(c not in "0123456789abcdef" for c in expected_previous_head)):
        return "INVALID_RECONCILIATION_INPUT"
    try:
        public_key=private_key.public_key()
        public_raw=public_key.public_bytes_raw()
        with sqlite3.connect(ledger_path,timeout=10) as con:
            meta=dict(con.execute("SELECT key,value FROM recovery_ledger_meta").fetchall())
        if (meta.get("authority_id")!=authority_id
            or meta.get("authority_key_sha256")!=hashlib.sha256(public_raw).hexdigest()):
            return "AUTHORITY_IDENTITY_MISMATCH"
        proxy=object.__new__(RecoveryAuthoritySigner)
        proxy.authority_id=authority_id
        proxy.private_key=private_key
        proxy.ledger_path=str(ledger_path)
        bundle=proxy.export_approval_ledger()
        if not verify_approval_ledger(bundle,public_key):
            return "INVALID_LOCAL_LEDGER"
        events=bundle["events"]; local_head=bundle["head_sha256"]
        if local_head==expected_previous_head:
            return "ALREADY_CURRENT"
        pending=[event for event in events
            if event["previous_event_sha256"]==expected_previous_head]
        if len(pending)!=1 or not events or pending[0]!=events[-1]:
            return "EXPECTED_PREDECESSOR_MISMATCH"
        if not head_anchor.compare_and_set(expected_previous_head,local_head):
            return "ANCHOR_RECONCILIATION_FAILED"
        return "RECONCILED"
    except (sqlite3.Error,OSError,ValueError,TypeError,KeyError,AttributeError,
            InvalidSignature,OverflowError):
        return "RECONCILIATION_ERROR"
