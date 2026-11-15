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
        try:
            external_head=head_anchor.read_head()
        except Exception:
            # A 2-2 split or transient read outage has no unique read quorum.
            # The signed predecessor supplied by the caller still constrains
            # the only safe CAS candidate; the quorum adapter will advance
            # only replicas at that predecessor and count replicas already
            # at the exact pending head.
            external_head=None
        if external_head is not None:
            if type(external_head) is not str or len(external_head)!=64:
                return "INVALID_EXTERNAL_ANCHOR_STATE"
            if external_head==local_head:
                return "ALREADY_CURRENT"
            if external_head!=expected_previous_head:
                return "EXTERNAL_PREDECESSOR_MISMATCH"
        if local_head==expected_previous_head:
            return "ALREADY_CURRENT" if external_head==expected_previous_head else "EXTERNAL_PREDECESSOR_MISMATCH"
        pending=[event for event in events
            if event["previous_event_sha256"]==expected_previous_head]
        if len(pending)!=1 or not events or pending[0]!=events[-1]:
            return "EXPECTED_PREDECESSOR_MISMATCH"
        try:
            accepted=head_anchor.compare_and_set(expected_previous_head,local_head)
        except Exception:
            accepted=False
        if not accepted:
            # The remote CAS may have succeeded while its response was lost.
            # Re-read before reporting failure; never create a second event.
            try:
                if head_anchor.read_head()==local_head:
                    return "ALREADY_CURRENT"
            except Exception:
                pass
            return "ANCHOR_RECONCILIATION_FAILED"
        return "RECONCILED"
    except (sqlite3.Error,OSError,ValueError,TypeError,KeyError,AttributeError,
            InvalidSignature,OverflowError):
        return "RECONCILIATION_ERROR"
