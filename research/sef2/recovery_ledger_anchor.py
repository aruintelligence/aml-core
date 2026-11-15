"""Independent verifier for an externally pinned recovery-authority ledger checkpoint.

The expected checkpoint digest must be retained outside the signer's storage
and administrative rollback domain. This verifier detects ledger rollback or
tampering relative to that pin; it does not itself distribute or update pins.
"""
import hashlib,sqlite3,pathlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from threshold_recovery import DOMAIN

CHECKPOINT_SCHEMA="AML-SEF2-RECOVERY-AUTHORITY-LEDGER-CHECKPOINT-V1"
LEDGER_DOMAIN=b"AML-SEF2-RECOVERY-AUTHORITY-LEDGER-V1\x00"

def ledger_checkpoint(database,authority_id,authority_public_hex):
    if (type(authority_public_hex) is not str or len(authority_public_hex)!=64
        or any(c not in "0123456789abcdef" for c in authority_public_hex)
        or type(authority_id) is not str or not authority_id):
        raise ValueError("invalid authority identity")
    raw=bytes.fromhex(authority_public_hex)
    if len(raw)!=32:
        raise ValueError("invalid authority identity")
    uri="file:"+pathlib.Path(database).resolve().as_posix()+"?mode=ro"
    with sqlite3.connect(uri,uri=True) as con:
        rows=con.execute("""SELECT policy_id,witness_id,generation,policy_sha256,
            previous_state_sha256,payload_sha256,signature
            FROM recovery_approval_ledger_v4 WHERE authority_id=?
            ORDER BY policy_id,witness_id,generation""",(authority_id,)).fetchall()
    records=[{"policy_id":r[0],"witness_id":r[1],"generation":r[2],
        "policy_sha256":r[3],"previous_state_sha256":r[4],
        "payload_sha256":r[5],"signature":r[6]} for r in rows]
    head=hashlib.sha256(LEDGER_DOMAIN+canonical(records)).hexdigest()
    return {"schema":CHECKPOINT_SCHEMA,"authority_id":authority_id,
        "authority_key_sha256":hashlib.sha256(raw).hexdigest(),
        "sequence":len(records),"head_hash":head}

def checkpoint_pin(checkpoint):
    return hashlib.sha256(canonical(checkpoint)).hexdigest()

def verify_ledger_checkpoint(database,authority_public_hex,expected_checkpoint,expected_pin):
    try:
        if (type(authority_public_hex) is not str or len(authority_public_hex)!=64
            or any(c not in "0123456789abcdef" for c in authority_public_hex)
            or type(expected_pin) is not str or len(expected_pin)!=64
            or any(c not in "0123456789abcdef" for c in expected_pin)):
            return False
        raw=bytes.fromhex(authority_public_hex)
        if len(raw)!=32 or type(expected_checkpoint) is not dict:
            return False
        if set(expected_checkpoint)!={"schema","authority_id","authority_key_sha256","sequence","head_hash"}:
            return False
        if (expected_checkpoint["schema"]!=CHECKPOINT_SCHEMA
            or type(expected_checkpoint["authority_id"]) is not str or not expected_checkpoint["authority_id"]
            or expected_checkpoint["authority_key_sha256"]!=hashlib.sha256(raw).hexdigest()
            or type(expected_checkpoint["sequence"]) is not int or expected_checkpoint["sequence"]<0
            or type(expected_checkpoint["head_hash"]) is not str or len(expected_checkpoint["head_hash"])!=64
            or any(c not in "0123456789abcdef" for c in expected_checkpoint["head_hash"])
            or checkpoint_pin(expected_checkpoint)!=expected_pin):
            return False
        uri="file:"+pathlib.Path(database).resolve().as_posix()+"?mode=ro"
        with sqlite3.connect(uri,uri=True) as con:
            rows=con.execute("""SELECT policy_id,witness_id,generation,policy_sha256,
                previous_state_sha256,payload_sha256,signature
                FROM recovery_approval_ledger_v4 WHERE authority_id=?
                ORDER BY policy_id,witness_id,generation""",(expected_checkpoint["authority_id"],)).fetchall()
        records=[{"policy_id":r[0],"witness_id":r[1],"generation":r[2],
            "policy_sha256":r[3],"previous_state_sha256":r[4],
            "payload_sha256":r[5],"signature":r[6]} for r in rows]
        key=Ed25519PublicKey.from_public_bytes(raw)
        for row in records:
            for field in ("policy_sha256","previous_state_sha256","payload_sha256"):
                value=row[field]
                if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                    return False
            signature=bytes.fromhex(row["signature"])
            if len(signature)!=64: return False
            key.verify(signature,DOMAIN+canonical({"policy_sha256":row["policy_sha256"],
                "payload_sha256":row["payload_sha256"]}))
        head=hashlib.sha256(LEDGER_DOMAIN+canonical(records)).hexdigest()
        actual={"schema":CHECKPOINT_SCHEMA,"authority_id":expected_checkpoint["authority_id"],
            "authority_key_sha256":hashlib.sha256(raw).hexdigest(),
            "sequence":len(records),"head_hash":head}
        return actual==expected_checkpoint
    except (OSError,sqlite3.Error,ValueError,TypeError,KeyError,InvalidSignature,OverflowError):
        return False

EVENT_CHECKPOINT_SCHEMA="AML-SEF2-RECOVERY-AUTHORITY-EVENT-CHECKPOINT-V1"

def event_chain_checkpoint(database,authority_id,authority_public_hex):
    """Return a deterministic event-chain head for one authority."""
    if (type(authority_public_hex) is not str or len(authority_public_hex)!=64
        or any(c not in "0123456789abcdef" for c in authority_public_hex)
        or type(authority_id) is not str or not authority_id):
        raise ValueError("invalid authority identity")
    raw=bytes.fromhex(authority_public_hex)
    if len(raw)!=32: raise ValueError("invalid authority key")
    uri="file:"+pathlib.Path(database).resolve().as_posix()+"?mode=ro"
    with sqlite3.connect(uri,uri=True) as con:
        rows=con.execute("""SELECT sequence,previous_event_sha256,policy_id,authority_id,
            witness_id,generation,policy_sha256,previous_state_sha256,payload_sha256,
            signature,event_sha256 FROM recovery_approval_events
            WHERE authority_id=? ORDER BY sequence""",(authority_id,)).fetchall()
    head=rows[-1][10] if rows else "0"*64
    return {"schema":EVENT_CHECKPOINT_SCHEMA,"authority_id":authority_id,
        "authority_key_sha256":hashlib.sha256(raw).hexdigest(),
        "sequence":len(rows),"head_hash":head}

def verify_event_chain(database,authority_public_hex,expected_checkpoint,expected_pin):
    """Verify sequence continuity, hash links, signatures and an external pin."""
    try:
        if (type(authority_public_hex) is not str or len(authority_public_hex)!=64
            or any(c not in "0123456789abcdef" for c in authority_public_hex)
            or type(expected_pin) is not str or len(expected_pin)!=64
            or any(c not in "0123456789abcdef" for c in expected_pin)):
            return False
        raw=bytes.fromhex(authority_public_hex)
        if len(raw)!=32 or type(expected_checkpoint) is not dict:
            return False
        if set(expected_checkpoint)!={"schema","authority_id","authority_key_sha256","sequence","head_hash"}:
            return False
        if (expected_checkpoint["schema"]!=EVENT_CHECKPOINT_SCHEMA
            or expected_checkpoint["authority_key_sha256"]!=hashlib.sha256(raw).hexdigest()
            or type(expected_checkpoint["authority_id"]) is not str
            or type(expected_checkpoint["sequence"]) is not int or expected_checkpoint["sequence"]<0
            or type(expected_checkpoint["head_hash"]) is not str
            or checkpoint_pin(expected_checkpoint)!=expected_pin):
            return False
        uri="file:"+pathlib.Path(database).resolve().as_posix()+"?mode=ro"
        with sqlite3.connect(uri,uri=True) as con:
            rows=con.execute("""SELECT sequence,previous_event_sha256,policy_id,authority_id,
                witness_id,generation,policy_sha256,previous_state_sha256,payload_sha256,
                signature,event_sha256 FROM recovery_approval_events
                WHERE authority_id=? ORDER BY sequence""",(expected_checkpoint["authority_id"],)).fetchall()
        key=Ed25519PublicKey.from_public_bytes(raw)
        previous="0"*64
        seen=set()
        for index,row in enumerate(rows,1):
            sequence,prev,policy_id,aid,witness,generation,pd,parent,digest,sig,event_hash=row
            if sequence!=index or prev!=previous or aid!=expected_checkpoint["authority_id"]:
                return False
            scope=(aid,witness,generation)
            if scope in seen: return False
            seen.add(scope)
            event={"sequence":sequence,"previous_event_sha256":prev,"policy_id":policy_id,
                "authority_id":aid,"witness_id":witness,"generation":generation,
                "policy_sha256":pd,"previous_state_sha256":parent,
                "payload_sha256":digest,"signature":sig}
            calculated=hashlib.sha256(canonical(event)).hexdigest()
            if calculated!=event_hash: return False
            for value in (pd,parent,digest):
                if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                    return False
            signature=bytes.fromhex(sig)
            if len(signature)!=64: return False
            key.verify(signature,DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest}))
            previous=event_hash
        actual={"schema":EVENT_CHECKPOINT_SCHEMA,
            "authority_id":expected_checkpoint["authority_id"],
            "authority_key_sha256":hashlib.sha256(raw).hexdigest(),
            "sequence":len(rows),"head_hash":previous}
        return actual==expected_checkpoint
    except (OSError,sqlite3.Error,ValueError,TypeError,KeyError,InvalidSignature,OverflowError):
        return False
