"""External evaluator-pinned checkpoint anchor for snapshot rollback detection.

The anchor file MUST live outside the witness database's rollback domain.
An independent evaluator pins its SHA256 through a separate trusted channel.
"""
import hashlib
import json
import pathlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from checkpoint_council import DOMAIN,valid_checkpoint
from signed_receipt import canonical
from signed_history import digest
from durable_checkpoint_witness import DurableWitness

def issue_anchor(store):
    envelope=store.latest()
    if envelope is None:
        raise ValueError("no published witness checkpoint")
    body={"schema":"AML-SEF2-EXTERNAL-WITNESS-ANCHOR-V1",
        "witness_id":store.name,"witness_public_hex":store.private.public_key().public_bytes_raw().hex(),
        "checkpoint":envelope["payload"]["checkpoint"],"witness_envelope":envelope}
    return body

def anchor_pin(anchor):
    return hashlib.sha256(canonical(anchor)).hexdigest()

def verify_anchor(db_path,witness_id,witness_public_hex,anchor_path,expected_anchor_pin):
    try:
        anchor=json.loads(pathlib.Path(anchor_path).read_text(),
            object_pairs_hook=lambda pairs: unique(pairs))
        if (type(expected_anchor_pin) is not str or len(expected_anchor_pin)!=64
            or anchor_pin(anchor)!=expected_anchor_pin
            or type(anchor) is not dict
            or set(anchor)!={"schema","witness_id","witness_public_hex","checkpoint","witness_envelope"}
            or anchor["schema"]!="AML-SEF2-EXTERNAL-WITNESS-ANCHOR-V1"
            or anchor["witness_id"]!=witness_id
            or anchor["witness_public_hex"]!=witness_public_hex
            or not valid_checkpoint(anchor["checkpoint"])):
            return False
        key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(witness_public_hex))
        envelope=anchor["witness_envelope"]
        if (type(envelope) is not dict or set(envelope)!={"payload","signature"}
            or envelope["payload"]!={"version":1,"witness_id":witness_id,"checkpoint":anchor["checkpoint"]}):
            return False
        key.verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(envelope["payload"]))
        # Do not generate a new signing key or mutate the witness database.
        import sqlite3
        with sqlite3.connect("file:"+pathlib.Path(db_path).resolve().as_posix()+"?mode=ro",uri=True) as con:
            retained=con.execute("SELECT epoch,head FROM retained WHERE slot=1").fetchone()
            row=con.execute("SELECT epoch,head,payload,envelope FROM checkpoints ORDER BY epoch DESC LIMIT 1").fetchone()
        if not retained or not row:
            return False
        epoch,head,payload_raw,envelope_raw=row
        local=json.loads(envelope_raw)
        checkpoint=json.loads(payload_raw)
        if (epoch!=retained[0] or head!=retained[1] or checkpoint!=local["payload"]["checkpoint"]
            or checkpoint["epoch"]!=epoch or checkpoint["head_hash"]!=head):
            return False
        key.verify(bytes.fromhex(local["signature"]),DOMAIN+canonical(local["payload"]))
        # An independently pinned higher epoch cannot be silently rolled back.
        # Require exact head agreement, not merely epoch >= pinned epoch.
        return checkpoint==anchor["checkpoint"] and local==envelope
    except (OSError,ValueError,TypeError,KeyError,InvalidSignature,OverflowError):
        return False

def unique(pairs):
    obj={}
    for key,value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key]=value
    return obj
