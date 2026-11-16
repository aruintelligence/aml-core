"""Crash-consistent anchor rotation; caller must durably pin returned digest independently.

Atomic file replacement prevents torn anchor documents. A crash after replacement
but before external pin publication fails closed until the evaluator reconciles.
The evaluator's trusted old pin is mandatory; this is not an anti-rollback store.
"""
import json
import os
import pathlib
import tempfile
from external_witness_anchor import issue_anchor,anchor_pin,unique
from checkpoint_council import DOMAIN
from signed_receipt import canonical
from checkpoint_council import valid_checkpoint

def rotate_anchor(store,anchor_path,trusted_old_pin):
    path=pathlib.Path(anchor_path)
    if type(trusted_old_pin) is not str or len(trusted_old_pin)!=64:
        raise ValueError("trusted old pin required")
    pub=store.private.public_key().public_bytes_raw().hex()
    old=json.loads(path.read_text(),object_pairs_hook=unique)
    if (type(old) is not dict or anchor_pin(old)!=trusted_old_pin
        or set(old)!={"schema","witness_id","witness_public_hex","checkpoint","witness_envelope"}
        or old["schema"]!="AML-SEF2-EXTERNAL-WITNESS-ANCHOR-V1"
        or old["witness_id"]!=store.name or old["witness_public_hex"]!=pub
        or not valid_checkpoint(old["checkpoint"])):
        raise ValueError("old anchor pin or identity invalid")
    envelope=old["witness_envelope"]
    payload={"version":1,"witness_id":store.name,"checkpoint":old["checkpoint"]}
    if type(envelope) is not dict or set(envelope)!={"payload","signature"} or envelope["payload"]!=payload:
        raise ValueError("old anchor envelope invalid")
    store.private.public_key().verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(payload))
    new=issue_anchor(store)
    before=old["checkpoint"]
    after=new["checkpoint"]
    if not valid_checkpoint(after) or after["epoch"]<=before["epoch"]:
        raise ValueError("rotation requires strictly newer epoch")
    # Recheck the old pin immediately before replacement; concurrent rotations
    # require an external single-writer lock (not provided by this prototype).
    if anchor_pin(json.loads(path.read_text(),object_pairs_hook=unique))!=trusted_old_pin:
        raise ValueError("anchor changed during rotation")
    fd,tmp=tempfile.mkstemp(prefix=".anchor-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w") as out:
            json.dump(new,out,sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp,path)
        directory_fd=os.open(str(path.parent),os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return anchor_pin(new)

def prepare_rotation(store,anchor_path,trusted_old_pin,candidate_path):
    """Stage signed successor without replacing active anchor or its old pin."""
    active=pathlib.Path(anchor_path)
    candidate=pathlib.Path(candidate_path)
    if candidate==active or candidate.exists():
        raise ValueError("candidate must be distinct and absent")
    old=json.loads(active.read_text(),object_pairs_hook=unique)
    if type(old) is not dict or type(trusted_old_pin) is not str or anchor_pin(old)!=trusted_old_pin:
        raise ValueError("untrusted predecessor")
    new=issue_anchor(store)
    if (type(old) is not dict or old.get("witness_id")!=store.name
        or old.get("witness_public_hex")!=store.private.public_key().public_bytes_raw().hex()
        or not valid_checkpoint(old.get("checkpoint"))
        or new["checkpoint"]["epoch"]<=old["checkpoint"]["epoch"]):
        raise ValueError("invalid rotation progression")
    # Reuse signature and predecessor validation from the rotation path by
    # checking the historical signed envelope without touching active state.
    envelope=old["witness_envelope"]
    payload={"version":1,"witness_id":store.name,"checkpoint":old["checkpoint"]}
    if (type(envelope) is not dict or set(envelope)!={"payload","signature"}
        or envelope.get("payload")!=payload):
        raise ValueError("invalid predecessor envelope")
    store.private.public_key().verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(payload))
    with candidate.open("x") as out:
        json.dump(new,out,sort_keys=True)
        out.flush()
        os.fsync(out.fileno())
    directory_fd=os.open(str(candidate.parent),os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return anchor_pin(new)

def activate_prepared_rotation(anchor_path,candidate_path,trusted_old_pin,approved_new_pin):
    """Activate only after independent evaluator has approved new pin.

    Requires an external single-writer lock and trusted durable pin publication.
    This helper never publishes the pin itself.
    """
    active=pathlib.Path(anchor_path)
    candidate=pathlib.Path(candidate_path)
    if active==candidate:
        raise ValueError("candidate must be distinct")
    old=json.loads(active.read_text(),object_pairs_hook=unique)
    new=json.loads(candidate.read_text(),object_pairs_hook=unique)
    if (type(trusted_old_pin) is not str or type(approved_new_pin) is not str
        or anchor_pin(old)!=trusted_old_pin or anchor_pin(new)!=approved_new_pin
        or type(new) is not dict or type(old) is not dict
        or set(new)!={"schema","witness_id","witness_public_hex","checkpoint","witness_envelope"}
        or set(old)!=set(new)
        or old["schema"]!="AML-SEF2-EXTERNAL-WITNESS-ANCHOR-V1"
        or new["witness_id"]!=old["witness_id"]
        or new["witness_public_hex"]!=old["witness_public_hex"]
        or new["schema"]!=old["schema"]
        or not valid_checkpoint(new["checkpoint"])
        or not valid_checkpoint(old["checkpoint"])
        or new["checkpoint"]["epoch"]<=old["checkpoint"]["epoch"]):
        raise ValueError("unapproved or inconsistent successor")
    payload={"version":1,"witness_id":new["witness_id"],"checkpoint":new["checkpoint"]}
    envelope=new["witness_envelope"]
    if (type(envelope) is not dict or set(envelope)!={"payload","signature"}
        or envelope.get("payload")!=payload):
        raise ValueError("invalid successor envelope")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(new["witness_public_hex"]))
    key.verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(payload))
    old_envelope=old["witness_envelope"]
    old_payload={"version":1,"witness_id":old["witness_id"],"checkpoint":old["checkpoint"]}
    if (type(old_envelope) is not dict or set(old_envelope)!={"payload","signature"}
        or old_envelope["payload"]!=old_payload):
        raise ValueError("invalid predecessor envelope")
    key.verify(bytes.fromhex(old_envelope["signature"]),DOMAIN+canonical(old_payload))
    os.replace(candidate,active)
    directory_fd=os.open(str(active.parent),os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return approved_new_pin
