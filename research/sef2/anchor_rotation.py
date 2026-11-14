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
