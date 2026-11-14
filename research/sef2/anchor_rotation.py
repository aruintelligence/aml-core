"""Crash-consistent anchor rotation; caller must durably pin returned digest independently.

Atomic file replacement prevents torn anchor documents. A crash after replacement
but before external pin publication fails closed until the evaluator reconciles.
The evaluator's trusted old pin is mandatory; this is not an anti-rollback store.
"""
import json
import os
import pathlib
import tempfile
from external_witness_anchor import issue_anchor,anchor_pin,verify_anchor,unique
from checkpoint_council import valid_checkpoint

def rotate_anchor(store,anchor_path,trusted_old_pin):
    path=pathlib.Path(anchor_path)
    if type(trusted_old_pin) is not str or len(trusted_old_pin)!=64:
        raise ValueError("trusted old pin required")
    pub=store.private.public_key().public_bytes_raw().hex()
    if not verify_anchor(store.path,store.name,pub,path,trusted_old_pin):
        raise ValueError("current anchor is not independently pinned")
    old=json.loads(path.read_text(),object_pairs_hook=unique)
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
