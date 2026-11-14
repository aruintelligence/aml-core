"""Evaluator-coordinated recovery for staged witness anchor rotation.

The registry must be physically/adminstratively independent of witness storage.
Pending pins authorize only the exact staged successor; they do not make the
old or new anchor acceptable as a completed rotation until committed.
"""
import json
import pathlib
from anchor_rotation import prepare_rotation,activate_prepared_rotation
from external_witness_anchor import anchor_pin,unique,verify_anchor

def stage(store,anchor_path,candidate_path,registry):
    state=registry.state(store.name)
    if state["pending"] is not None:
        raise ValueError("rotation already pending")
    new_pin=prepare_rotation(store,anchor_path,state["active"],candidate_path)
    registry.prepare(store.name,state["active"],new_pin)
    return new_pin

def recover(store,anchor_path,candidate_path,registry):
    state=registry.state(store.name)
    active=state["active"]
    pending=state["pending"]
    if pending is None:
        return "ACTIVE" if verify_anchor(store.path,store.name,
            store.private.public_key().public_bytes_raw().hex(),anchor_path,active) else "FAIL_CLOSED"
    try:
        path=pathlib.Path(anchor_path)
        candidate=pathlib.Path(candidate_path)
        current=json.loads(path.read_text(),object_pairs_hook=unique)
        current_pin=anchor_pin(current)
        if current_pin==active:
            if not candidate.is_file():
                return "FAIL_CLOSED"
            activate_prepared_rotation(path,candidate,active,pending)
        elif current_pin==pending:
            # Crash after atomic replacement but before registry commit.
            if not verify_anchor(store.path,store.name,
                store.private.public_key().public_bytes_raw().hex(),path,pending):
                return "FAIL_CLOSED"
        else:
            return "FAIL_CLOSED"
        if not verify_anchor(store.path,store.name,
            store.private.public_key().public_bytes_raw().hex(),path,pending):
            return "FAIL_CLOSED"
        registry.commit(store.name,active,pending)
        return "RECOVERED"
    except (OSError,ValueError,TypeError,KeyError):
        return "FAIL_CLOSED"
