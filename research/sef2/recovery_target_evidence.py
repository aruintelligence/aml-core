"""Export and independently verify quorum-authorized tracked-target registry history."""
import hashlib,json,sqlite3
from signed_receipt import canonical
from recovery_target_registry import (GENESIS,validate_targets,targets_digest,
    verify_target_change)

SCHEMA="AML-SEF2-RECOVERY-TARGET-HISTORY-V1"

def _strict(raw):
    def hook(pairs):
        out={}
        for key,value in pairs:
            if key in out: raise ValueError("duplicate JSON key")
            out[key]=value
        return out
    value=json.loads(raw,object_pairs_hook=hook)
    if canonical(value).decode()!=raw: raise ValueError("noncanonical target-registry JSON")
    return value

def _hex64(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def export_target_registry_history(database_path,initial_targets):
    if not validate_targets(initial_targets): raise ValueError("invalid initial targets")
    with sqlite3.connect(database_path) as con:
        state=con.execute("SELECT generation,targets_json,head_sha256 FROM target_state WHERE singleton=1").fetchone()
        if state is None: raise ValueError("uninitialized target registry")
        rows=con.execute("""SELECT generation,change_json,previous_head_sha256,event_sha256
            FROM target_events ORDER BY generation""").fetchall()
    generation,targets_raw,head=state
    events=[{"generation":g,"change":_strict(raw),
        "previous_head_sha256":previous,"event_sha256":event}
        for g,raw,previous,event in rows]
    return {"schema":SCHEMA,"initial_targets":list(initial_targets),
        "generation":generation,"current_targets":_strict(targets_raw),
        "events":events,"head_sha256":head}

def verify_target_registry_history(bundle,policy,expected_head_sha256=None):
    try:
        required={"schema","initial_targets","generation","current_targets","events","head_sha256"}
        if type(bundle) is not dict or set(bundle)!=required or bundle["schema"]!=SCHEMA:
            return False
        initial=bundle["initial_targets"]
        if not validate_targets(initial) or not validate_targets(bundle["current_targets"]):
            return False
        if type(bundle["generation"]) is not int or bundle["generation"]<1 or not _hex64(bundle["head_sha256"]):
            return False
        current=list(initial); previous=GENESIS; expected_generation=2
        for event in bundle["events"]:
            if type(event) is not dict or set(event)!={"generation","change","previous_head_sha256","event_sha256"}:
                return False
            if (event["generation"]!=expected_generation or event["previous_head_sha256"]!=previous
                or not _hex64(event["event_sha256"])):
                return False
            change=event["change"]
            if not verify_target_change(change,current,expected_generation,previous,policy):
                return False
            body={"generation":expected_generation,
                "change_sha256":hashlib.sha256(canonical(change)).hexdigest(),
                "previous_head_sha256":previous}
            calculated=hashlib.sha256(canonical(body)).hexdigest()
            if calculated!=event["event_sha256"]:
                return False
            current=change["payload"]["next_targets"]; previous=calculated
            expected_generation+=1
        if bundle["generation"]!=expected_generation-1:
            return False
        if bundle["current_targets"]!=current or bundle["head_sha256"]!=previous:
            return False
        if expected_head_sha256 is not None and bundle["head_sha256"]!=expected_head_sha256:
            return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
