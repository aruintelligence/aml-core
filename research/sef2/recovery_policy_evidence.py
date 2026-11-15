"""Export and independently verify recovery-policy registry history."""
import hashlib,json,sqlite3
from signed_receipt import canonical
from threshold_recovery import policy_digest,validate_policy
from recovery_policy_rotation import verify_policy_rotation

SCHEMA="AML-SEF2-RECOVERY-POLICY-HISTORY-V1"
GENESIS="0"*64

def _strict(raw):
    def hook(pairs):
        out={}
        for key,value in pairs:
            if key in out: raise ValueError("duplicate JSON key")
            out[key]=value
        return out
    value=json.loads(raw,object_pairs_hook=hook)
    if canonical(value).decode()!=raw: raise ValueError("noncanonical JSON")
    return value

def _digest(value): return hashlib.sha256(canonical(value)).hexdigest()

def export_policy_registry_history(database_path):
    with sqlite3.connect(database_path) as con:
        state=con.execute("""SELECT schema,generation,genesis_policy_json,genesis_policy_sha256,
            current_policy_json,current_policy_sha256,head_sha256
            FROM recovery_policy_state WHERE singleton=1""").fetchone()
        if state is None: raise ValueError("uninitialized policy registry")
        rows=con.execute("""SELECT generation,previous_policy_json,next_policy_json,
            rotation_json,previous_event_sha256,event_sha256
            FROM recovery_policy_events ORDER BY generation""").fetchall()
    schema,generation,genesis_raw,genesis_sha,current_raw,current_sha,head=state
    events=[{"generation":g,"previous_policy":_strict(old),"next_policy":_strict(new),
        "rotation":_strict(rotation),"previous_event_sha256":prev,"event_sha256":event}
        for g,old,new,rotation,prev,event in rows]
    return {"schema":SCHEMA,"registry_schema":schema,"generation":generation,
        "genesis_policy":_strict(genesis_raw),"genesis_policy_sha256":genesis_sha,
        "current_policy":_strict(current_raw),"current_policy_sha256":current_sha,
        "events":events,"head_sha256":head}

def verify_policy_registry_history(bundle,expected_head_sha256=None):
    try:
        required={"schema","registry_schema","generation","genesis_policy","genesis_policy_sha256",
            "current_policy","current_policy_sha256","events","head_sha256"}
        if type(bundle) is not dict or set(bundle)!=required or bundle["schema"]!=SCHEMA:
            return False
        if type(bundle["generation"]) is not int or bundle["generation"]<1:
            return False
        if not validate_policy(bundle["genesis_policy"]) or not validate_policy(bundle["current_policy"]):
            return False
        if bundle["genesis_policy_sha256"]!=policy_digest(bundle["genesis_policy"]):
            return False
        if bundle["current_policy_sha256"]!=policy_digest(bundle["current_policy"]):
            return False
        if type(bundle["events"]) is not list:
            return False
        previous_policy=bundle["genesis_policy"]; previous_event=GENESIS
        expected_generation=2
        for event in bundle["events"]:
            if type(event) is not dict or set(event)!={"generation","previous_policy","next_policy",
                "rotation","previous_event_sha256","event_sha256"}:
                return False
            if event["generation"]!=expected_generation or event["previous_policy"]!=previous_policy:
                return False
            if event["previous_event_sha256"]!=previous_event:
                return False
            if not verify_policy_rotation(previous_policy,event["next_policy"],event["rotation"],expected_generation):
                return False
            body={"generation":expected_generation,
                "previous_policy_sha256":policy_digest(previous_policy),
                "next_policy_sha256":policy_digest(event["next_policy"]),
                "rotation_sha256":_digest(event["rotation"]),
                "previous_event_sha256":previous_event}
            calculated=_digest(body)
            if event["event_sha256"]!=calculated:
                return False
            previous_policy=event["next_policy"]; previous_event=calculated; expected_generation+=1
        if bundle["generation"]!=expected_generation-1:
            return False
        if bundle["current_policy"]!=previous_policy or bundle["head_sha256"]!=previous_event:
            return False
        if expected_head_sha256 is not None and bundle["head_sha256"]!=expected_head_sha256:
            return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
