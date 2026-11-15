"""Quorum-authorized monotonic registry for recovery-anchor tracked targets."""
import hashlib,json,os,sqlite3,stat
from signed_receipt import canonical
from threshold_recovery import (RecoveryAuthoritySigner,make_approval_bundle,
    verify_approval_bundle,policy_digest,validate_policy)

SCHEMA="AML-SEF2-RECOVERY-TARGET-CHANGE-V1"
GENESIS="0"*64

def _hex64(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def validate_targets(targets):
    return (type(targets) in (list,tuple) and len(targets)>0
        and all(type(target) is str and target for target in targets)
        and list(targets)==sorted(set(targets)))

def targets_digest(targets):
    if not validate_targets(targets): raise ValueError("invalid tracked target set")
    return hashlib.sha256(canonical(list(targets))).hexdigest()

def make_target_change(current_targets,next_generation,previous_head,add,remove,policy,signers):
    if not validate_policy(policy) or not validate_targets(current_targets):
        raise ValueError("invalid target registry inputs")
    if type(next_generation) is not int or next_generation<2 or not _hex64(previous_head):
        raise ValueError("invalid target registry generation/head")
    if (type(add) not in (list,tuple) or type(remove) not in (list,tuple)
        or list(add)!=sorted(set(add)) or list(remove)!=sorted(set(remove))
        or any(type(x) is not str or not x for x in list(add)+list(remove))
        or set(add)&set(remove)):
        raise ValueError("invalid target delta")
    current=set(current_targets)
    if set(remove)-current or set(add)&current:
        raise ValueError("target delta does not apply to current set")
    result=sorted((current-set(remove))|set(add))
    if not result:
        raise ValueError("tracked target set cannot become empty")
    if (type(signers) is not dict or any(not isinstance(s,RecoveryAuthoritySigner)
        for s in signers.values())):
        raise ValueError("durable recovery authority signers required")
    payload={"schema":SCHEMA,"generation":next_generation,
        "previous_head_sha256":previous_head,
        "previous_targets_sha256":targets_digest(current_targets),
        "policy_sha256":policy_digest(policy),"add":list(add),"remove":list(remove),
        "next_targets":result}
    return {"payload":payload,"approval":make_approval_bundle(payload,policy,signers)}

def verify_target_change(change,current_targets,expected_generation,expected_previous_head,policy):
    try:
        if not validate_policy(policy) or not validate_targets(current_targets):
            return False
        if type(change) is not dict or set(change)!={"payload","approval"}:
            return False
        p=change["payload"]
        if type(p) is not dict or set(p)!={"schema","generation","previous_head_sha256",
            "previous_targets_sha256","policy_sha256","add","remove","next_targets"}:
            return False
        if (p["schema"]!=SCHEMA or p["generation"]!=expected_generation
            or p["previous_head_sha256"]!=expected_previous_head
            or p["previous_targets_sha256"]!=targets_digest(current_targets)
            or p["policy_sha256"]!=policy_digest(policy)
            or not validate_targets(p["next_targets"])):
            return False
        add=p["add"]; remove=p["remove"]
        if (type(add) is not list or type(remove) is not list or add!=sorted(set(add))
            or remove!=sorted(set(remove)) or set(add)&set(remove)):
            return False
        current=set(current_targets)
        if set(remove)-current or set(add)&current:
            return False
        if p["next_targets"]!=sorted((current-set(remove))|set(add)):
            return False
        return verify_approval_bundle(p,change["approval"],policy)
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False

class RecoveryTargetRegistry:
    def __init__(self,path):
        self.path=str(path)
        flags=os.O_CREAT|os.O_EXCL|os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
        try:
            fd=os.open(self.path,flags,0o600); os.close(fd)
        except FileExistsError:
            info=os.stat(self.path,follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("target registry must be a private regular file")
        os.chmod(self.path,0o600,follow_symlinks=False)
        with sqlite3.connect(self.path) as con:
            con.execute("PRAGMA journal_mode=DELETE"); con.execute("PRAGMA synchronous=FULL")
            con.execute("""CREATE TABLE IF NOT EXISTS target_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,
                targets_json TEXT NOT NULL,head_sha256 TEXT NOT NULL)""")
            con.execute("""CREATE TABLE IF NOT EXISTS target_events (
                generation INTEGER PRIMARY KEY,change_json TEXT NOT NULL,
                previous_head_sha256 TEXT NOT NULL,event_sha256 TEXT NOT NULL UNIQUE)""")
    def initialize(self,targets):
        if not validate_targets(targets): raise ValueError("invalid initial targets")
        raw=canonical(list(targets)).decode()
        with sqlite3.connect(self.path,timeout=10) as con:
            con.execute("BEGIN IMMEDIATE")
            row=con.execute("SELECT generation,targets_json,head_sha256 FROM target_state WHERE singleton=1").fetchone()
            if row:
                if row==(1,raw,GENESIS): return "ALREADY_INITIALIZED"
                raise ValueError("target registry already initialized differently")
            con.execute("INSERT INTO target_state VALUES (1,?,?,?)",(1,raw,GENESIS))
        return "INITIALIZED"
    def state(self):
        with sqlite3.connect(self.path) as con:
            row=con.execute("SELECT generation,targets_json,head_sha256 FROM target_state WHERE singleton=1").fetchone()
            if row is None: raise ValueError("uninitialized target registry")
            generation,raw,head=row; targets=json.loads(raw)
            if not validate_targets(targets) or not _hex64(head): raise ValueError("corrupt target registry")
            return {"generation":generation,"targets":targets,"head_sha256":head}
    def apply(self,change,policy):
        try:
            with sqlite3.connect(self.path,timeout=10) as con:
                con.execute("PRAGMA synchronous=FULL"); con.execute("BEGIN IMMEDIATE")
                row=con.execute("SELECT generation,targets_json,head_sha256 FROM target_state WHERE singleton=1").fetchone()
                if row is None: return "UNINITIALIZED"
                generation,raw,head=row; targets=json.loads(raw)
                if not verify_target_change(change,targets,generation+1,head,policy):
                    return "INVALID_CHANGE"
                event={"generation":generation+1,"change_sha256":hashlib.sha256(canonical(change)).hexdigest(),
                    "previous_head_sha256":head}
                event_hash=hashlib.sha256(canonical(event)).hexdigest()
                con.execute("INSERT INTO target_events VALUES (?,?,?,?)",
                    (generation+1,canonical(change).decode(),head,event_hash))
                con.execute("UPDATE target_state SET generation=?,targets_json=?,head_sha256=? WHERE singleton=1",
                    (generation+1,canonical(change["payload"]["next_targets"]).decode(),event_hash))
            return "UPDATED"
        except (sqlite3.Error,ValueError,TypeError,KeyError):
            return "STORE_OR_STATE_ERROR"
