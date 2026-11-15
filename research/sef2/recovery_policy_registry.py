"""Durable policy registry for dual-consent recovery-council rotation.

The registry serializes installation and stores a verifiable policy-transition
history. Its SQLite state remains rollbackable; an independent anchor quorum
must pin the current generation/head outside this registry's admin domain.
"""
import hashlib,json,os,stat,sqlite3
from signed_receipt import canonical
from threshold_recovery import validate_policy,policy_digest
from recovery_policy_rotation import verify_policy_rotation

GENESIS="0"*64
STATE_SCHEMA="AML-SEF2-RECOVERY-POLICY-REGISTRY-V1"

def _strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise ValueError("duplicate JSON key")
            result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs)
    if canonical(value).decode("utf-8")!=raw:
        raise ValueError("noncanonical policy registry JSON")
    return value

def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

class RecoveryPolicyRegistry:
    def __init__(self,database_path):
        self.database_path=str(database_path)
        flags=os.O_CREAT|os.O_EXCL|os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
        try:
            fd=os.open(self.database_path,flags,0o600); os.close(fd)
        except FileExistsError:
            info=os.stat(self.database_path,follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("recovery policy registry must be a private regular file")
        os.chmod(self.database_path,0o600,follow_symlinks=False)
        with sqlite3.connect(self.database_path,timeout=10) as con:
            con.execute("PRAGMA journal_mode=DELETE"); con.execute("PRAGMA synchronous=FULL")
            con.execute("""CREATE TABLE IF NOT EXISTS recovery_policy_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema TEXT NOT NULL, generation INTEGER NOT NULL,
                genesis_policy_json TEXT NOT NULL, genesis_policy_sha256 TEXT NOT NULL,
                current_policy_json TEXT NOT NULL, current_policy_sha256 TEXT NOT NULL,
                head_sha256 TEXT NOT NULL)""")
            con.execute("""CREATE TABLE IF NOT EXISTS recovery_policy_events (
                generation INTEGER PRIMARY KEY,
                previous_policy_json TEXT NOT NULL, next_policy_json TEXT NOT NULL,
                rotation_json TEXT NOT NULL, previous_event_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL UNIQUE)""")

    def initialize(self,policy):
        if not validate_policy(policy): raise ValueError("invalid initial recovery policy")
        raw=canonical(policy).decode("utf-8"); digest=policy_digest(policy)
        with sqlite3.connect(self.database_path,timeout=10) as con:
            con.execute("PRAGMA synchronous=FULL"); con.execute("BEGIN IMMEDIATE")
            row=con.execute("SELECT 1 FROM recovery_policy_state WHERE singleton=1").fetchone()
            if row:
                try:
                    existing=self._verified_state(con)
                except (ValueError,TypeError,KeyError,AttributeError):
                    raise ValueError("corrupt recovery policy registry cannot be reinitialized")
                if existing is not None and existing["policy_sha256"]==digest:
                    return "ALREADY_INITIALIZED"
                raise ValueError("recovery policy registry already initialized")
            con.execute("""INSERT INTO recovery_policy_state VALUES (1,?,?,?,?,?,?,?)""",
                (STATE_SCHEMA,1,raw,digest,raw,digest,GENESIS))
        return "INITIALIZED"

    def _verified_state(self,con):
        row=con.execute("""SELECT schema,generation,genesis_policy_json,genesis_policy_sha256,
            current_policy_json,current_policy_sha256,head_sha256
            FROM recovery_policy_state WHERE singleton=1""").fetchone()
        if row is None: return None
        schema,generation,genesis_raw,genesis_digest,current_raw,current_digest,head=row
        if (schema!=STATE_SCHEMA or type(generation) is not int or generation<1
            or type(head) is not str or len(head)!=64):
            raise ValueError("corrupt policy registry state")
        genesis=_strict_json(genesis_raw); current=_strict_json(current_raw)
        if (not validate_policy(genesis) or not validate_policy(current)
            or policy_digest(genesis)!=genesis_digest or policy_digest(current)!=current_digest):
            raise ValueError("corrupt policy registry state")
        previous_policy=genesis; previous_digest=genesis_digest; previous_event=GENESIS
        events=con.execute("""SELECT generation,previous_policy_json,next_policy_json,
            rotation_json,previous_event_sha256,event_sha256
            FROM recovery_policy_events ORDER BY generation""").fetchall()
        expected_generation=2
        for event_row in events:
            event_generation,previous_raw,next_raw,rotation_raw,previous_event_hash,event_hash=event_row
            old=_strict_json(previous_raw); new=_strict_json(next_raw); rotation=_strict_json(rotation_raw)
            if (event_generation!=expected_generation or previous_event_hash!=previous_event
                or policy_digest(old)!=previous_digest
                or not verify_policy_rotation(old,new,rotation,event_generation)):
                raise ValueError("corrupt policy registry history")
            event={"generation":event_generation,"previous_policy_sha256":previous_digest,
                "next_policy_sha256":policy_digest(new),"rotation_sha256":_digest(rotation),
                "previous_event_sha256":previous_event}
            calculated=_digest(event)
            if calculated!=event_hash: raise ValueError("corrupt policy registry history")
            previous_policy=new; previous_digest=policy_digest(new)
            previous_event=calculated; expected_generation+=1
        if (generation!=expected_generation-1 or current!=previous_policy
            or current_digest!=previous_digest or head!=previous_event):
            raise ValueError("corrupt policy registry state or history")
        return {"generation":generation,"policy":current,
            "policy_sha256":current_digest,"head_sha256":head}

    def state(self):
        try:
            uri="file:"+os.path.abspath(self.database_path)+"?mode=ro"
            with sqlite3.connect(uri,uri=True,timeout=10) as con:
                result=self._verified_state(con)
            if result is None: raise ValueError("recovery policy registry uninitialized")
            return result
        except (sqlite3.Error,ValueError,TypeError,KeyError):
            raise ValueError("corrupt or unavailable recovery policy registry state")

    def verify_history(self):
        try:
            uri="file:"+os.path.abspath(self.database_path)+"?mode=ro"
            with sqlite3.connect(uri,uri=True,timeout=10) as con:
                return self._verified_state(con) is not None
        except (sqlite3.Error,ValueError,TypeError,KeyError,AttributeError):
            return False

    def rotate(self,next_policy,rotation):
        if not validate_policy(next_policy): return "INVALID_ROTATION"
        try:
            with sqlite3.connect(self.database_path,timeout=10) as con:
                con.execute("PRAGMA synchronous=FULL"); con.execute("BEGIN IMMEDIATE")
                try:
                    state=self._verified_state(con)
                except (ValueError,TypeError,KeyError,AttributeError):
                    return "CORRUPT_STATE"
                if state is None: return "UNINITIALIZED"
                generation=state["generation"]+1
                current=state["policy"]
                if not verify_policy_rotation(current,next_policy,rotation,generation):
                    return "INVALID_ROTATION"
                previous_raw=canonical(current).decode("utf-8")
                next_raw=canonical(next_policy).decode("utf-8")
                rotation_raw=canonical(rotation).decode("utf-8")
                event={"generation":generation,"previous_policy_sha256":state["policy_sha256"],
                    "next_policy_sha256":policy_digest(next_policy),
                    "rotation_sha256":_digest(rotation),"previous_event_sha256":state["head_sha256"]}
                event_hash=_digest(event)
                con.execute("""INSERT INTO recovery_policy_events VALUES (?,?,?,?,?,?)""",
                    (generation,previous_raw,next_raw,rotation_raw,state["head_sha256"],event_hash))
                con.execute("""UPDATE recovery_policy_state SET generation=?,current_policy_json=?,
                    current_policy_sha256=?,head_sha256=? WHERE singleton=1""",
                    (generation,next_raw,policy_digest(next_policy),event_hash))
            return "ROTATED"
        except sqlite3.Error:
            return "STORE_OR_STATE_ERROR"
