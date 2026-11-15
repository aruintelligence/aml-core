"""Verifier-side monotonic recovery policy activation registry.

A verifier accepts a policy cutover only with an independently verifiable
cutover certificate. The local activation history is hash-chained and may be
pinned to an independent compare-and-set head anchor. If the registry is rolled
back while that anchor remains current, state verification fails closed.
"""
import hashlib,json,os,sqlite3,stat
from signed_receipt import canonical
from recovery_cutover import verify_independent_cutover_certificate

SCHEMA="AML-SEF2-RECOVERY-ACTIVATION-REGISTRY-V1"
GENESIS="0"*64

def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def _valid_digest(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

class RecoveryActivationRegistry:
    def __init__(self,path,head_anchor=None):
        self.path=str(path); self.head_anchor=head_anchor
        flags=os.O_CREAT|os.O_EXCL|os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
        try:
            fd=os.open(self.path,flags,0o600); os.close(fd)
        except FileExistsError:
            info=os.stat(self.path,follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("activation registry must be a private regular file")
        os.chmod(self.path,0o600,follow_symlinks=False)
        with sqlite3.connect(self.path) as con:
            con.execute("PRAGMA journal_mode=DELETE"); con.execute("PRAGMA synchronous=FULL")
            con.execute("""CREATE TABLE IF NOT EXISTS recovery_activation_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema TEXT NOT NULL,generation INTEGER NOT NULL,
                policy_sha256 TEXT NOT NULL,head_sha256 TEXT NOT NULL)""")
            con.execute("""CREATE TABLE IF NOT EXISTS recovery_activation_events (
                generation INTEGER PRIMARY KEY,previous_policy_sha256 TEXT NOT NULL,
                next_policy_sha256 TEXT NOT NULL,cutover_sha256 TEXT NOT NULL,
                previous_event_sha256 TEXT NOT NULL,event_sha256 TEXT NOT NULL UNIQUE,
                certificate_json TEXT NOT NULL,rotation_json TEXT NOT NULL)""")

    def initialize(self,policy_sha256,generation=1):
        if not _valid_digest(policy_sha256) or type(generation) is not int or generation<1:
            raise ValueError("invalid initial activation state")
        with sqlite3.connect(self.path,timeout=10) as con:
            con.execute("BEGIN IMMEDIATE")
            row=con.execute("SELECT schema,generation,policy_sha256,head_sha256 FROM recovery_activation_state WHERE singleton=1").fetchone()
            if row:
                if row==(SCHEMA,generation,policy_sha256,GENESIS): return "ALREADY_INITIALIZED"
                raise ValueError("activation registry already initialized differently")
            con.execute("INSERT INTO recovery_activation_state VALUES (1,?,?,?,?)",
                (SCHEMA,generation,policy_sha256,GENESIS))
        if self.head_anchor is not None:
            anchored=self.head_anchor.read_head()
            if anchored!=GENESIS:
                raise RuntimeError("activation anchor is not at genesis")
        return "INITIALIZED"

    def _verified_state(self,con):
        row=con.execute("SELECT schema,generation,policy_sha256,head_sha256 FROM recovery_activation_state WHERE singleton=1").fetchone()
        if row is None: return None
        schema,generation,policy_sha,head=row
        if schema!=SCHEMA or type(generation) is not int or generation<1 or not _valid_digest(policy_sha) or not _valid_digest(head):
            raise ValueError("corrupt activation state")
        events=con.execute("""SELECT generation,previous_policy_sha256,next_policy_sha256,
            cutover_sha256,previous_event_sha256,event_sha256,certificate_json,rotation_json
            FROM recovery_activation_events ORDER BY generation""").fetchall()
        expected_generation=(events[0][0] if events else generation+1)
        previous=GENESIS
        final_policy=None
        for index,event in enumerate(events):
            g,old_sha,new_sha,cutover_sha,prev,event_sha,cert_raw,rotation_raw=event
            if index==0: expected_generation=g
            if g!=expected_generation or prev!=previous or not all(_valid_digest(v) for v in (old_sha,new_sha,cutover_sha,event_sha)):
                raise ValueError("corrupt activation history")
            try:
                certificate=json.loads(cert_raw); rotation=json.loads(rotation_raw)
            except (ValueError,TypeError):
                raise ValueError("corrupt activation evidence")
            if _digest(certificate)!=cutover_sha:
                raise ValueError("activation certificate digest mismatch")
            calculated=_digest({"generation":g,"previous_policy_sha256":old_sha,
                "next_policy_sha256":new_sha,"cutover_sha256":cutover_sha,
                "previous_event_sha256":prev})
            if calculated!=event_sha:
                raise ValueError("activation event hash mismatch")
            previous=event_sha; final_policy=new_sha; expected_generation+=1
        if events:
            if generation!=events[-1][0] or policy_sha!=final_policy or head!=previous:
                raise ValueError("activation state/history mismatch")
        elif head!=GENESIS:
            raise ValueError("activation genesis head mismatch")
        return {"generation":generation,"policy_sha256":policy_sha,"head_sha256":head}

    def state(self):
        try:
            with sqlite3.connect(self.path) as con: result=self._verified_state(con)
            if result is None: raise ValueError("uninitialized")
            if self.head_anchor is not None and self.head_anchor.read_head()!=result["head_sha256"]:
                raise ValueError("activation registry differs from independent anchor")
            return result
        except (sqlite3.Error,ValueError,TypeError,KeyError,RuntimeError,OSError):
            raise ValueError("corrupt, rolled-back, or unavailable activation registry")

    def export_evidence(self):
        with sqlite3.connect(self.path) as con:
            state=self._verified_state(con)
            if state is None: raise ValueError("activation registry uninitialized")
            rows=con.execute("""SELECT generation,previous_policy_sha256,next_policy_sha256,
                cutover_sha256,previous_event_sha256,event_sha256,certificate_json,rotation_json
                FROM recovery_activation_events ORDER BY generation""").fetchall()
        events=[]
        for row in rows:
            g,old_sha,new_sha,cutover_sha,prev,event_sha,cert_raw,rotation_raw=row
            events.append({"generation":g,"previous_policy_sha256":old_sha,
                "next_policy_sha256":new_sha,"cutover_sha256":cutover_sha,
                "previous_event_sha256":prev,"event_sha256":event_sha,
                "certificate":json.loads(cert_raw),"rotation":json.loads(rotation_raw)})
        return {"schema":"AML-SEF2-RECOVERY-ACTIVATION-EVIDENCE-V1",
            "state":state,"events":events}

    def activate(self,certificate,rotation,next_policy_sha256,generation,
            verifier_keys,threshold,max_faults,independence_manifest,independence_pin):
        if not verify_independent_cutover_certificate(certificate,rotation,next_policy_sha256,
            generation,verifier_keys,threshold,max_faults,independence_manifest,independence_pin):
            return "INVALID_CUTOVER"
        try:
            with sqlite3.connect(self.path,timeout=10) as con:
                con.execute("PRAGMA synchronous=FULL"); con.execute("BEGIN IMMEDIATE")
                try: state=self._verified_state(con)
                except ValueError: return "CORRUPT_STATE"
                if state is None: return "UNINITIALIZED"
                if self.head_anchor is not None:
                    try:
                        if self.head_anchor.read_head()!=state["head_sha256"]: return "ANCHOR_MISMATCH"
                    except (RuntimeError,OSError,ValueError): return "ANCHOR_UNAVAILABLE"
                if generation!=state["generation"]+1: return "GENERATION_MISMATCH"
                payload=rotation.get("payload") if type(rotation) is dict else None
                if (type(payload) is not dict
                    or payload.get("generation")!=generation
                    or payload.get("previous_policy_sha256")!=state["policy_sha256"]
                    or payload.get("next_policy_sha256")!=next_policy_sha256):
                    return "ROTATION_STATE_MISMATCH"
                cutover_sha=_digest(certificate)
                event={"generation":generation,"previous_policy_sha256":state["policy_sha256"],
                    "next_policy_sha256":next_policy_sha256,"cutover_sha256":cutover_sha,
                    "previous_event_sha256":state["head_sha256"]}
                event_sha=_digest(event)
                con.execute("INSERT INTO recovery_activation_events VALUES (?,?,?,?,?,?,?,?)",
                    (generation,state["policy_sha256"],next_policy_sha256,cutover_sha,
                     state["head_sha256"],event_sha,canonical(certificate).decode(),
                     canonical(rotation).decode()))
                con.execute("UPDATE recovery_activation_state SET generation=?,policy_sha256=?,head_sha256=? WHERE singleton=1",
                    (generation,next_policy_sha256,event_sha))
            if self.head_anchor is not None:
                try:
                    if not self.head_anchor.compare_and_set(state["head_sha256"],event_sha):
                        return "ANCHOR_UPDATE_FAILED"
                except (RuntimeError,OSError,ValueError):
                    return "ANCHOR_UPDATE_FAILED"
            return "ACTIVATED"
        except sqlite3.Error:
            return "STORE_OR_STATE_ERROR"
