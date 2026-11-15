"""Durable, externally anchored publication log for recovery transparency V3."""
import json,os,sqlite3,stat
from signed_receipt import canonical
from recovery_transparency_checkpoint import verify_transparency_checkpoint_v3

GENESIS="0"*64

class RecoveryTransparencyLog:
    def __init__(self,path,head_anchor):
        self.path=str(path); self.head_anchor=head_anchor
        if head_anchor is None: raise ValueError("independent transparency head anchor required")
        flags=os.O_CREAT|os.O_EXCL|os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
        try:
            fd=os.open(self.path,flags,0o600); os.close(fd)
        except FileExistsError:
            info=os.stat(self.path,follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("transparency log must be a private regular file")
        os.chmod(self.path,0o600,follow_symlinks=False)
        with sqlite3.connect(self.path,timeout=10) as con:
            con.execute("PRAGMA journal_mode=DELETE"); con.execute("PRAGMA synchronous=FULL")
            con.execute("""CREATE TABLE IF NOT EXISTS transparency_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL,head_sha256 TEXT NOT NULL)""")
            con.execute("""CREATE TABLE IF NOT EXISTS transparency_events (
                sequence INTEGER PRIMARY KEY,checkpoint_json TEXT NOT NULL,
                previous_head_sha256 TEXT NOT NULL,head_sha256 TEXT NOT NULL UNIQUE)""")
            con.execute("INSERT OR IGNORE INTO transparency_state VALUES (1,0,?)",(GENESIS,))
    def _local_state(self):
        with sqlite3.connect(self.path) as con:
            sequence,head=con.execute(
                "SELECT sequence,head_sha256 FROM transparency_state WHERE singleton=1").fetchone()
            rows=con.execute("""SELECT sequence,checkpoint_json,previous_head_sha256,head_sha256
                FROM transparency_events ORDER BY sequence""").fetchall()
        previous=GENESIS
        if sequence!=len(rows): raise ValueError("transparency sequence/event count mismatch")
        for expected,(event_sequence,raw,predecessor,event_head) in enumerate(rows,1):
            checkpoint=json.loads(raw)
            if (event_sequence!=expected or predecessor!=previous
                or checkpoint.get("checkpoint_sha256")!=event_head
                or checkpoint.get("payload",{}).get("sequence")!=expected
                or checkpoint.get("payload",{}).get("previous_checkpoint_sha256")!=previous):
                raise ValueError("corrupt recovery transparency log")
            previous=event_head
        if head!=previous: raise ValueError("transparency head differs from event chain")
        return {"sequence":sequence,"head_sha256":head}
    def state(self):
        try:
            state=self._local_state()
            if self.head_anchor.read_head()!=state["head_sha256"]:
                raise ValueError("recovery transparency log differs from independent anchor")
            return state
        except (OSError,RuntimeError,ValueError,sqlite3.Error,TypeError,KeyError) as exc:
            raise ValueError("corrupt, rolled-back, or unavailable recovery transparency log") from exc
    def append(self,checkpoint,policy,tracked_targets):
        try:
            local=self._local_state()
            anchored=self.head_anchor.read_head()
        except (OSError,RuntimeError,ValueError,sqlite3.Error):
            return "ANCHOR_UNAVAILABLE"
        if anchored!=local["head_sha256"]:
            return "ANCHOR_MISMATCH"
        sequence=local["sequence"]+1
        if not verify_transparency_checkpoint_v3(checkpoint,policy,tracked_targets,
            sequence,local["head_sha256"],checkpoint.get("payload",{}).get("policy_generation"),
            checkpoint.get("payload",{}).get("target_registry_generation")):
            return "INVALID_CHECKPOINT"
        new_head=checkpoint["checkpoint_sha256"]
        try:
            with sqlite3.connect(self.path,timeout=10) as con:
                con.execute("PRAGMA synchronous=FULL"); con.execute("BEGIN IMMEDIATE")
                row=con.execute("SELECT sequence,head_sha256 FROM transparency_state WHERE singleton=1").fetchone()
                if tuple(row)!=(local["sequence"],local["head_sha256"]):
                    return "CONCURRENT_UPDATE"
                con.execute("INSERT INTO transparency_events VALUES (?,?,?,?)",
                    (sequence,canonical(checkpoint).decode(),local["head_sha256"],new_head))
                con.execute("UPDATE transparency_state SET sequence=?,head_sha256=? WHERE singleton=1",
                    (sequence,new_head))
        except sqlite3.Error:
            return "STORE_ERROR"
        try:
            if not self.head_anchor.compare_and_set(local["head_sha256"],new_head):
                return "ANCHOR_UPDATE_FAILED"
        except (OSError,RuntimeError,ValueError):
            return "ANCHOR_UPDATE_FAILED"
        return "PUBLISHED"
    def reconcile_anchor(self,expected_predecessor=None):
        local=self._local_state()
        with sqlite3.connect(self.path) as con:
            row=con.execute("""SELECT previous_head_sha256,head_sha256 FROM transparency_events
                ORDER BY sequence DESC LIMIT 1""").fetchone()
        predecessor=row[0] if row else GENESIS
        try: anchored=self.head_anchor.read_head()
        except (OSError,RuntimeError,ValueError):
            if expected_predecessor is None:
                raise RuntimeError("anchor unreadable; predecessor pin required")
            anchored=expected_predecessor
        if anchored==local["head_sha256"]: return local["head_sha256"]
        if anchored!=predecessor: raise RuntimeError("EXPECTED_PREDECESSOR_MISMATCH")
        if not self.head_anchor.compare_and_set(predecessor,local["head_sha256"]):
            raise RuntimeError("transparency anchor reconciliation CAS failed")
        return local["head_sha256"]
