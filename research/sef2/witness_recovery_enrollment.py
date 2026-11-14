"""Atomic bridge from offline key recovery into durable witness trust enrollment."""
import json,sqlite3
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from trust_enrollment import valid
from witness_key_recovery import advance_state,key_fingerprint,verify_transition
from checkpoint_council import valid_checkpoint

class WitnessRecoveryEnrollment:
    def __init__(self,path,recovery_state_path,recovery_public_key,recovery_authority_id):
        self.path=str(path); self.recovery_state_path=str(recovery_state_path)
        if sqlite3.os.path.abspath(self.path)==sqlite3.os.path.abspath(self.recovery_state_path):
            raise ValueError("recovery state must use a separate database file")
        self.recovery_public_key=recovery_public_key
        self.recovery_authority_id=recovery_authority_id
        with sqlite3.connect(self.recovery_state_path) as con:
            con.execute("PRAGMA journal_mode=DELETE")
            con.execute("PRAGMA synchronous=FULL")
            con.execute("CREATE TABLE IF NOT EXISTS witness_recovery_state (witness_id TEXT PRIMARY KEY,state TEXT NOT NULL)")
            con.execute("CREATE TABLE IF NOT EXISTS witness_recovery_events (witness_id TEXT NOT NULL,generation INTEGER NOT NULL,transition_sha256 TEXT NOT NULL,event TEXT NOT NULL,PRIMARY KEY(witness_id,generation))")

    def _connect(self):
        con=sqlite3.connect(self.path,timeout=10)
        con.execute("PRAGMA main.journal_mode=DELETE")
        con.execute("PRAGMA main.synchronous=FULL")
        con.execute("ATTACH DATABASE ? AS recovery",(self.recovery_state_path,))
        con.execute("PRAGMA recovery.journal_mode=DELETE")
        con.execute("PRAGMA recovery.synchronous=FULL")
        return con
    def initialize(self,witness_id,checkpoint):
        if not valid_checkpoint(checkpoint): raise ValueError("invalid initial checkpoint")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row=con.execute("SELECT payload FROM epochs ORDER BY epoch DESC LIMIT 1").fetchone()
            if row is None: raise ValueError("trust enrollment required")
            manifest=json.loads(row[0])
            if not valid(manifest) or "witness" not in manifest["public_keys"]: raise ValueError("invalid enrolled witness trust")
            state={"witness_id":witness_id,"generation":0,"public_key_sha256":key_fingerprint(manifest["public_keys"]["witness"]),"checkpoint":dict(checkpoint),"transition_sha256":"0"*64}
            existing=con.execute("SELECT state FROM recovery.witness_recovery_state WHERE witness_id=?",(witness_id,)).fetchone()
            if existing:
                if json.loads(existing[0])!=state: raise ValueError("already initialized differently")
                return state
            con.execute("INSERT INTO recovery.witness_recovery_state VALUES (?,?)",(witness_id,canonical(state).decode()))
            return state
    def state(self,witness_id):
        with sqlite3.connect(self.recovery_state_path) as con: row=con.execute("SELECT state FROM witness_recovery_state WHERE witness_id=?",(witness_id,)).fetchone()
        if row is None: raise ValueError("uninitialized")
        return json.loads(row[0])
    def recover(self,witness_id,envelope):
        try:
            with sqlite3.connect(self.path,timeout=10) as con:
                con.execute("BEGIN IMMEDIATE")
                row=con.execute("SELECT state FROM recovery.witness_recovery_state WHERE witness_id=?",(witness_id,)).fetchone()
                mr=con.execute("SELECT epoch,payload FROM epochs ORDER BY epoch DESC LIMIT 1").fetchone()
                if row is None or mr is None: return "UNINITIALIZED"
                current=json.loads(row[0]); manifest=json.loads(mr[1])
                if not valid(manifest) or key_fingerprint(manifest["public_keys"]["witness"])!=current["public_key_sha256"]: return "TRUST_STATE_MISMATCH"
                if not verify_transition(envelope,current,self.recovery_public_key,self.recovery_authority_id): return "INVALID_RECOVERY"
                next_state=advance_state(envelope,current,self.recovery_public_key,self.recovery_authority_id)
                updated=dict(manifest); updated["epoch"]=manifest["epoch"]+1
                updated["public_keys"]=dict(manifest["public_keys"])
                old=updated["public_keys"]["witness"]
                updated["public_keys"]["witness"]=envelope["payload"]["new_public_key_hex"]
                updated["revoked_key_hex"]=sorted(set(updated["revoked_key_hex"])|{old})
                if not valid(updated): return "INVALID_ENROLLMENT"
                con.execute("INSERT INTO epochs VALUES (?,?)",(updated["epoch"],canonical(updated).decode()))
                con.execute("INSERT INTO revoked VALUES (?)",(old,))
                con.execute("UPDATE recovery.witness_recovery_state SET state=? WHERE witness_id=?",(canonical(next_state).decode(),witness_id))
                con.execute("INSERT INTO recovery.witness_recovery_events VALUES (?,?,?,?)",(witness_id,next_state["generation"],next_state["transition_sha256"],canonical(envelope).decode()))
                return "RECOVERED"
        except (sqlite3.Error,ValueError,TypeError,KeyError,InvalidSignature,OverflowError,AttributeError):
            return "STORE_OR_STATE_ERROR"
