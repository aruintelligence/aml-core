"""Capability broker requiring holder proof of possession for a fresh challenge."""
import hashlib,secrets,sqlite3
from gated_action_broker import canonical_request
from strict_evaluator import verify_strict_evaluator
from session_capability import verify_session_capability,verify_holder_proof

class SessionCapabilityBroker:
    def __init__(self,path,registry,witness,replicas,threshold,enrolled_keys,
                 issuer,issuer_public_hex,audience):
        if type(issuer) is not str or not issuer or type(audience) is not str or not audience:
            raise ValueError("invalid issuer or audience")
        if type(issuer_public_hex) is not str or len(bytes.fromhex(issuer_public_hex))!=32:
            raise ValueError("invalid issuer key")
        self.path=str(path); self.registry=registry; self.witness=witness
        self.replicas=replicas; self.threshold=threshold; self.enrolled_keys=enrolled_keys
        self.issuer=issuer; self.issuer_public_hex=issuer_public_hex; self.audience=audience
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS session_effects (operation_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS session_policy_epoch (audience TEXT PRIMARY KEY,epoch INTEGER NOT NULL)")
            db.execute("INSERT OR IGNORE INTO session_policy_epoch VALUES (?,0)",(audience,))
            db.execute("""CREATE TABLE IF NOT EXISTS execution_challenges (
                operation_id TEXT PRIMARY KEY,challenge TEXT UNIQUE NOT NULL,
                epoch INTEGER NOT NULL,consumed INTEGER NOT NULL CHECK(consumed IN (0,1)))""")
    def current_epoch(self):
        with sqlite3.connect(self.path) as db:
            row=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(self.audience,)).fetchone()
            if row is None: raise ValueError("missing policy epoch")
            return row[0]
    def revoke_all(self):
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE session_policy_epoch SET epoch=epoch+1 WHERE audience=?",(self.audience,))
    def issue_execution_challenge(self,operation_id):
        if type(operation_id) is not str or not operation_id or len(operation_id)>128:
            raise ValueError("invalid operation id")
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            epoch=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(self.audience,)).fetchone()[0]
            row=db.execute("SELECT challenge,epoch,consumed FROM execution_challenges WHERE operation_id=?",(operation_id,)).fetchone()
            if row:
                if row[1]!=epoch or row[2]!=0: raise PermissionError("challenge unavailable")
                return row[0]
            challenge=secrets.token_hex(32)
            db.execute("INSERT INTO execution_challenges VALUES (?,?,?,0)",(operation_id,challenge,epoch))
            return challenge
    def execute(self,request,attestations,capability,holder_proof,challenge):
        try:
            body=canonical_request(request)
            if not verify_strict_evaluator(self.registry,self.witness,self.replicas,
                                            self.threshold,attestations,self.enrolled_keys):
                return "DENIED"
            digest=hashlib.sha256(body).hexdigest()
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                epoch_row=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(self.audience,)).fetchone()
                if epoch_row is None: return "DENIED"
                epoch=epoch_row[0]
                if not verify_session_capability(capability,self.issuer_public_hex,self.issuer,
                    self.audience,request,epoch):
                    return "DENIED"
                c=db.execute("SELECT challenge,epoch,consumed FROM execution_challenges WHERE operation_id=?",
                    (request["operation_id"],)).fetchone()
                if c is None or c[0]!=challenge or c[1]!=epoch or c[2]!=0:
                    return "DENIED"
                if not verify_holder_proof(holder_proof,capability,request,challenge):
                    return "DENIED"
                existing=db.execute("SELECT request_hash FROM session_effects WHERE operation_id=?",
                    (request["operation_id"],)).fetchone()
                if existing is not None:
                    return "ALREADY_APPLIED" if existing[0]==digest else "DENIED"
                db.execute("INSERT INTO session_effects VALUES (?,?)",(request["operation_id"],digest))
                db.execute("UPDATE execution_challenges SET consumed=1 WHERE operation_id=?",
                    (request["operation_id"],))
            return "APPLIED"
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError):
            return "DENIED"
