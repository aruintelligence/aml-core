"""Synthetic capability broker: atomic policy-epoch revocation and effect commit.

This is an in-process research fixture. OS-level isolation and remote
authority enrollment are not provided; filesystem access can bypass it.
"""
import hashlib
import sqlite3
from gated_action_broker import canonical_request
from strict_evaluator import verify_strict_evaluator
from action_capability import verify_capability

class CapabilityBroker:
    def __init__(self,path,registry,witness,replicas,threshold,enrolled_keys,
                 issuer,issuer_public_hex,audience):
        if type(issuer) is not str or not issuer or type(audience) is not str or not audience:
            raise ValueError("invalid issuer or audience")
        if type(issuer_public_hex) is not str or len(bytes.fromhex(issuer_public_hex))!=32:
            raise ValueError("invalid issuer key")
        self.path=str(path)
        self.registry=registry
        self.witness=witness
        self.replicas=replicas
        self.threshold=threshold
        self.enrolled_keys=enrolled_keys
        self.issuer=issuer
        self.issuer_public_hex=issuer_public_hex
        self.audience=audience
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS effects (operation_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS policy_epoch (audience TEXT PRIMARY KEY, epoch INTEGER NOT NULL)")
            db.execute("INSERT OR IGNORE INTO policy_epoch VALUES (?,0)",(audience,))
    def revoke_all(self):
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE policy_epoch SET epoch=epoch+1 WHERE audience=?",(self.audience,))
    def current_epoch(self):
        with sqlite3.connect(self.path) as db:
            row=db.execute("SELECT epoch FROM policy_epoch WHERE audience=?",(self.audience,)).fetchone()
            if row is None:
                raise ValueError("missing policy epoch")
            return row[0]
    def execute(self,request,attestations,capability=None):
        try:
            body=canonical_request(request)
            if not verify_strict_evaluator(self.registry,self.witness,self.replicas,
                                            self.threshold,attestations,self.enrolled_keys):
                return "DENIED"
            digest=hashlib.sha256(body).hexdigest()
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                row=db.execute("SELECT epoch FROM policy_epoch WHERE audience=?",(self.audience,)).fetchone()
                if row is None or not verify_capability(capability,self.issuer_public_hex,
                    self.issuer,self.audience,request,row[0]):
                    return "DENIED"
                existing=db.execute("SELECT request_hash FROM effects WHERE operation_id=?",
                                    (request["operation_id"],)).fetchone()
                if existing is not None:
                    return "ALREADY_APPLIED" if existing[0]==digest else "DENIED"
                db.execute("INSERT INTO effects VALUES (?,?)",(request["operation_id"],digest))
            return "APPLIED"
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError):
            return "DENIED"
