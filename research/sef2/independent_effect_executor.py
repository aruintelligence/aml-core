"""Independent synthetic effect executor.

The executor owns the effect database and accepts a commit only when it can
independently verify all authorization evidence:
* authority-issued holder-bound capability,
* broker-signed execution challenge,
* holder proof of possession,
* strict-evaluator signed authorization,
* current epoch from an independently retained revocation anchor.

The broker cannot write the executor database in the intended deployment.
This remains a synthetic effect, not proof that any external payment/device
action occurred.
"""
import hashlib,sqlite3
from gated_action_broker import canonical_request
from session_capability import verify_session_capability,verify_holder_proof
from authenticated_execution_challenge import verify_execution_challenge
from execution_gate_receipt import verify_evaluator_authorization

class IndependentEffectExecutor:
    def __init__(self,path,issuer,issuer_public_hex,audience,broker_id,broker_public_hex,
                 evaluator_id,evaluator_public_hex,witness,epoch_anchor,execution_witness=None):
        for value,name in ((issuer,"issuer"),(audience,"audience"),(broker_id,"broker_id"),
                           (evaluator_id,"evaluator_id"),(witness,"witness")):
            if type(value) is not str or not value:
                raise ValueError("invalid "+name)
        for value in (issuer_public_hex,broker_public_hex,evaluator_public_hex):
            if type(value) is not str or len(bytes.fromhex(value))!=32:
                raise ValueError("invalid pinned public key")
        self.path=str(path); self.issuer=issuer; self.issuer_public_hex=issuer_public_hex
        self.audience=audience; self.broker_id=broker_id; self.broker_public_hex=broker_public_hex
        self.evaluator_id=evaluator_id; self.evaluator_public_hex=evaluator_public_hex
        self.witness=witness; self.epoch_anchor=epoch_anchor
        self.execution_witness=execution_witness
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS independent_effects (
                operation_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,policy_epoch INTEGER NOT NULL)""")

    def execute(self,request,capability,execution_challenge,holder_proof,evaluator_authorization):
        try:
            epoch=self.epoch_anchor.read_epoch(self.audience)
            if type(epoch) is not int or epoch<0:
                return "DENIED"
            if not verify_session_capability(capability,self.issuer_public_hex,self.issuer,
                    self.audience,request,epoch):
                return "DENIED"
            if not verify_execution_challenge(execution_challenge,self.broker_public_hex,
                    self.broker_id,self.audience,request,capability,epoch):
                return "DENIED"
            raw_challenge=execution_challenge["payload"]["challenge"]
            if not verify_holder_proof(holder_proof,capability,request,raw_challenge):
                return "DENIED"
            if not verify_evaluator_authorization(evaluator_authorization,
                    self.evaluator_public_hex,self.evaluator_id,self.audience,self.witness,
                    request,capability,execution_challenge,epoch):
                return "DENIED"
            request_hash=hashlib.sha256(canonical_request(request)).hexdigest()
            from signed_receipt import canonical
            evidence={"capability":capability,"execution_challenge":execution_challenge,
                "holder_proof":holder_proof,"evaluator_authorization":evaluator_authorization}
            evidence_hash=hashlib.sha256(canonical(evidence)).hexdigest()
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                existing=db.execute("""SELECT request_sha256,evidence_sha256,policy_epoch
                    FROM independent_effects WHERE operation_id=?""",
                    (request["operation_id"],)).fetchone()
                if existing is not None:
                    return "ALREADY_APPLIED" if existing[0]==request_hash else "DENIED"
                # Re-read external epoch immediately before commit. If revocation
                # advanced between verification and the transaction, fail closed.
                if self.epoch_anchor.read_epoch(self.audience)!=epoch:
                    return "DENIED"
                if self.execution_witness is not None:
                    if hasattr(self.execution_witness,"consume_authorized"):
                        self.execution_witness.consume_authorized(request,capability,raw_challenge,
                            holder_proof,evaluator_authorization)
                    else:
                        self.execution_witness.consume(request,capability,raw_challenge)
                db.execute("INSERT INTO independent_effects VALUES (?,?,?,?)",
                    (request["operation_id"],request_hash,evidence_hash,epoch))
            return "APPLIED"
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError,PermissionError):
            return "DENIED"
