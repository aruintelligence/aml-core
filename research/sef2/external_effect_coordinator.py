"""Independent authorization coordinator for idempotent downstream effects.

The coordinator linearizes authorization locally as PENDING, then invokes a
downstream endpoint that must provide operation-id idempotency, signed durable
receipts and query-by-operation-id. If the apply response is lost, the
coordinator queries the endpoint. If status cannot be established, it returns
AMBIGUOUS and never silently reports success.

A PENDING row represents an already-authorized operation. Explicit
reconcile_pending() may complete it after later policy revocation.
"""
import hashlib,json,sqlite3
from authenticated_execution_challenge import verify_execution_challenge
from execution_gate_receipt import verify_evaluator_authorization
from gated_action_broker import canonical_request
from idempotent_effect_endpoint import verify_endpoint_receipt
from session_capability import verify_holder_proof,verify_session_capability
from signed_receipt import canonical

class ExternalEffectCoordinator:
    def __init__(self,path,issuer,issuer_public_hex,audience,broker_id,broker_public_hex,
                 evaluator_id,evaluator_public_hex,witness,epoch_anchor,
                 endpoint_id,endpoint_public_hex,transport):
        for value,name in ((issuer,"issuer"),(audience,"audience"),(broker_id,"broker_id"),
                           (evaluator_id,"evaluator_id"),(witness,"witness"),
                           (endpoint_id,"endpoint_id")):
            if type(value) is not str or not value: raise ValueError("invalid "+name)
        for value in (issuer_public_hex,broker_public_hex,evaluator_public_hex,endpoint_public_hex):
            if type(value) is not str or len(bytes.fromhex(value))!=32:
                raise ValueError("invalid pinned public key")
        self.path=str(path); self.issuer=issuer; self.issuer_public_hex=issuer_public_hex
        self.audience=audience; self.broker_id=broker_id; self.broker_public_hex=broker_public_hex
        self.evaluator_id=evaluator_id; self.evaluator_public_hex=evaluator_public_hex
        self.witness=witness; self.epoch_anchor=epoch_anchor
        self.endpoint_id=endpoint_id; self.endpoint_public_hex=endpoint_public_hex
        self.transport=transport
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS external_effects (
                operation_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,effect_sha256 TEXT NOT NULL,
                policy_epoch INTEGER NOT NULL,status TEXT NOT NULL
                CHECK(status IN ('PENDING','COMMITTED')),
                receipt_json TEXT)""")

    def _verify_authorization(self,request,capability,execution_challenge,
                              holder_proof,evaluator_authorization):
        epoch=self.epoch_anchor.read_epoch(self.audience)
        if type(epoch) is not int or epoch<0: return None
        if not verify_session_capability(capability,self.issuer_public_hex,self.issuer,
                self.audience,request,epoch): return None
        if not verify_execution_challenge(execution_challenge,self.broker_public_hex,
                self.broker_id,self.audience,request,capability,epoch): return None
        raw=execution_challenge["payload"]["challenge"]
        if not verify_holder_proof(holder_proof,capability,request,raw): return None
        if not verify_evaluator_authorization(evaluator_authorization,self.evaluator_public_hex,
                self.evaluator_id,self.audience,self.witness,request,capability,
                execution_challenge,epoch): return None
        request_hash=hashlib.sha256(canonical_request(request)).hexdigest()
        evidence={"capability":capability,"execution_challenge":execution_challenge,
            "holder_proof":holder_proof,"evaluator_authorization":evaluator_authorization}
        evidence_hash=hashlib.sha256(canonical(evidence)).hexdigest()
        effect_payload={"schema":"AML-SEF2-IDEMPOTENT-DOWNSTREAM-EFFECT-V1",
            "operation_id":request["operation_id"],"request_sha256":request_hash}
        effect_hash=hashlib.sha256(canonical(effect_payload)).hexdigest()
        return epoch,request_hash,evidence_hash,effect_hash

    def _valid_receipt(self,receipt,operation_id,request_hash,effect_hash):
        return verify_endpoint_receipt(receipt,self.endpoint_public_hex,self.endpoint_id,
            operation_id,request_hash,effect_hash)

    def _mark_committed(self,operation_id,receipt):
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            row=db.execute("""SELECT request_sha256,effect_sha256,status FROM external_effects
                WHERE operation_id=?""",(operation_id,)).fetchone()
            if row is None: return False
            if not self._valid_receipt(receipt,operation_id,row[0],row[1]): return False
            db.execute("UPDATE external_effects SET status='COMMITTED',receipt_json=? WHERE operation_id=?",
                (canonical(receipt).decode(),operation_id))
        return True

    def _complete_pending(self,operation_id,request_hash,effect_hash,allow_apply):
        try:
            existing=self.transport.query(operation_id)
        except Exception:
            existing=None
            query_failed=True
        else:
            query_failed=False
        if existing is not None:
            if not self._valid_receipt(existing,operation_id,request_hash,effect_hash):
                return "DENIED"
            return "RECOVERED" if self._mark_committed(operation_id,existing) else "DENIED"
        if query_failed:
            return "AMBIGUOUS"
        if not allow_apply:
            return "AMBIGUOUS"
        try:
            receipt=self.transport.apply(operation_id,request_hash,effect_hash)
        except Exception:
            try:
                receipt=self.transport.query(operation_id)
            except Exception:
                return "AMBIGUOUS"
            if receipt is None:
                return "AMBIGUOUS"
        if not self._valid_receipt(receipt,operation_id,request_hash,effect_hash):
            return "DENIED"
        return "RECOVERED" if self._mark_committed(operation_id,receipt) else "DENIED"

    def execute(self,request,capability,execution_challenge,holder_proof,evaluator_authorization):
        try:
            verified=self._verify_authorization(request,capability,execution_challenge,
                holder_proof,evaluator_authorization)
            if verified is None: return "DENIED"
            epoch,request_hash,evidence_hash,effect_hash=verified
            operation_id=request["operation_id"]
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                row=db.execute("""SELECT request_sha256,evidence_sha256,effect_sha256,
                    policy_epoch,status,receipt_json FROM external_effects WHERE operation_id=?""",
                    (operation_id,)).fetchone()
                if row:
                    if row[:4]!=(request_hash,evidence_hash,effect_hash,epoch): return "DENIED"
                    if row[4]=="COMMITTED":
                        if row[5] is None: return "DENIED"
                        receipt=json.loads(row[5])
                        return "ALREADY_APPLIED" if self._valid_receipt(receipt,operation_id,
                            request_hash,effect_hash) else "DENIED"
                    # Same exact evidence already linearized as authorized PENDING.
                    pending=True
                else:
                    if self.epoch_anchor.read_epoch(self.audience)!=epoch: return "DENIED"
                    db.execute("INSERT INTO external_effects VALUES (?,?,?,?,?,'PENDING',NULL)",
                        (operation_id,request_hash,evidence_hash,effect_hash,epoch))
                    pending=False
            result=self._complete_pending(operation_id,request_hash,effect_hash,True)
            if result=="RECOVERED":
                return "APPLIED"
            return result
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError,PermissionError):
            return "DENIED"

    def reconcile_pending(self,operation_id):
        if type(operation_id) is not str or not operation_id: return "DENIED"
        try:
            with sqlite3.connect(self.path) as db:
                row=db.execute("""SELECT request_sha256,effect_sha256,status,receipt_json
                    FROM external_effects WHERE operation_id=?""",(operation_id,)).fetchone()
            if row is None: return "NOT_FOUND"
            if row[2]=="COMMITTED":
                if row[3] is None: return "DENIED"
                receipt=json.loads(row[3])
                return "ALREADY_APPLIED" if self._valid_receipt(receipt,operation_id,row[0],row[1]) else "DENIED"
            return self._complete_pending(operation_id,row[0],row[1],True)
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError):
            return "DENIED"
