"""Independent authorization verifier plus real durable filesystem effect.

This executor does not trust the submitting broker's success claim. It
independently verifies authority capability, broker challenge, holder proof,
evaluator authorization and current revocation epoch before durably
linearizing a PENDING operation. The protected consequence is a file owned by
the executor's OS identity.

The effect is deterministic/idempotent local filesystem state. This is not a
claim about payments, remote devices, root/kernel compromise or arbitrary
non-idempotent external APIs.
"""
import hashlib,json,os,pathlib,sqlite3,tempfile
from authenticated_execution_challenge import verify_execution_challenge
from execution_gate_receipt import verify_evaluator_authorization
from gated_action_broker import canonical_request
from session_capability import verify_holder_proof,verify_session_capability
from signed_receipt import canonical

class InjectedIndependentFilesystemCrash(RuntimeError): pass

class IndependentFilesystemEffectExecutor:
    def __init__(self,path,effect_dir,issuer,issuer_public_hex,audience,broker_id,
                 broker_public_hex,evaluator_id,evaluator_public_hex,witness,
                 epoch_anchor,fault_hook=None,execution_witness=None):
        for value,name in ((issuer,"issuer"),(audience,"audience"),(broker_id,"broker_id"),
                           (evaluator_id,"evaluator_id"),(witness,"witness")):
            if type(value) is not str or not value: raise ValueError("invalid "+name)
        for value in (issuer_public_hex,broker_public_hex,evaluator_public_hex):
            if type(value) is not str or len(bytes.fromhex(value))!=32:
                raise ValueError("invalid pinned public key")
        self.path=str(path); self.effect_dir=pathlib.Path(effect_dir)
        self.issuer=issuer; self.issuer_public_hex=issuer_public_hex; self.audience=audience
        self.broker_id=broker_id; self.broker_public_hex=broker_public_hex
        self.evaluator_id=evaluator_id; self.evaluator_public_hex=evaluator_public_hex
        self.witness=witness; self.epoch_anchor=epoch_anchor; self.fault_hook=fault_hook
        if execution_witness is None or not hasattr(execution_witness,"consume_authorized"):
            raise ValueError("full-authorization execution witness required")
        self.execution_witness=execution_witness
        self.effect_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
        if self.effect_dir.is_symlink() or not self.effect_dir.is_dir():
            raise ValueError("effect directory must be a real directory")
        os.chmod(self.effect_dir,0o700)
        if self.effect_dir.stat().st_mode & 0o077:
            raise ValueError("effect directory must be private")
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS independent_filesystem_effects (
                operation_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,policy_epoch INTEGER NOT NULL,
                effect_payload TEXT NOT NULL,consumption_sha256 TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('PENDING','COMMITTED')))""")

    def _path(self,operation_id):
        return self.effect_dir/(hashlib.sha256(operation_id.encode()).hexdigest()+".effect.json")

    def _payload(self,request,request_hash,evidence_hash,epoch):
        return json.dumps({"schema":"AML-SEF2-INDEPENDENT-FILESYSTEM-EFFECT-V1",
            "operation_id":request["operation_id"],"request_sha256":request_hash,
            "evidence_sha256":evidence_hash,"policy_epoch":epoch},
            sort_keys=True,separators=(",",":"))

    def _file_matches(self,path,payload):
        try: return path.is_file() and not path.is_symlink() and path.read_text()==payload
        except OSError: return False

    def _install(self,operation_id,payload):
        final=self._path(operation_id)
        if final.exists():
            if not self._file_matches(final,payload):
                raise ValueError("protected effect conflicts with committed authorization")
            return
        fd,tmp=tempfile.mkstemp(prefix=".pending-",dir=self.effect_dir)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,"wb",closefd=True) as stream:
                stream.write(payload.encode()); stream.flush(); os.fsync(stream.fileno())
            fd=None; os.replace(tmp,final)
            dfd=os.open(self.effect_dir,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
            try: os.fsync(dfd)
            finally: os.close(dfd)
        finally:
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
            try:
                if os.path.exists(tmp): os.unlink(tmp)
            except OSError: pass

    def _fault(self,point):
        if self.fault_hook is not None: self.fault_hook(point)

    def _verify(self,request,capability,execution_challenge,holder_proof,evaluator_authorization):
        epoch=self.epoch_anchor.read_epoch(self.audience)
        if type(epoch) is not int or epoch<0: return None
        if not verify_session_capability(capability,self.issuer_public_hex,self.issuer,
                self.audience,request,epoch): return None
        if not verify_execution_challenge(execution_challenge,self.broker_public_hex,
                self.broker_id,self.audience,request,capability,epoch): return None
        raw_challenge=execution_challenge["payload"]["challenge"]
        if not verify_holder_proof(holder_proof,capability,request,raw_challenge): return None
        if not verify_evaluator_authorization(evaluator_authorization,self.evaluator_public_hex,
                self.evaluator_id,self.audience,self.witness,request,capability,
                execution_challenge,epoch): return None
        request_hash=hashlib.sha256(canonical_request(request)).hexdigest()
        evidence={"capability":capability,"execution_challenge":execution_challenge,
            "holder_proof":holder_proof,"evaluator_authorization":evaluator_authorization}
        evidence_hash=hashlib.sha256(canonical(evidence)).hexdigest()
        return epoch,request_hash,evidence_hash

    def execute(self,request,capability,execution_challenge,holder_proof,evaluator_authorization):
        try:
            verified=self._verify(request,capability,execution_challenge,holder_proof,evaluator_authorization)
            if verified is None: return "DENIED"
            epoch,request_hash,evidence_hash=verified
            payload=self._payload(request,request_hash,evidence_hash,epoch)
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                row=db.execute("""SELECT request_sha256,evidence_sha256,policy_epoch,effect_payload,
                    consumption_sha256,status FROM independent_filesystem_effects WHERE operation_id=?""",
                    (request["operation_id"],)).fetchone()
                if row is not None:
                    if row[:4]!=(request_hash,evidence_hash,epoch,payload): return "DENIED"
                    if row[5]=="COMMITTED":
                        return "ALREADY_APPLIED" if self._file_matches(self._path(request["operation_id"]),payload) else "DENIED"
                else:
                    if self.epoch_anchor.read_epoch(self.audience)!=epoch: return "DENIED"
                    raw_challenge=execution_challenge["payload"]["challenge"]
                    consumed=self.execution_witness.consume_authorized(request,capability,raw_challenge,
                        holder_proof,evaluator_authorization)
                    consumption_sha256=hashlib.sha256(canonical(consumed)).hexdigest()
                    self._fault("after_consumption")
                    db.execute("""INSERT INTO independent_filesystem_effects
                        VALUES (?,?,?,?,?,?,'PENDING')""",
                        (request["operation_id"],request_hash,evidence_hash,epoch,payload,
                         consumption_sha256))
            self._fault("after_pending")
            self._install(request["operation_id"],payload)
            self._fault("after_effect")
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                row=db.execute("""SELECT request_sha256,evidence_sha256,policy_epoch,effect_payload,
                    consumption_sha256,status FROM independent_filesystem_effects WHERE operation_id=?""",
                    (request["operation_id"],)).fetchone()
                if row is None or row[:4]!=(request_hash,evidence_hash,epoch,payload): return "DENIED"
                if not self._file_matches(self._path(request["operation_id"]),payload): return "DENIED"
                db.execute("UPDATE independent_filesystem_effects SET status='COMMITTED' WHERE operation_id=?",
                    (request["operation_id"],))
            return "APPLIED"
        except InjectedIndependentFilesystemCrash: raise
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError,PermissionError):
            return "DENIED"

    def recover_pending(self,operation_id):
        try:
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                row=db.execute("""SELECT request_sha256,evidence_sha256,policy_epoch,effect_payload,
                    consumption_sha256,status FROM independent_filesystem_effects WHERE operation_id=?""",
                    (operation_id,)).fetchone()
                if row is None: return "NOT_FOUND"
                payload=row[3]
                if type(row[4]) is not str or len(row[4])!=64:
                    return "DENIED"
                if row[5]=="COMMITTED":
                    return "ALREADY_APPLIED" if self._file_matches(self._path(operation_id),payload) else "DENIED"
            self._install(operation_id,payload)
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                row=db.execute("""SELECT effect_payload,consumption_sha256,status
                    FROM independent_filesystem_effects WHERE operation_id=?""",(operation_id,)).fetchone()
                if (row is None or row[0]!=payload or type(row[1]) is not str or len(row[1])!=64
                    or not self._file_matches(self._path(operation_id),payload)):
                    return "DENIED"
                db.execute("UPDATE independent_filesystem_effects SET status='COMMITTED' WHERE operation_id=?",
                    (operation_id,))
            return "RECOVERED"
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError):
            return "DENIED"
