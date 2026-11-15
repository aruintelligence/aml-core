"""Session-bound broker for a real broker-owned filesystem side effect.

The protected effect is an atomically installed file in a broker-only directory.
Authorization is linearized when a durable PENDING row is committed under the
current policy epoch. A revocation after that point does not cancel the already
authorized operation. Crash recovery is explicit via recover_pending().

This demonstrates a kernel-enforced local consequence, not a payment or remote
external effect. Filesystem durability depends on fsync/rename semantics.
"""
import hashlib,json,os,pathlib,sqlite3,tempfile
from gated_action_broker import canonical_request
from strict_evaluator import verify_strict_evaluator
from session_capability import verify_session_capability,verify_holder_proof
from session_capability_broker import SessionCapabilityBroker

class InjectedEffectCrash(RuntimeError): pass

class DurableFilesystemEffectBroker(SessionCapabilityBroker):
    def __init__(self,path,effect_dir,registry,witness,replicas,threshold,enrolled_keys,
                 issuer,issuer_public_hex,audience,broker_instance_id=None,
                 broker_challenge_private=None,epoch_anchor=None,fault_hook=None):
        super().__init__(path,registry,witness,replicas,threshold,enrolled_keys,issuer,
            issuer_public_hex,audience,broker_instance_id,broker_challenge_private,epoch_anchor,None)
        self.effect_dir=pathlib.Path(effect_dir)
        self.fault_hook=fault_hook
        self.effect_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
        if self.effect_dir.is_symlink() or not self.effect_dir.is_dir():
            raise ValueError("effect directory must be a real directory")
        os.chmod(self.effect_dir,0o700)
        if self.effect_dir.stat().st_mode & 0o077:
            raise ValueError("effect directory must not be group/world accessible")
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS filesystem_effects (
                operation_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,
                effect_payload TEXT NOT NULL,status TEXT NOT NULL
                CHECK(status IN ('PENDING','COMMITTED')))""")

    def _effect_path(self,operation_id):
        name=hashlib.sha256(operation_id.encode("utf-8")).hexdigest()+".effect.json"
        return self.effect_dir/name

    def _effect_payload(self,request,digest):
        return json.dumps({"schema":"AML-SEF2-FILESYSTEM-EFFECT-V1",
            "operation_id":request["operation_id"],"request_sha256":digest},
            sort_keys=True,separators=(",",":"))

    def _verify_file(self,path,payload):
        try:
            return path.is_file() and not path.is_symlink() and path.read_text()==payload
        except OSError:
            return False

    def _durable_install(self,operation_id,payload):
        final=self._effect_path(operation_id)
        if final.exists():
            if not self._verify_file(final,payload):
                raise ValueError("existing protected effect conflicts with authorized payload")
            return
        fd,tmp=tempfile.mkstemp(prefix=".pending-",dir=self.effect_dir)
        try:
            os.fchmod(fd,0o600)
            data=payload.encode("utf-8")
            with os.fdopen(fd,"wb",closefd=True) as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            fd=None
            os.replace(tmp,final)
            directory_fd=os.open(self.effect_dir,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        finally:
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
            try:
                if os.path.exists(tmp): os.unlink(tmp)
            except OSError: pass

    def _fault(self,point):
        if self.fault_hook is not None:
            self.fault_hook(point)

    def execute(self,request,attestations,capability,holder_proof,challenge):
        try:
            body=canonical_request(request)
            if not verify_strict_evaluator(self.registry,self.witness,self.replicas,
                                            self.threshold,attestations,self.enrolled_keys):
                return "DENIED"
            digest=hashlib.sha256(body).hexdigest()
            payload=self._effect_payload(request,digest)
            anchored=self.epoch_anchor.read_epoch(self.audience) if self.epoch_anchor is not None else None
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                epoch_row=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(self.audience,)).fetchone()
                if epoch_row is None: return "DENIED"
                epoch=epoch_row[0]
                if anchored is not None:
                    if epoch>anchored: return "DENIED"
                    if epoch<anchored:
                        db.execute("UPDATE session_policy_epoch SET epoch=? WHERE audience=?",(anchored,self.audience))
                        epoch=anchored
                if not verify_session_capability(capability,self.issuer_public_hex,self.issuer,
                    self.audience,request,epoch):
                    return "DENIED"
                c=db.execute("SELECT challenge,epoch,consumed FROM execution_challenges WHERE operation_id=?",
                    (request["operation_id"],)).fetchone()
                if c is None or c[0]!=challenge or c[1]!=epoch:
                    return "DENIED"
                if not verify_holder_proof(holder_proof,capability,request,challenge):
                    return "DENIED"
                existing=db.execute("""SELECT request_hash,effect_payload,status FROM filesystem_effects
                    WHERE operation_id=?""",(request["operation_id"],)).fetchone()
                if existing is not None:
                    if existing[0]!=digest or existing[1]!=payload:
                        return "DENIED"
                    if existing[2]=="COMMITTED":
                        return "ALREADY_APPLIED" if self._verify_file(self._effect_path(request["operation_id"]),payload) else "DENIED"
                    # PENDING was already authorized before any later revocation.
                else:
                    if c[2]!=0: return "DENIED"
                    db.execute("INSERT INTO filesystem_effects VALUES (?,?,?,'PENDING')",
                        (request["operation_id"],digest,payload))
            self._fault("after_pending")
            self._durable_install(request["operation_id"],payload)
            self._fault("after_effect")
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                row=db.execute("SELECT request_hash,effect_payload,status FROM filesystem_effects WHERE operation_id=?",
                    (request["operation_id"],)).fetchone()
                if row is None or row[0]!=digest or row[1]!=payload:
                    return "DENIED"
                if not self._verify_file(self._effect_path(request["operation_id"]),payload):
                    return "DENIED"
                db.execute("UPDATE filesystem_effects SET status='COMMITTED' WHERE operation_id=?",
                    (request["operation_id"],))
                db.execute("UPDATE execution_challenges SET consumed=1 WHERE operation_id=?",
                    (request["operation_id"],))
            return "APPLIED"
        except InjectedEffectCrash:
            raise
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError):
            return "DENIED"

    def recover_pending(self,operation_id):
        if type(operation_id) is not str or not operation_id:
            return "DENIED"
        try:
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                row=db.execute("""SELECT request_hash,effect_payload,status FROM filesystem_effects
                    WHERE operation_id=?""",(operation_id,)).fetchone()
                if row is None: return "NOT_FOUND"
                digest,payload,status=row
                if status=="COMMITTED":
                    return "ALREADY_APPLIED" if self._verify_file(self._effect_path(operation_id),payload) else "DENIED"
            self._durable_install(operation_id,payload)
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                row=db.execute("SELECT request_hash,effect_payload,status FROM filesystem_effects WHERE operation_id=?",
                    (operation_id,)).fetchone()
                if row is None or row[0]!=digest or row[1]!=payload:
                    return "DENIED"
                if not self._verify_file(self._effect_path(operation_id),payload):
                    return "DENIED"
                db.execute("UPDATE filesystem_effects SET status='COMMITTED' WHERE operation_id=?",(operation_id,))
                db.execute("UPDATE execution_challenges SET consumed=1 WHERE operation_id=?",(operation_id,))
            return "RECOVERED"
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError):
            return "DENIED"
