"""Capability broker requiring holder proof of possession for a fresh challenge."""
import hashlib,secrets,sqlite3
from gated_action_broker import canonical_request
from strict_evaluator import verify_strict_evaluator
from session_capability import verify_session_capability,verify_holder_proof

class SessionCapabilityBroker:
    def __init__(self,path,registry,witness,replicas,threshold,enrolled_keys,
                 issuer,issuer_public_hex,audience,broker_instance_id=None,broker_challenge_private=None,
                 epoch_anchor=None):
        if type(issuer) is not str or not issuer or type(audience) is not str or not audience:
            raise ValueError("invalid issuer or audience")
        if type(issuer_public_hex) is not str or len(bytes.fromhex(issuer_public_hex))!=32:
            raise ValueError("invalid issuer key")
        self.path=str(path); self.registry=registry; self.witness=witness
        self.replicas=replicas; self.threshold=threshold; self.enrolled_keys=enrolled_keys
        self.issuer=issuer; self.issuer_public_hex=issuer_public_hex; self.audience=audience
        self.broker_instance_id=broker_instance_id; self.broker_challenge_private=broker_challenge_private
        self.epoch_anchor=epoch_anchor
        if (broker_instance_id is None)!=(broker_challenge_private is None):
            raise ValueError("broker challenge identity configuration must be complete")
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS session_effects (operation_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS session_policy_epoch (audience TEXT PRIMARY KEY,epoch INTEGER NOT NULL)")
            db.execute("INSERT OR IGNORE INTO session_policy_epoch VALUES (?,0)",(audience,))
            db.execute("""CREATE TABLE IF NOT EXISTS execution_challenges (
                operation_id TEXT PRIMARY KEY,challenge TEXT UNIQUE NOT NULL,
                epoch INTEGER NOT NULL,consumed INTEGER NOT NULL CHECK(consumed IN (0,1)))""")
            local_epoch=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(audience,)).fetchone()[0]
        if self.epoch_anchor is not None:
            try:
                anchored=self.epoch_anchor.read_epoch(audience)
            except ValueError:
                anchored=self.epoch_anchor.initialize(audience,local_epoch)
            if anchored<local_epoch:
                raise ValueError("session revocation anchor is behind broker state")
            if anchored>local_epoch:
                with sqlite3.connect(self.path,timeout=10) as db:
                    db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                    db.execute("UPDATE session_policy_epoch SET epoch=? WHERE audience=?",(anchored,audience))
    def current_epoch(self):
        anchored=self.epoch_anchor.read_epoch(self.audience) if self.epoch_anchor is not None else None
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(self.audience,)).fetchone()
            if row is None: raise ValueError("missing policy epoch")
            local=row[0]
            if anchored is None: return local
            if local>anchored: raise PermissionError("local session epoch is ahead of independent anchor")
            if local<anchored:
                db.execute("UPDATE session_policy_epoch SET epoch=? WHERE audience=?",(anchored,self.audience))
            return anchored
    def revoke_all(self):
        anchored=self.epoch_anchor.read_epoch(self.audience) if self.epoch_anchor is not None else None
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            local=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(self.audience,)).fetchone()[0]
            if anchored is not None:
                if local>anchored: raise PermissionError("unreconciled session revocation")
                if local<anchored:
                    db.execute("UPDATE session_policy_epoch SET epoch=? WHERE audience=?",(anchored,self.audience))
                    local=anchored
            new_epoch=local+1
            db.execute("UPDATE session_policy_epoch SET epoch=? WHERE audience=?",(new_epoch,self.audience))
        if self.epoch_anchor is not None and not self.epoch_anchor.compare_and_set(self.audience,anchored,new_epoch):
            raise RuntimeError("session revocation anchor update failed; broker is fail-closed")
        return new_epoch

    def reconcile_revocation_anchor(self):
        if self.epoch_anchor is None:
            return self.current_epoch()
        anchored=self.epoch_anchor.read_epoch(self.audience)
        with sqlite3.connect(self.path) as db:
            local=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(self.audience,)).fetchone()[0]
        if local==anchored: return anchored
        if local==anchored+1 and self.epoch_anchor.compare_and_set(self.audience,anchored,local):
            return local
        raise RuntimeError("session revocation state cannot be reconciled safely")
    def issue_authenticated_execution_challenge(self,request,capability):
        if self.broker_instance_id is None:
            raise PermissionError("broker challenge signing is not configured")
        epoch=self.current_epoch()
        if not verify_session_capability(capability,self.issuer_public_hex,self.issuer,
            self.audience,request,epoch):
            raise PermissionError("cannot authenticate challenge for invalid capability")
        challenge=self.issue_execution_challenge(request["operation_id"])
        from authenticated_execution_challenge import make_execution_challenge
        return make_execution_challenge(self.broker_challenge_private,self.broker_instance_id,
            self.audience,request,capability,epoch,challenge)

    def issue_execution_challenge(self,operation_id):
        if type(operation_id) is not str or not operation_id or len(operation_id)>128:
            raise ValueError("invalid operation id")
        anchored=self.epoch_anchor.read_epoch(self.audience) if self.epoch_anchor is not None else None
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            epoch=db.execute("SELECT epoch FROM session_policy_epoch WHERE audience=?",(self.audience,)).fetchone()[0]
            if anchored is not None:
                if epoch>anchored: raise PermissionError("session revocation anchor not reconciled")
                if epoch<anchored:
                    db.execute("UPDATE session_policy_epoch SET epoch=? WHERE audience=?",(anchored,self.audience))
                    epoch=anchored
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
