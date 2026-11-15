"""Signer-side issuance policy for holder-bound session capabilities.

The holder public key is an enrollment input pinned in durable signer state,
not a per-request caller choice. Broker intent, action policy, one-use
challenge/operation consumption and optional independent witness are enforced
before the session capability is issued.
"""
import sqlite3
from broker_intent import verify_intent
from signer_policy import SignerPolicy
from session_capability import issue_session_capability

class SessionSignerPolicy:
    def __init__(self,database,private_key,issuer,audience,broker_id,broker_public_hex,
                 holder_public_hex,policy_epoch=0,signer_witness=None):
        if (type(broker_id) is not str or not broker_id
            or type(audience) is not str or not audience
            or type(broker_public_hex) is not str
            or type(holder_public_hex) is not str):
            raise ValueError("invalid session signer enrollment")
        if len(bytes.fromhex(broker_public_hex))!=32 or len(bytes.fromhex(holder_public_hex))!=32:
            raise ValueError("invalid enrolled public key")
        if type(policy_epoch) is not int or policy_epoch<0:
            raise ValueError("invalid policy epoch")
        self.database=str(database); self.private_key=private_key; self.issuer=issuer
        self.audience=audience; self.broker_id=broker_id
        self.broker_public_hex=broker_public_hex
        self.holder_public_hex=holder_public_hex
        self.policy_epoch=policy_epoch; self.signer_witness=signer_witness
        with sqlite3.connect(self.database,timeout=5) as db:
            db.execute("PRAGMA synchronous=FULL")
            # Deliberately share the legacy signer ledger so one operation cannot
            # obtain both a bearer and session capability after consumption.
            db.execute("""CREATE TABLE IF NOT EXISTS signer_challenges (
                challenge TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS session_holder_enrollment (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                holder_public_hex TEXT NOT NULL)""")
            row=db.execute("SELECT holder_public_hex FROM session_holder_enrollment WHERE singleton=1").fetchone()
            if row is None:
                db.execute("INSERT INTO session_holder_enrollment VALUES (1,?)",(holder_public_hex,))
            elif row[0]!=holder_public_hex:
                raise ValueError("session holder enrollment mismatch")
            db.commit()

    def authorize(self,request,intent):
        if not SignerPolicy.validate_request(request):
            raise PermissionError("signer policy denied action")
        if not verify_intent(intent,self.broker_public_hex,self.broker_id,self.audience,request):
            raise PermissionError("broker intent signature or scope invalid")
        challenge=intent["payload"]["challenge"]
        if self.signer_witness is not None:
            self.signer_witness.consume(challenge,request["operation_id"],request)
        try:
            with sqlite3.connect(self.database,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                enrollment=db.execute("SELECT holder_public_hex FROM session_holder_enrollment WHERE singleton=1").fetchone()
                if enrollment is None or enrollment[0]!=self.holder_public_hex:
                    raise PermissionError("holder enrollment unavailable or changed")
                db.execute("INSERT INTO signer_challenges VALUES (?,?)",
                    (challenge,request["operation_id"]))
                capability=issue_session_capability(self.private_key,self.issuer,
                    self.audience,request,self.policy_epoch,self.holder_public_hex)
                db.commit()
                return capability
        except sqlite3.IntegrityError as exc:
            raise PermissionError("challenge or operation already authorized") from exc
