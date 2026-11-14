"""Signer-side policy for broker-authenticated, one-use action intent.

Synthetic reference only. Broker identity enrollment is an operator trust input;
this module does not implement remote key discovery or key rotation.
"""
import sqlite3
from action_capability import issue_capability
from broker_intent import verify_intent

class SignerPolicy:
    def __init__(self,database,private_key,issuer,audience,broker_id,broker_public_hex,policy_epoch=0,signer_witness=None):
        if (type(broker_id) is not str or not broker_id or type(audience) is not str or not audience
            or type(broker_public_hex) is not str or len(bytes.fromhex(broker_public_hex))!=32):
            raise ValueError("invalid enrolled broker identity")
        self.database=database
        self.private_key=private_key
        self.issuer=issuer
        self.audience=audience
        self.broker_id=broker_id
        self.broker_public_hex=broker_public_hex
        self.policy_epoch=policy_epoch
        self.signer_witness=signer_witness
        with sqlite3.connect(database) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS signer_challenges (challenge TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL)")
            db.commit()

    @staticmethod
    def validate_request(request):
        if type(request) is not dict or set(request)!={"operation_id","action","target","amount_cents"}:
            return False
        if (type(request["operation_id"]) is not str or not request["operation_id"]
            or len(request["operation_id"])>128
            or request["action"]!="payment:simulate"
            or request["target"]!="fixture:merchant-a"
            or type(request["amount_cents"]) is not int
            or not 1<=request["amount_cents"]<=500):
            return False
        return True

    def authorize(self,request,intent):
        if not self.validate_request(request):
            raise PermissionError("signer policy denied action")
        if not verify_intent(intent,self.broker_public_hex,self.broker_id,self.audience,request):
            raise PermissionError("broker intent signature or scope invalid")
        challenge=intent["payload"]["challenge"]
        # Append to independently administered monotonic state before local issuance.
        # A crash after this point can strand an operation, but cannot safely replay it.
        if self.signer_witness is not None:
            self.signer_witness.consume(challenge,request["operation_id"],request)
        try:
            with sqlite3.connect(self.database,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO signer_challenges VALUES (?,?)",(challenge,request["operation_id"]))
                envelope=issue_capability(self.private_key,self.issuer,self.audience,request,self.policy_epoch)
                db.commit()
                return envelope
        except sqlite3.IntegrityError as exc:
            raise PermissionError("challenge or operation already authorized") from exc
