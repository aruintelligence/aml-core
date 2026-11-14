"""Signer-side authorization policy and durable one-time challenge ledger.

Synthetic reference component. The policy is deliberately independent of the
broker's decision: it validates an exact action schema and bounded fixture
policy before issuing an action-bound capability.
"""
import sqlite3
from action_capability import issue_capability

class SignerPolicy:
    def __init__(self, database, private_key, issuer, audience, policy_epoch=0):
        self.database=database
        self.private_key=private_key
        self.issuer=issuer
        self.audience=audience
        self.policy_epoch=policy_epoch
        with sqlite3.connect(database) as db:
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

    def authorize(self, request, challenge):
        if not self.validate_request(request):
            raise PermissionError("signer policy denied action")
        if type(challenge) is not str or not 32<=len(challenge)<=128:
            raise PermissionError("invalid signer challenge")
        try:
            with sqlite3.connect(self.database, timeout=5, isolation_level=None) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO signer_challenges VALUES (?,?)",
                           (challenge,request["operation_id"]))
                envelope=issue_capability(self.private_key,self.issuer,self.audience,
                                          request,self.policy_epoch)
                db.commit()
                return envelope
        except sqlite3.IntegrityError as exc:
            raise PermissionError("challenge or operation already authorized") from exc
