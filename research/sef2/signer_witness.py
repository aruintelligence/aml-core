"""Independent monotonic signer-intent witness (synthetic local reference).

Deploy this database and process under a separately administered identity. Merely
using a second file on the signer host does not provide independent rollback
protection. Append-before-issue deliberately fails closed on ambiguous crashes.
"""
import hashlib
import sqlite3
from gated_action_broker import canonical_request

class SignerWitness:
    def __init__(self,database):
        self.database=str(database)
        with sqlite3.connect(self.database) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS consumed_intents (
                challenge TEXT PRIMARY KEY,
                operation_id TEXT UNIQUE NOT NULL,
                request_sha256 TEXT NOT NULL
            )""")
            db.commit()

    def consume(self,challenge,operation_id,request):
        if (type(challenge) is not str or not 32<=len(challenge)<=128
            or type(operation_id) is not str or not operation_id):
            raise PermissionError("invalid witness intent")
        digest=hashlib.sha256(canonical_request(request)).hexdigest()
        try:
            with sqlite3.connect(self.database,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO consumed_intents VALUES (?,?,?)",
                           (challenge,operation_id,digest))
                db.commit()
        except sqlite3.IntegrityError as exc:
            raise PermissionError("witness rejected replay or duplicate operation") from exc
