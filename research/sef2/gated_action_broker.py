"""Synthetic action broker with independent pre-execution authorization gate.

A model cannot invoke the protected effect through this API without passing
the evaluator gate. This is a reference-monitor *prototype*, not a host-level
sandbox: callers with direct filesystem or effect access can bypass it.
"""
import hashlib
import json
import sqlite3
from strict_evaluator import verify_strict_evaluator

def canonical_request(request):
    if (type(request) is not dict or set(request)!={"operation_id","action","target","amount_cents"}
        or type(request["operation_id"]) is not str or not request["operation_id"]
        or request["action"]!="payment:simulate" or request["target"]!="fixture:merchant-a"
        or type(request["amount_cents"]) is not int
        or not 1<=request["amount_cents"]<=10000):
        raise ValueError("unsupported or malformed action")
    return json.dumps(request,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

class GatedBroker:
    def __init__(self,path,registry,witness,replicas,threshold,enrolled_keys):
        self.path=str(path)
        self.registry=registry
        self.witness=witness
        self.replicas=replicas
        self.threshold=threshold
        self.enrolled_keys=enrolled_keys
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS effects (operation_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL)")
    def execute(self,request,attestations):
        if type(self) is not GatedBroker:
            return "DENIED"
        try:
            body=canonical_request(request)
            if not verify_strict_evaluator(self.registry,self.witness,self.replicas,
                                            self.threshold,attestations,self.enrolled_keys):
                return "DENIED"
            digest=hashlib.sha256(body).hexdigest()
            with sqlite3.connect(self.path,timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                row=db.execute("SELECT request_hash FROM effects WHERE operation_id=?",(request["operation_id"],)).fetchone()
                if row is not None:
                    return "ALREADY_APPLIED" if row[0]==digest else "DENIED"
                # The only synthetic effect is a durable row in the broker's
                # private database, written in the same transaction.
                db.execute("INSERT INTO effects VALUES (?,?)",(request["operation_id"],digest))
            return "APPLIED"
        except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError):
            return "DENIED"
