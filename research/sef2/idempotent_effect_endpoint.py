"""Idempotent downstream effect endpoint with signed durable receipts.

The endpoint implements the minimum contract needed to reconcile ambiguous
network outcomes:
- globally stable operation_id idempotency key,
- exact request/effect hash binding,
- durable apply,
- read-after-write query by operation_id,
- signed receipt.

A signed receipt proves what this endpoint committed to its own durable state;
it does not prove the truth of an external physical-world consequence.
"""
import hashlib,json,sqlite3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical

DOMAIN=b"AML-SEF2-IDEMPOTENT-EFFECT-RECEIPT-V1\x00"
SCHEMA="AML-SEF2-IDEMPOTENT-EFFECT-RECEIPT-V1"
ZERO="0"*64

def _digest(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

class IdempotentEffectEndpoint:
    def __init__(self,path,endpoint_id,private_key):
        if type(endpoint_id) is not str or not endpoint_id:
            raise ValueError("invalid endpoint identity")
        self.path=str(path); self.endpoint_id=endpoint_id; self.private_key=private_key
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS effect_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL,head_sha256 TEXT NOT NULL)""")
            db.execute("INSERT OR IGNORE INTO effect_head VALUES (1,0,?)",(ZERO,))
            db.execute("""CREATE TABLE IF NOT EXISTS effects (
                operation_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,
                effect_sha256 TEXT NOT NULL,receipt_json TEXT NOT NULL,
                signature TEXT NOT NULL)""")

    def apply(self,operation_id,request_sha256,effect_sha256):
        if (type(operation_id) is not str or not operation_id or len(operation_id)>128
            or not _digest(request_sha256) or not _digest(effect_sha256)):
            raise ValueError("invalid effect request")
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            row=db.execute("""SELECT request_sha256,effect_sha256,receipt_json,signature
                FROM effects WHERE operation_id=?""",(operation_id,)).fetchone()
            if row:
                if row[0]!=request_sha256 or row[1]!=effect_sha256:
                    raise PermissionError("operation id already bound to different effect")
                return {"payload":json.loads(row[2]),"signature":row[3]}
            sequence,previous=db.execute(
                "SELECT sequence,head_sha256 FROM effect_head WHERE singleton=1").fetchone()
            core={"schema":SCHEMA,"endpoint_id":self.endpoint_id,"sequence":sequence+1,
                "operation_id":operation_id,"request_sha256":request_sha256,
                "effect_sha256":effect_sha256,"previous_receipt_sha256":previous}
            receipt_sha=hashlib.sha256(DOMAIN+canonical(core)).hexdigest()
            payload={**core,"receipt_sha256":receipt_sha}
            signature=self.private_key.sign(DOMAIN+canonical(payload)).hex()
            db.execute("INSERT INTO effects VALUES (?,?,?,?,?)",(operation_id,request_sha256,
                effect_sha256,canonical(payload).decode(),signature))
            db.execute("UPDATE effect_head SET sequence=?,head_sha256=? WHERE singleton=1",
                (sequence+1,receipt_sha))
            return {"payload":payload,"signature":signature}

    def query(self,operation_id):
        if type(operation_id) is not str or not operation_id:
            raise ValueError("invalid operation id")
        with sqlite3.connect(self.path) as db:
            row=db.execute("SELECT receipt_json,signature FROM effects WHERE operation_id=?",
                (operation_id,)).fetchone()
        return None if row is None else {"payload":json.loads(row[0]),"signature":row[1]}

def verify_endpoint_receipt(envelope,public_hex,endpoint_id,operation_id,
        request_sha256,effect_sha256):
    try:
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
            return False
        p=envelope["payload"]
        required={"schema","endpoint_id","sequence","operation_id","request_sha256",
            "effect_sha256","previous_receipt_sha256","receipt_sha256"}
        if type(p) is not dict or set(p)!=required:
            return False
        core={k:p[k] for k in ("schema","endpoint_id","sequence","operation_id",
            "request_sha256","effect_sha256","previous_receipt_sha256")}
        if (p["schema"]!=SCHEMA or p["endpoint_id"]!=endpoint_id
            or type(p["sequence"]) is not int or p["sequence"]<1
            or p["operation_id"]!=operation_id or p["request_sha256"]!=request_sha256
            or p["effect_sha256"]!=effect_sha256
            or not _digest(p["previous_receipt_sha256"])
            or p["receipt_sha256"]!=hashlib.sha256(DOMAIN+canonical(core)).hexdigest()
            or type(public_hex) is not str or len(bytes.fromhex(public_hex))!=32):
            return False
        public=Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        public.verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(p))
        return True
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False
