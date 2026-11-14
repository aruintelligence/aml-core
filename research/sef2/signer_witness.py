"""Monotonic signer-intent witness with signed, hash-linked append receipts."""
import hashlib
import json
import socket
import sqlite3
import struct
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical

ENTRY_DOMAIN=b"AML-SEF2-WITNESS-ENTRY-V1\x00"
RECEIPT_DOMAIN=b"AML-SEF2-WITNESS-RECEIPT-V1\x00"
ZERO_HASH="0"*64

class SignerWitness:
    def __init__(self,database,private_key=None):
        self.database=str(database)
        self.private_key=private_key
        with sqlite3.connect(self.database) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS consumed_intents (
                sequence INTEGER PRIMARY KEY, challenge TEXT UNIQUE NOT NULL,
                operation_id TEXT UNIQUE NOT NULL, request_sha256 TEXT NOT NULL,
                previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL, signature TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS witness_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL, head_hash TEXT NOT NULL)""")
            db.execute("INSERT OR IGNORE INTO witness_head VALUES (1,0,?)",(ZERO_HASH,))
            db.commit()

    def consume(self,challenge,operation_id,request):
        if (type(challenge) is not str or not 32<=len(challenge)<=128
            or type(operation_id) is not str or not operation_id):
            raise PermissionError("invalid witness intent")
        if (type(request) is not dict or set(request)!={"operation_id","action","target","amount_cents"}
            or request.get("operation_id")!=operation_id or request.get("action")!="payment:simulate"
            or request.get("target")!="fixture:merchant-a" or type(request.get("amount_cents")) is not int
            or not 1<=request["amount_cents"]<=10000):
            raise PermissionError("invalid witness request scope")
        digest=hashlib.sha256(canonical(request)).hexdigest()
        try:
            with sqlite3.connect(self.database,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                sequence,previous=db.execute("SELECT sequence,head_hash FROM witness_head WHERE singleton=1").fetchone()
                core={"schema":"AML-SEF2-WITNESS-ENTRY-V1","sequence":sequence+1,
                      "challenge":challenge,"operation_id":operation_id,
                      "request_sha256":digest,"previous_hash":previous}
                entry_hash=hashlib.sha256(ENTRY_DOMAIN+canonical(core)).hexdigest()
                payload={**core,"entry_hash":entry_hash}
                signature=(self.private_key.sign(RECEIPT_DOMAIN+canonical(payload)).hex()
                           if self.private_key is not None else "")
                db.execute("INSERT INTO consumed_intents VALUES (?,?,?,?,?,?,?)",
                           (sequence+1,challenge,operation_id,digest,previous,entry_hash,signature))
                db.execute("UPDATE witness_head SET sequence=?,head_hash=? WHERE singleton=1",
                           (sequence+1,entry_hash))
                db.commit()
                return {"payload":payload,"signature":signature}
        except sqlite3.IntegrityError as exc:
            raise PermissionError("witness rejected replay or duplicate operation") from exc

class RemoteSignerWitness:
    """Unix socket client with pinned Ed25519 verification of append receipts."""
    def __init__(self,socket_path,trusted_public_hex,checkpoint_database,timeout=3):
        self.socket_path=str(socket_path)
        self.timeout=timeout
        self.checkpoint_database=str(checkpoint_database)
        try: self.public_key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_hex))
        except (ValueError,TypeError) as exc: raise ValueError("invalid witness public key pin") from exc
        with sqlite3.connect(self.checkpoint_database) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS witness_checkpoint (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL, head_hash TEXT NOT NULL)""")
            db.execute("INSERT OR IGNORE INTO witness_checkpoint VALUES (1,0,?)",(ZERO_HASH,))
            db.commit()

    def consume(self,challenge,operation_id,request):
        body=json.dumps({"challenge":challenge,"operation_id":operation_id,
            "request":request},sort_keys=True,separators=(",",":")).encode()
        if len(body)>65536: raise PermissionError("witness request too large")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout)
            conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            size=struct.unpack("!I",self._read_exact(conn,4))[0]
            if size>8192: raise PermissionError("invalid witness response")
            response=json.loads(self._read_exact(conn,size))
        if type(response) is not dict or set(response)!={"status","receipt"} or response["status"]!="CONSUMED":
            raise PermissionError("independent witness denied intent")
        receipt=response["receipt"]
        if type(receipt) is not dict or set(receipt)!={"payload","signature"}:
            raise PermissionError("malformed witness receipt")
        p=receipt["payload"]
        if type(p) is not dict or set(p)!={"schema","sequence","challenge","operation_id","request_sha256","previous_hash","entry_hash"}:
            raise PermissionError("malformed witness receipt payload")
        digest=hashlib.sha256(canonical(request)).hexdigest()
        core={k:p[k] for k in ("schema","sequence","challenge","operation_id","request_sha256","previous_hash")}
        expected=hashlib.sha256(ENTRY_DOMAIN+canonical(core)).hexdigest()
        if (p["schema"]!="AML-SEF2-WITNESS-ENTRY-V1" or type(p["sequence"]) is not int or p["sequence"]<1
            or p["challenge"]!=challenge or p["operation_id"]!=operation_id
            or p["request_sha256"]!=digest or p["entry_hash"]!=expected
            or type(receipt["signature"]) is not str or len(receipt["signature"])!=128):
            raise PermissionError("witness receipt scope or hash invalid")
        try: self.public_key.verify(bytes.fromhex(receipt["signature"]),RECEIPT_DOMAIN+canonical(p))
        except (ValueError,InvalidSignature) as exc: raise PermissionError("witness receipt signature invalid") from exc
        # The signer retains its last accepted witness head independently of the witness DB.
        try:
            with sqlite3.connect(self.checkpoint_database,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                sequence,head=db.execute("SELECT sequence,head_hash FROM witness_checkpoint WHERE singleton=1").fetchone()
                if p["sequence"]!=sequence+1 or p["previous_hash"]!=head:
                    raise PermissionError("witness rollback or fork detected")
                db.execute("UPDATE witness_checkpoint SET sequence=?,head_hash=? WHERE singleton=1",
                           (p["sequence"],p["entry_hash"]))
                db.commit()
        except sqlite3.DatabaseError as exc:
            raise PermissionError("signer checkpoint unavailable") from exc
        return receipt

    @staticmethod
    def _read_exact(conn,size):
        chunks=[]
        while size:
            chunk=conn.recv(size)
            if not chunk: raise PermissionError("witness connection ended")
            chunks.append(chunk); size-=len(chunk)
        return b"".join(chunks)
