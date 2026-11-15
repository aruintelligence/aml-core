"""Independent accepted-head anchor for signed execution-consumption receipts.

The anchor pins the execution witness identity/key and monotonically accepts its
signed hash-chain heads. It does not validate the underlying action request;
the broker/client must verify the receipt against the exact request/capability/
challenge before asking this anchor to retain it.
"""
import hashlib,sqlite3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from execution_consumption_witness import (EXECUTION_ENTRY_DOMAIN,
    EXECUTION_RECEIPT_DOMAIN,EXECUTION_RECEIPT_SCHEMA,ZERO_HASH)
from signed_receipt import canonical

class ExecutionReceiptAnchor:
    def __init__(self,path,witness_id,witness_public_hex):
        raw=bytes.fromhex(witness_public_hex)
        if len(raw)!=32 or type(witness_id) is not str or not witness_id:
            raise ValueError("invalid execution receipt anchor enrollment")
        self.path=str(path); self.witness_id=witness_id; self.public_hex=witness_public_hex
        self.public_key=Ed25519PublicKey.from_public_bytes(raw)
        fingerprint=hashlib.sha256(raw).hexdigest()
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS execution_receipt_anchor (
                witness_id TEXT PRIMARY KEY, witness_key_sha256 TEXT NOT NULL,
                sequence INTEGER NOT NULL, head_hash TEXT NOT NULL)""")
            row=db.execute("""SELECT witness_key_sha256,sequence,head_hash
                FROM execution_receipt_anchor WHERE witness_id=?""",(witness_id,)).fetchone()
            if row is None:
                db.execute("INSERT INTO execution_receipt_anchor VALUES (?,?,0,?)",
                    (witness_id,fingerprint,ZERO_HASH))
            elif row[0]!=fingerprint:
                raise ValueError("execution receipt anchor witness key changed")
            db.commit()
    def _validate(self,receipt):
        if type(receipt) is not dict or set(receipt)!={"payload","signature"}:
            raise PermissionError("malformed execution receipt")
        p=receipt["payload"]
        required={"schema","witness_id","sequence","operation_id","request_sha256",
            "capability_sha256","challenge_sha256","previous_hash","entry_hash"}
        if type(p) is not dict or set(p)!=required:
            raise PermissionError("malformed execution receipt payload")
        if (p["schema"]!=EXECUTION_RECEIPT_SCHEMA or p["witness_id"]!=self.witness_id
            or type(p["sequence"]) is not int or p["sequence"]<1):
            raise PermissionError("execution receipt identity/sequence invalid")
        for field in ("request_sha256","capability_sha256","challenge_sha256",
                      "previous_hash","entry_hash"):
            value=p[field]
            if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                raise PermissionError("execution receipt digest invalid")
        sig=bytes.fromhex(receipt["signature"])
        if len(sig)!=64: raise PermissionError("execution receipt signature invalid")
        self.public_key.verify(sig,EXECUTION_RECEIPT_DOMAIN+canonical(p))
        core={k:p[k] for k in ("sequence","operation_id","request_sha256",
            "capability_sha256","challenge_sha256","previous_hash")}
        core={"schema":"AML-SEF2-EXECUTION-CONSUMPTION-ENTRY-V1",**core}
        calculated=hashlib.sha256(EXECUTION_ENTRY_DOMAIN+canonical(core)).hexdigest()
        if calculated!=p["entry_hash"]:
            raise PermissionError("execution receipt entry hash invalid")
        return p
    def accept(self,receipt):
        try:
            p=self._validate(receipt)
            with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                sequence,head=db.execute("""SELECT sequence,head_hash FROM execution_receipt_anchor
                    WHERE witness_id=?""",(self.witness_id,)).fetchone()
                if p["sequence"]==sequence and p["entry_hash"]==head:
                    return "ANCHORED"
                if p["sequence"]!=sequence+1 or p["previous_hash"]!=head:
                    raise PermissionError("execution receipt rollback or fork detected")
                db.execute("""UPDATE execution_receipt_anchor SET sequence=?,head_hash=?
                    WHERE witness_id=?""",(p["sequence"],p["entry_hash"],self.witness_id))
                return "ANCHORED"
        except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,sqlite3.DatabaseError) as exc:
            raise PermissionError("execution receipt anchor rejected receipt") from exc
    def state(self):
        with sqlite3.connect(self.path) as db:
            row=db.execute("""SELECT sequence,head_hash FROM execution_receipt_anchor
                WHERE witness_id=?""",(self.witness_id,)).fetchone()
        return {"sequence":row[0],"head_hash":row[1]}

class RemoteExecutionReceiptAnchor:
    def __init__(self,socket_path,timeout=3):
        self.socket_path=str(socket_path); self.timeout=timeout
    def accept(self,receipt):
        import json,socket,struct
        body=json.dumps({"op":"ANCHOR","receipt":receipt},
            sort_keys=True,separators=(",",":")).encode()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout); conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            size=struct.unpack("!I",self._read(conn,4))[0]
            if size>4096: raise PermissionError("execution anchor response too large")
            response=json.loads(self._read(conn,size))
        if response!={"status":"ANCHORED"}:
            raise PermissionError("execution receipt anchor denied receipt")
        return "ANCHORED"
    @staticmethod
    def _read(conn,size):
        parts=[]
        while size:
            chunk=conn.recv(size)
            if not chunk: raise PermissionError("execution anchor connection ended")
            parts.append(chunk); size-=len(chunk)
        return b"".join(parts)
