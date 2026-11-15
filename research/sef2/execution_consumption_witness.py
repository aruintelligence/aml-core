"""Independent single-use execution consumption witness with signed chain support.

The witness records an authorized operation before the broker commits its local
synthetic effect. If the broker crashes after witness consumption but before
local commit, the operation is intentionally stranded: safety over availability.
Rollback resistance requires the witness state and/or an independently retained
accepted receipt head to survive broker/witness rollback.
"""
import hashlib,sqlite3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from gated_action_broker import canonical_request
from session_capability import capability_digest

ZERO_HASH="0"*64
EXECUTION_ENTRY_DOMAIN=b"AML-SEF2-EXECUTION-CONSUMPTION-ENTRY-V1\x00"
EXECUTION_RECEIPT_DOMAIN=b"AML-SEF2-EXECUTION-CONSUMPTION-RECEIPT-V2\x00"
EXECUTION_RECEIPT_SCHEMA="AML-SEF2-EXECUTION-CONSUMPTION-RECEIPT-V2"

class ExecutionConsumptionWitness:
    def __init__(self,path):
        self.path=str(path)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS execution_consumption (
                operation_id TEXT PRIMARY KEY,
                request_sha256 TEXT NOT NULL,
                capability_sha256 TEXT NOT NULL,
                challenge_sha256 TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS execution_consumption_log (
                sequence INTEGER PRIMARY KEY,
                operation_id TEXT UNIQUE NOT NULL,
                request_sha256 TEXT NOT NULL,
                capability_sha256 TEXT NOT NULL,
                challenge_sha256 TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE)""")
            db.execute("""CREATE TABLE IF NOT EXISTS execution_consumption_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL, head_hash TEXT NOT NULL)""")
            db.execute("INSERT OR IGNORE INTO execution_consumption_head VALUES (1,0,?)",(ZERO_HASH,))
            count=db.execute("SELECT COUNT(*) FROM execution_consumption").fetchone()[0]
            logged=db.execute("SELECT COUNT(*) FROM execution_consumption_log").fetchone()[0]
            if count!=logged:
                raise ValueError("execution witness legacy/incomplete log requires reconciliation")
            db.commit()
    @staticmethod
    def _record(request,capability,challenge):
        operation=request.get("operation_id") if type(request) is dict else None
        if type(operation) is not str or not operation or type(challenge) is not str or not challenge:
            raise PermissionError("invalid execution consumption scope")
        return (operation,
            hashlib.sha256(canonical_request(request)).hexdigest(),
            capability_digest(capability),
            hashlib.sha256(challenge.encode()).hexdigest())
    @staticmethod
    def _entry(sequence,previous,record):
        core={"schema":"AML-SEF2-EXECUTION-CONSUMPTION-ENTRY-V1",
            "sequence":sequence,"operation_id":record[0],"request_sha256":record[1],
            "capability_sha256":record[2],"challenge_sha256":record[3],
            "previous_hash":previous}
        entry_hash=hashlib.sha256(EXECUTION_ENTRY_DOMAIN+canonical(core)).hexdigest()
        return {**core,"entry_hash":entry_hash}
    def consume_record(self,request,capability,challenge):
        record=self._record(request,capability,challenge)
        try:
            with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                sequence,previous=db.execute(
                    "SELECT sequence,head_hash FROM execution_consumption_head WHERE singleton=1").fetchone()
                entry=self._entry(sequence+1,previous,record)
                db.execute("INSERT INTO execution_consumption VALUES (?,?,?,?)",record)
                db.execute("""INSERT INTO execution_consumption_log
                    VALUES (?,?,?,?,?,?,?)""",
                    (entry["sequence"],record[0],record[1],record[2],record[3],
                     previous,entry["entry_hash"]))
                db.execute("UPDATE execution_consumption_head SET sequence=?,head_hash=? WHERE singleton=1",
                    (entry["sequence"],entry["entry_hash"]))
                return entry
        except sqlite3.IntegrityError as exc:
            raise PermissionError("operation already crossed execution boundary") from exc
    def consume(self,request,capability,challenge):
        self.consume_record(request,capability,challenge)
        return "CONSUMED"
    def lookup(self,operation_id):
        with sqlite3.connect(self.path) as db:
            row=db.execute("""SELECT request_sha256,capability_sha256,challenge_sha256
                FROM execution_consumption WHERE operation_id=?""",(operation_id,)).fetchone()
        if row is None: return None
        return {"operation_id":operation_id,"request_sha256":row[0],
            "capability_sha256":row[1],"challenge_sha256":row[2]}
    def head(self):
        with sqlite3.connect(self.path) as db:
            sequence,head=db.execute(
                "SELECT sequence,head_hash FROM execution_consumption_head WHERE singleton=1").fetchone()
        return {"sequence":sequence,"head_hash":head}

class RemoteExecutionConsumptionWitness:
    """Unix-socket client for separately owned execution consumption state."""
    def __init__(self,socket_path,timeout=3):
        self.socket_path=str(socket_path); self.timeout=timeout
    def consume(self,request,capability,challenge):
        import json,socket,struct
        body=json.dumps({"op":"CONSUME","request":request,"capability":capability,
            "challenge":challenge},sort_keys=True,separators=(",",":")).encode()
        if len(body)>131072: raise PermissionError("execution witness request too large")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout); conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            size=struct.unpack("!I",self._read(conn,4))[0]
            if size>4096: raise PermissionError("execution witness response too large")
            response=json.loads(self._read(conn,size))
        if response!={"status":"CONSUMED"}:
            raise PermissionError("independent execution witness denied operation")
        return "CONSUMED"
    @staticmethod
    def _read(conn,size):
        parts=[]
        while size:
            chunk=conn.recv(size)
            if not chunk: raise PermissionError("execution witness connection ended")
            parts.append(chunk); size-=len(chunk)
        return b"".join(parts)

def make_consumption_receipt(private_key,witness_id,request,capability,challenge,
                             sequence=1,previous_hash=ZERO_HASH):
    if type(witness_id) is not str or not witness_id:
        raise ValueError("invalid execution witness identity")
    if type(sequence) is not int or sequence<1 or type(previous_hash) is not str or len(previous_hash)!=64:
        raise ValueError("invalid execution witness chain position")
    record=ExecutionConsumptionWitness._record(request,capability,challenge)
    entry=ExecutionConsumptionWitness._entry(sequence,previous_hash,record)
    payload={"schema":EXECUTION_RECEIPT_SCHEMA,"witness_id":witness_id,**entry}
    return {"payload":payload,
        "signature":private_key.sign(EXECUTION_RECEIPT_DOMAIN+canonical(payload)).hex()}

def make_consumption_receipt_from_entry(private_key,witness_id,entry):
    if type(witness_id) is not str or not witness_id:
        raise ValueError("invalid execution witness identity")
    required={"schema","sequence","operation_id","request_sha256","capability_sha256",
              "challenge_sha256","previous_hash","entry_hash"}
    if type(entry) is not dict or set(entry)!=required:
        raise ValueError("invalid execution consumption entry")
    payload={"schema":EXECUTION_RECEIPT_SCHEMA,"witness_id":witness_id,**entry}
    return {"payload":payload,
        "signature":private_key.sign(EXECUTION_RECEIPT_DOMAIN+canonical(payload)).hex()}

def verify_consumption_receipt(receipt,public_hex,witness_id,request,capability,challenge):
    try:
        if type(receipt) is not dict or set(receipt)!={"payload","signature"}:
            return False
        p=receipt["payload"]
        required={"schema","witness_id","sequence","operation_id","request_sha256",
            "capability_sha256","challenge_sha256","previous_hash","entry_hash"}
        if type(p) is not dict or set(p)!=required:
            return False
        if (p["schema"]!=EXECUTION_RECEIPT_SCHEMA or p["witness_id"]!=witness_id
            or type(p["sequence"]) is not int or p["sequence"]<1
            or type(p["previous_hash"]) is not str or len(p["previous_hash"])!=64):
            return False
        record=ExecutionConsumptionWitness._record(request,capability,challenge)
        entry=ExecutionConsumptionWitness._entry(p["sequence"],p["previous_hash"],record)
        expected={"schema":EXECUTION_RECEIPT_SCHEMA,"witness_id":witness_id,**entry}
        if p!=expected:
            return False
        raw=bytes.fromhex(public_hex); sig=bytes.fromhex(receipt["signature"])
        if len(raw)!=32 or len(sig)!=64:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(sig,
            EXECUTION_RECEIPT_DOMAIN+canonical(p))
        return True
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError):
        return False

class SignedRemoteExecutionConsumptionWitness(RemoteExecutionConsumptionWitness):
    """Remote witness requiring a pinned signed receipt and optional retained head."""
    def __init__(self,socket_path,witness_id,public_hex,checkpoint_database=None,timeout=3):
        super().__init__(socket_path,timeout)
        raw=bytes.fromhex(public_hex)
        if len(raw)!=32 or type(witness_id) is not str or not witness_id:
            raise ValueError("invalid execution witness pin")
        self.witness_id=witness_id; self.public_hex=public_hex
        self.checkpoint_database=None if checkpoint_database is None else str(checkpoint_database)
        if self.checkpoint_database is not None:
            with sqlite3.connect(self.checkpoint_database) as db:
                db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
                db.execute("""CREATE TABLE IF NOT EXISTS execution_witness_checkpoint (
                    witness_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, head_hash TEXT NOT NULL)""")
                db.execute("INSERT OR IGNORE INTO execution_witness_checkpoint VALUES (?,0,?)",
                    (self.witness_id,ZERO_HASH))
                db.commit()
    def _retain(self,receipt):
        if self.checkpoint_database is None:
            return
        p=receipt["payload"]
        with sqlite3.connect(self.checkpoint_database,timeout=5,isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            row=db.execute("""SELECT sequence,head_hash FROM execution_witness_checkpoint
                WHERE witness_id=?""",(self.witness_id,)).fetchone()
            if row is None:
                raise PermissionError("execution witness checkpoint missing")
            sequence,head=row
            if p["sequence"]!=sequence+1 or p["previous_hash"]!=head:
                raise PermissionError("execution witness rollback or fork detected")
            db.execute("""UPDATE execution_witness_checkpoint SET sequence=?,head_hash=?
                WHERE witness_id=?""",(p["sequence"],p["entry_hash"],self.witness_id))
    def checkpoint(self):
        if self.checkpoint_database is None:
            return None
        with sqlite3.connect(self.checkpoint_database) as db:
            row=db.execute("""SELECT sequence,head_hash FROM execution_witness_checkpoint
                WHERE witness_id=?""",(self.witness_id,)).fetchone()
        return {"sequence":row[0],"head_hash":row[1]} if row else None
    def consume(self,request,capability,challenge):
        import json,socket,struct
        body=json.dumps({"op":"CONSUME","request":request,"capability":capability,
            "challenge":challenge},sort_keys=True,separators=(",",":")).encode()
        if len(body)>131072: raise PermissionError("execution witness request too large")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout); conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            size=struct.unpack("!I",self._read(conn,4))[0]
            if size>16384: raise PermissionError("execution witness response too large")
            response=json.loads(self._read(conn,size))
        if (type(response) is not dict or set(response)!={"status","receipt"}
            or response["status"]!="CONSUMED"
            or not verify_consumption_receipt(response["receipt"],self.public_hex,
                self.witness_id,request,capability,challenge)):
            raise PermissionError("signed execution witness receipt invalid")
        self._retain(response["receipt"])
        return response["receipt"]
