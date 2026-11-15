"""Full-authorization-bound execution consumption witness (V3).

V2 consumption receipts bind request, capability and broker challenge. V3 also
binds the exact holder proof and evaluator authorization verified by the effect
executor, preventing audit-time evidence splicing between distinct valid
authorization instances.
"""
import hashlib,json,socket,sqlite3,struct
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from gated_action_broker import canonical_request
from session_capability import capability_digest

ZERO_HASH="0"*64
ENTRY_DOMAIN=b"AML-SEF2-AUTHORIZED-EXECUTION-CONSUMPTION-ENTRY-V3\x00"
RECEIPT_DOMAIN=b"AML-SEF2-AUTHORIZED-EXECUTION-CONSUMPTION-RECEIPT-V3\x00"
RECEIPT_SCHEMA="AML-SEF2-AUTHORIZED-EXECUTION-CONSUMPTION-RECEIPT-V3"

def evidence_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def authorization_record(request,capability,challenge,holder_proof,evaluator_authorization):
    operation=request.get("operation_id") if type(request) is dict else None
    if type(operation) is not str or not operation or type(challenge) is not str or not challenge:
        raise PermissionError("invalid authorized execution scope")
    return (operation,
        hashlib.sha256(canonical_request(request)).hexdigest(),
        capability_digest(capability),
        hashlib.sha256(challenge.encode()).hexdigest(),
        evidence_digest(holder_proof),
        evidence_digest(evaluator_authorization))

def make_entry(sequence,previous_hash,record):
    if type(sequence) is not int or sequence<1 or type(previous_hash) is not str or len(previous_hash)!=64:
        raise ValueError("invalid authorized execution chain position")
    core={"schema":"AML-SEF2-AUTHORIZED-EXECUTION-CONSUMPTION-ENTRY-V3",
        "sequence":sequence,"operation_id":record[0],"request_sha256":record[1],
        "capability_sha256":record[2],"challenge_sha256":record[3],
        "holder_proof_sha256":record[4],
        "evaluator_authorization_sha256":record[5],
        "previous_hash":previous_hash}
    entry_hash=hashlib.sha256(ENTRY_DOMAIN+canonical(core)).hexdigest()
    return {**core,"entry_hash":entry_hash}

class AuthorizedExecutionConsumptionWitness:
    def __init__(self,path):
        self.path=str(path)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS authorized_execution_consumption (
                operation_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,
                capability_sha256 TEXT NOT NULL,challenge_sha256 TEXT NOT NULL,
                holder_proof_sha256 TEXT NOT NULL,
                evaluator_authorization_sha256 TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS authorized_execution_consumption_log (
                sequence INTEGER PRIMARY KEY,operation_id TEXT UNIQUE NOT NULL,
                request_sha256 TEXT NOT NULL,capability_sha256 TEXT NOT NULL,
                challenge_sha256 TEXT NOT NULL,holder_proof_sha256 TEXT NOT NULL,
                evaluator_authorization_sha256 TEXT NOT NULL,
                previous_hash TEXT NOT NULL,entry_hash TEXT NOT NULL UNIQUE)""")
            db.execute("""CREATE TABLE IF NOT EXISTS authorized_execution_consumption_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL,head_hash TEXT NOT NULL)""")
            db.execute("INSERT OR IGNORE INTO authorized_execution_consumption_head VALUES (1,0,?)",(ZERO_HASH,))
            count=db.execute("SELECT COUNT(*) FROM authorized_execution_consumption").fetchone()[0]
            logged=db.execute("SELECT COUNT(*) FROM authorized_execution_consumption_log").fetchone()[0]
            if count!=logged:
                raise ValueError("authorized execution witness incomplete log requires reconciliation")
    def consume_record(self,request,capability,challenge,holder_proof,evaluator_authorization):
        record=authorization_record(request,capability,challenge,holder_proof,evaluator_authorization)
        try:
            with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                sequence,previous=db.execute(
                    "SELECT sequence,head_hash FROM authorized_execution_consumption_head WHERE singleton=1").fetchone()
                entry=make_entry(sequence+1,previous,record)
                db.execute("INSERT INTO authorized_execution_consumption VALUES (?,?,?,?,?,?)",record)
                db.execute("INSERT INTO authorized_execution_consumption_log VALUES (?,?,?,?,?,?,?,?,?)",
                    (entry["sequence"],*record,previous,entry["entry_hash"]))
                db.execute("""UPDATE authorized_execution_consumption_head
                    SET sequence=?,head_hash=? WHERE singleton=1""",
                    (entry["sequence"],entry["entry_hash"]))
                return entry
        except sqlite3.IntegrityError as exc:
            raise PermissionError("operation already crossed full authorization execution boundary") from exc
    def head(self):
        with sqlite3.connect(self.path) as db:
            sequence,head=db.execute(
                "SELECT sequence,head_hash FROM authorized_execution_consumption_head WHERE singleton=1").fetchone()
        return {"sequence":sequence,"head_hash":head}

def make_authorized_consumption_receipt(private_key,witness_id,entry):
    required={"schema","sequence","operation_id","request_sha256","capability_sha256",
        "challenge_sha256","holder_proof_sha256","evaluator_authorization_sha256",
        "previous_hash","entry_hash"}
    if type(witness_id) is not str or not witness_id or type(entry) is not dict or set(entry)!=required:
        raise ValueError("invalid authorized execution entry")
    payload={"schema":RECEIPT_SCHEMA,"witness_id":witness_id,
        **{k:v for k,v in entry.items() if k!="schema"}}
    return {"payload":payload,
        "signature":private_key.sign(RECEIPT_DOMAIN+canonical(payload)).hex()}

def verify_authorized_consumption_receipt(receipt,public_hex,witness_id,request,capability,
                                           challenge,holder_proof,evaluator_authorization):
    try:
        if type(receipt) is not dict or set(receipt)!={"payload","signature"}:
            return False
        p=receipt["payload"]
        required={"schema","witness_id","sequence","operation_id","request_sha256",
            "capability_sha256","challenge_sha256","holder_proof_sha256",
            "evaluator_authorization_sha256","previous_hash","entry_hash"}
        if type(p) is not dict or set(p)!=required or p["schema"]!=RECEIPT_SCHEMA or p["witness_id"]!=witness_id:
            return False
        record=authorization_record(request,capability,challenge,holder_proof,evaluator_authorization)
        entry=make_entry(p["sequence"],p["previous_hash"],record)
        expected={"schema":RECEIPT_SCHEMA,"witness_id":witness_id,
            **{k:v for k,v in entry.items() if k!="schema"}}
        if p!=expected:
            return False
        raw=bytes.fromhex(public_hex); sig=bytes.fromhex(receipt["signature"])
        if len(raw)!=32 or len(sig)!=64:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(sig,RECEIPT_DOMAIN+canonical(p))
        return True
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError):
        return False

class SignedRemoteAuthorizedExecutionConsumptionWitness:
    def __init__(self,socket_path,witness_id,public_hex,timeout=3):
        raw=bytes.fromhex(public_hex)
        if len(raw)!=32 or type(witness_id) is not str or not witness_id:
            raise ValueError("invalid authorized execution witness pin")
        self.socket_path=str(socket_path); self.witness_id=witness_id
        self.public_hex=public_hex; self.timeout=timeout
    @staticmethod
    def _read(conn,size):
        parts=[]
        while size:
            chunk=conn.recv(size)
            if not chunk: raise PermissionError("authorized execution witness connection ended")
            parts.append(chunk); size-=len(chunk)
        return b"".join(parts)
    def consume_authorized(self,request,capability,challenge,holder_proof,evaluator_authorization):
        body=json.dumps({"op":"CONSUME_AUTHORIZED","request":request,"capability":capability,
            "challenge":challenge,"holder_proof":holder_proof,
            "evaluator_authorization":evaluator_authorization},
            sort_keys=True,separators=(",",":")).encode()
        if len(body)>262144:
            raise PermissionError("authorized execution witness request too large")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout); conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            size=struct.unpack("!I",self._read(conn,4))[0]
            if size>32768: raise PermissionError("authorized execution witness response too large")
            response=json.loads(self._read(conn,size))
        if (type(response) is not dict or set(response)!={"status","receipt"}
            or response["status"]!="CONSUMED"
            or not verify_authorized_consumption_receipt(response["receipt"],self.public_hex,
                self.witness_id,request,capability,challenge,holder_proof,evaluator_authorization)):
            raise PermissionError("authorized execution consumption receipt invalid")
        return response["receipt"]


def validate_authorized_receipt_structure(receipt,public_hex,witness_id):
    try:
        if type(receipt) is not dict or set(receipt)!={"payload","signature"}:
            raise PermissionError("malformed authorized execution receipt")
        p=receipt["payload"]
        required={"schema","witness_id","sequence","operation_id","request_sha256",
            "capability_sha256","challenge_sha256","holder_proof_sha256",
            "evaluator_authorization_sha256","previous_hash","entry_hash"}
        if type(p) is not dict or set(p)!=required:
            raise PermissionError("malformed authorized execution receipt payload")
        if (p["schema"]!=RECEIPT_SCHEMA or p["witness_id"]!=witness_id
            or type(p["sequence"]) is not int or p["sequence"]<1
            or type(p["operation_id"]) is not str or not p["operation_id"]):
            raise PermissionError("authorized execution receipt scope invalid")
        for name in ("request_sha256","capability_sha256","challenge_sha256",
                     "holder_proof_sha256","evaluator_authorization_sha256",
                     "previous_hash","entry_hash"):
            value=p[name]
            if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                raise PermissionError("authorized execution receipt digest invalid")
        core={"schema":"AML-SEF2-AUTHORIZED-EXECUTION-CONSUMPTION-ENTRY-V3",
            "sequence":p["sequence"],"operation_id":p["operation_id"],
            "request_sha256":p["request_sha256"],"capability_sha256":p["capability_sha256"],
            "challenge_sha256":p["challenge_sha256"],
            "holder_proof_sha256":p["holder_proof_sha256"],
            "evaluator_authorization_sha256":p["evaluator_authorization_sha256"],
            "previous_hash":p["previous_hash"]}
        if hashlib.sha256(ENTRY_DOMAIN+canonical(core)).hexdigest()!=p["entry_hash"]:
            raise PermissionError("authorized execution receipt entry hash invalid")
        raw=bytes.fromhex(public_hex); sig=bytes.fromhex(receipt["signature"])
        if len(raw)!=32 or len(sig)!=64:
            raise PermissionError("authorized execution receipt signature invalid")
        Ed25519PublicKey.from_public_bytes(raw).verify(sig,RECEIPT_DOMAIN+canonical(p))
        return p
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError) as exc:
        raise PermissionError("authorized execution receipt invalid") from exc

class AuthorizedExecutionReceiptAnchor:
    def __init__(self,path,witness_id,witness_public_hex):
        raw=bytes.fromhex(witness_public_hex)
        if len(raw)!=32 or type(witness_id) is not str or not witness_id:
            raise ValueError("invalid authorized execution receipt anchor enrollment")
        self.path=str(path); self.witness_id=witness_id; self.public_hex=witness_public_hex
        fingerprint=hashlib.sha256(raw).hexdigest()
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS authorized_execution_receipt_anchor (
                witness_id TEXT PRIMARY KEY,witness_key_sha256 TEXT NOT NULL,
                sequence INTEGER NOT NULL,head_hash TEXT NOT NULL)""")
            row=db.execute("""SELECT witness_key_sha256,sequence,head_hash
                FROM authorized_execution_receipt_anchor WHERE witness_id=?""",(witness_id,)).fetchone()
            if row is None:
                db.execute("INSERT INTO authorized_execution_receipt_anchor VALUES (?,?,0,?)",
                    (witness_id,fingerprint,ZERO_HASH))
            elif row[0]!=fingerprint:
                raise ValueError("authorized execution receipt anchor witness key changed")
    def accept(self,receipt):
        p=validate_authorized_receipt_structure(receipt,self.public_hex,self.witness_id)
        try:
            with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                sequence,head=db.execute("""SELECT sequence,head_hash
                    FROM authorized_execution_receipt_anchor WHERE witness_id=?""",
                    (self.witness_id,)).fetchone()
                if p["sequence"]==sequence and p["entry_hash"]==head:
                    return "ANCHORED"
                if p["sequence"]!=sequence+1 or p["previous_hash"]!=head:
                    raise PermissionError("authorized execution receipt rollback or fork detected")
                db.execute("""UPDATE authorized_execution_receipt_anchor
                    SET sequence=?,head_hash=? WHERE witness_id=?""",
                    (p["sequence"],p["entry_hash"],self.witness_id))
                return "ANCHORED"
        except sqlite3.DatabaseError as exc:
            raise PermissionError("authorized execution receipt anchor store failed") from exc
    def state(self):
        with sqlite3.connect(self.path) as db:
            row=db.execute("""SELECT sequence,head_hash FROM authorized_execution_receipt_anchor
                WHERE witness_id=?""",(self.witness_id,)).fetchone()
        return {"sequence":row[0],"head_hash":row[1]}

class RemoteAuthorizedExecutionReceiptAnchor:
    def __init__(self,socket_path,timeout=3):
        self.socket_path=str(socket_path); self.timeout=timeout
    @staticmethod
    def _read(conn,size):
        parts=[]
        while size:
            chunk=conn.recv(size)
            if not chunk: raise PermissionError("authorized execution anchor connection ended")
            parts.append(chunk); size-=len(chunk)
        return b"".join(parts)
    def accept(self,receipt):
        body=json.dumps({"op":"ANCHOR_AUTHORIZED","receipt":receipt},
            sort_keys=True,separators=(",",":")).encode()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout); conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            size=struct.unpack("!I",self._read(conn,4))[0]
            if size>4096: raise PermissionError("authorized execution anchor response too large")
            response=json.loads(self._read(conn,size))
        if response!={"status":"ANCHORED"}:
            raise PermissionError("authorized execution receipt anchor denied receipt")
        return "ANCHORED"

class AnchoredRemoteAuthorizedExecutionConsumptionWitness:
    def __init__(self,witness_socket,witness_id,witness_public_hex,anchor_socket,timeout=3):
        self.witness=SignedRemoteAuthorizedExecutionConsumptionWitness(
            witness_socket,witness_id,witness_public_hex,timeout)
        self.anchor=RemoteAuthorizedExecutionReceiptAnchor(anchor_socket,timeout)
    def consume_authorized(self,request,capability,challenge,holder_proof,evaluator_authorization):
        receipt=self.witness.consume_authorized(request,capability,challenge,
            holder_proof,evaluator_authorization)
        if self.anchor.accept(receipt)!="ANCHORED":
            raise PermissionError("full authorization consumption head not independently anchored")
        return receipt
