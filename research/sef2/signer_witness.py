"""Independent monotonic signer-intent witness (synthetic local reference)."""
import hashlib
import json
import socket
import sqlite3
import struct
from gated_action_broker import canonical_request

class SignerWitness:
    def __init__(self,database):
        self.database=str(database)
        with sqlite3.connect(self.database) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS consumed_intents (
                challenge TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL,
                request_sha256 TEXT NOT NULL)""")
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

class RemoteSignerWitness:
    """Length-delimited Unix socket client; witness peer identity is OS-enforced."""
    def __init__(self,socket_path,timeout=3):
        self.socket_path=str(socket_path)
        self.timeout=timeout

    def consume(self,challenge,operation_id,request):
        payload=json.dumps({"challenge":challenge,"operation_id":operation_id,
            "request":request},sort_keys=True,separators=(",",":")).encode()
        if len(payload)>65536:
            raise PermissionError("witness request too large")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout)
            conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(payload))+payload)
            header=self._read_exact(conn,4)
            size=struct.unpack("!I",header)[0]
            if size>4096:
                raise PermissionError("invalid witness response")
            response=json.loads(self._read_exact(conn,size))
        if response!={"status":"CONSUMED"}:
            raise PermissionError("independent witness denied intent")

    @staticmethod
    def _read_exact(conn,size):
        chunks=[]
        while size:
            chunk=conn.recv(size)
            if not chunk:
                raise PermissionError("witness connection ended")
            chunks.append(chunk)
            size-=len(chunk)
        return b"".join(chunks)
