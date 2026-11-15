"""Independent single-use execution consumption witness.

The witness records an authorized operation before the broker commits its local
synthetic effect. If the broker crashes after witness consumption but before
local commit, the operation is intentionally stranded: safety over availability.
Rollback resistance exists only when this database is retained outside the
broker's rollback/administrative domain.
"""
import hashlib,sqlite3
from gated_action_broker import canonical_request
from session_capability import capability_digest

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
    def consume(self,request,capability,challenge):
        record=self._record(request,capability,challenge)
        try:
            with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO execution_consumption VALUES (?,?,?,?)",record)
            return "CONSUMED"
        except sqlite3.IntegrityError as exc:
            raise PermissionError("operation already crossed execution boundary") from exc
    def lookup(self,operation_id):
        with sqlite3.connect(self.path) as db:
            row=db.execute("""SELECT request_sha256,capability_sha256,challenge_sha256
                FROM execution_consumption WHERE operation_id=?""",(operation_id,)).fetchone()
        if row is None: return None
        return {"operation_id":operation_id,"request_sha256":row[0],
            "capability_sha256":row[1],"challenge_sha256":row[2]}


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
            header=self._read(conn,4); size=struct.unpack("!I",header)[0]
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
