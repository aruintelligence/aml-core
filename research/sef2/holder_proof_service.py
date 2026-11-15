"""Separate-UID holder proof service for session-bound capabilities.

Synthetic Linux reference. The private Ed25519 holder key never leaves the
service-owned state directory. Only an explicitly authorized runtime UID may
register an exact capability/request pair or request a proof for a broker
challenge. The untrusted model/client UID is not an authorized peer.
"""
import json,os,socket,sqlite3,struct,sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import capability_digest,make_holder_proof
from gated_action_broker import canonical_request
import hashlib

MAX_FRAME=131072

def read_exact(conn,size):
    parts=[]
    while size:
        chunk=conn.recv(size)
        if not chunk: raise ValueError("truncated frame")
        parts.append(chunk); size-=len(chunk)
    return b"".join(parts)

def reject_duplicate_keys(pairs):
    out={}
    for key,value in pairs:
        if key in out: raise ValueError("duplicate JSON key")
        out[key]=value
    return out

def load_or_create_key(path,public_path):
    if os.path.exists(path):
        if os.stat(path,follow_symlinks=False).st_mode & 0o077:
            raise PermissionError("holder private key permissions too broad")
        key=serialization.load_pem_private_key(open(path,"rb").read(),password=None)
        if not isinstance(key,Ed25519PrivateKey): raise ValueError("wrong holder key type")
    else:
        key=Ed25519PrivateKey.generate()
        data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    fd=os.open(public_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o644)
    with os.fdopen(fd,"w") as stream:
        stream.write(raw.hex()); stream.flush(); os.fsync(stream.fileno())
    return key

class HolderProofState:
    def __init__(self,database,key):
        self.database=str(database); self.key=key
        with sqlite3.connect(self.database) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS enrolled_sessions (
                operation_id TEXT PRIMARY KEY,
                capability_sha256 TEXT NOT NULL,
                request_sha256 TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS proof_challenges (
                challenge TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL,
                proof TEXT NOT NULL)""")
            db.commit()
    def register(self,capability,request):
        p=capability.get("payload") if type(capability) is dict else None
        if type(p) is not dict or p.get("holder_public_key_hex")!=self.key.public_key().public_bytes_raw().hex():
            raise PermissionError("capability is not bound to holder service key")
        operation=request.get("operation_id") if type(request) is dict else None
        if type(operation) is not str or not operation or p.get("operation_id")!=operation:
            raise PermissionError("operation binding mismatch")
        cap_hash=capability_digest(capability)
        request_hash=hashlib.sha256(canonical_request(request)).hexdigest()
        with sqlite3.connect(self.database,timeout=5,isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT capability_sha256,request_sha256 FROM enrolled_sessions WHERE operation_id=?",
                (operation,)).fetchone()
            if row:
                if row!=(cap_hash,request_hash): raise PermissionError("conflicting session registration")
                return "REGISTERED"
            db.execute("INSERT INTO enrolled_sessions VALUES (?,?,?)",(operation,cap_hash,request_hash))
        return "REGISTERED"
    def prove(self,capability,request,challenge):
        operation=request.get("operation_id") if type(request) is dict else None
        if type(operation) is not str or type(challenge) is not str:
            raise PermissionError("invalid proof request")
        cap_hash=capability_digest(capability)
        request_hash=hashlib.sha256(canonical_request(request)).hexdigest()
        with sqlite3.connect(self.database,timeout=5,isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT capability_sha256,request_sha256 FROM enrolled_sessions WHERE operation_id=?",
                (operation,)).fetchone()
            if row!=(cap_hash,request_hash): raise PermissionError("session not enrolled")
            existing=db.execute("SELECT operation_id,proof FROM proof_challenges WHERE challenge=?",
                (challenge,)).fetchone()
            if existing:
                if existing[0]!=operation: raise PermissionError("challenge reused across operations")
                return json.loads(existing[1])
            proof=make_holder_proof(self.key,capability,request,challenge)
            db.execute("INSERT INTO proof_challenges VALUES (?,?,?)",
                (challenge,operation,json.dumps(proof,sort_keys=True,separators=(",",":"))))
            return proof

def serve(sock_path,database,key_path,public_path,allowed_uid,allowed_gid):
    key=load_or_create_key(key_path,public_path); state=HolderProofState(database,key)
    try: os.unlink(sock_path)
    except FileNotFoundError: pass
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(sock_path); os.chown(sock_path,-1,allowed_gid); os.chmod(sock_path,0o660); server.listen(32)
        while True:
            conn,_=server.accept()
            with conn:
                conn.settimeout(3)
                try:
                    if not hasattr(socket,"SO_PEERCRED"): raise PermissionError("SO_PEERCRED unavailable")
                    _,uid,_=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid!=allowed_uid: raise PermissionError("untrusted runtime UID")
                    size=struct.unpack("!I",read_exact(conn,4))[0]
                    if size<2 or size>MAX_FRAME: raise ValueError("invalid frame size")
                    req=json.loads(read_exact(conn,size),object_pairs_hook=reject_duplicate_keys)
                    if type(req) is not dict or set(req) not in (
                        {"op","capability","request"},{"op","capability","request","challenge"}):
                        raise ValueError("invalid request schema")
                    if req["op"]=="REGISTER" and set(req)=={"op","capability","request"}:
                        result={"status":state.register(req["capability"],req["request"])}
                    elif req["op"]=="PROVE" and set(req)=={"op","capability","request","challenge"}:
                        result={"status":"PROVED","proof":state.prove(req["capability"],req["request"],req["challenge"])}
                    else: raise ValueError("unsupported operation")
                except Exception:
                    result={"status":"DENIED"}
                body=json.dumps(result,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)

if __name__=="__main__":
    serve(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],int(sys.argv[5]),int(sys.argv[6]))
