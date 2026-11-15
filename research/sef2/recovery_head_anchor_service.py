"""Separate-UID Unix-socket recovery head anchor service and client transport."""
import hashlib,json,os,socket,sqlite3,struct,sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_receipt import canonical
from threshold_recovery import RECOVERY_ANCHOR_READ_DOMAIN,RECOVERY_ANCHOR_CAS_DOMAIN

ZERO="0"*64
def _read_exact(conn,size):
    chunks=[]
    while size:
        part=conn.recv(size)
        if not part: raise ValueError("truncated frame")
        chunks.append(part); size-=len(part)
    return b"".join(chunks)
def _valid_hash(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)
def _load_key(private_path,public_path):
    if os.path.exists(private_path):
        if os.stat(private_path).st_mode & 0o077: raise PermissionError("anchor key permissions too broad")
        key=serialization.load_pem_private_key(open(private_path,"rb").read(),password=None)
        if not isinstance(key,Ed25519PrivateKey): raise ValueError("wrong key type")
    else:
        key=Ed25519PrivateKey.generate()
        raw=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        fd=os.open(private_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
    fd=os.open(public_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o644)
    with os.fdopen(fd,"w") as stream: stream.write(public); stream.flush(); os.fsync(stream.fileno())
    return key
class UnixRecoveryHeadAnchorTransport:
    def __init__(self,socket_path,timeout=3):
        self.socket_path=str(socket_path); self.timeout=timeout
    def _call(self,request):
        body=json.dumps(request,sort_keys=True,separators=(",",":")).encode()
        if len(body)>4096: raise OSError("request too large")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout); conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            size=struct.unpack("!I",_read_exact(conn,4))[0]
            if size>8192: raise OSError("response too large")
            return json.loads(_read_exact(conn,size))
    def read_head(self,nonce): return self._call({"op":"read","nonce":nonce})
    def compare_and_set(self,expected,new,nonce):
        return self._call({"op":"cas","expected_head":expected,"new_head":new,"nonce":nonce})
def serve(anchor_id,socket_path,database,private_path,public_path,allowed_uid,allowed_gid):
    if type(anchor_id) is not str or not anchor_id: raise ValueError("invalid anchor id")
    key=_load_key(private_path,public_path)
    with sqlite3.connect(database,timeout=10) as db:
        db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE IF NOT EXISTS anchor_meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS anchor_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),head TEXT NOT NULL)")
        objects=db.execute("""SELECT type,name FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name""").fetchall()
        if any(kind!="table" or name not in {"anchor_meta","anchor_state"} for kind,name in objects):
            raise ValueError("recovery head anchor database contains unexpected schema objects")
        names={name for kind,name in objects}
        if names!={"anchor_meta","anchor_state"}:
            raise ValueError("recovery head anchor database schema is incomplete")
        if tuple(row[1] for row in db.execute("PRAGMA table_info(anchor_meta)"))!=("key","value"):
            raise ValueError("recovery head anchor metadata layout is not canonical")
        if tuple(row[1] for row in db.execute("PRAGMA table_info(anchor_state)"))!=("singleton","head"):
            raise ValueError("recovery head anchor state layout is not canonical")
        identity={"anchor_id":anchor_id,
            "anchor_key_sha256":hashlib.sha256(key.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw)).hexdigest()}
        existing=dict(db.execute("SELECT key,value FROM anchor_meta").fetchall())
        if existing and existing!=identity:
            raise ValueError("recovery head anchor database belongs to another identity")
        if not existing:
            db.executemany("INSERT INTO anchor_meta VALUES (?,?)",identity.items())
        db.execute("INSERT OR IGNORE INTO anchor_state VALUES (1,?)",(ZERO,))
        rows=db.execute("SELECT singleton,head FROM anchor_state").fetchall()
        if len(rows)!=1 or rows[0][0]!=1 or not _valid_hash(rows[0][1]):
            raise ValueError("recovery head anchor database state is malformed")
        db.commit()
    try: os.unlink(socket_path)
    except FileNotFoundError: pass
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(socket_path); os.chown(socket_path,-1,allowed_gid); os.chmod(socket_path,0o660)
        server.listen(32)
        while True:
            conn,_=server.accept()
            with conn:
                conn.settimeout(3)
                try:
                    if not hasattr(socket,"SO_PEERCRED"): raise PermissionError("peer credentials unavailable")
                    _,uid,_=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid!=allowed_uid: raise PermissionError("untrusted client uid")
                    size=struct.unpack("!I",_read_exact(conn,4))[0]
                    if size>4096: raise ValueError("request too large")
                    req=json.loads(_read_exact(conn,size))
                    if type(req) is not dict or req.get("op") not in ("read","cas"): raise ValueError("bad request")
                    nonce=req.get("nonce")
                    if type(nonce) is not str or len(nonce)<32 or len(nonce)>128: raise ValueError("bad nonce")
                    if req["op"]=="read":
                        with sqlite3.connect(database) as db:
                            head=db.execute("SELECT head FROM anchor_state WHERE singleton=1").fetchone()[0]
                        response={"anchor_id":anchor_id,"head_sha256":head,"nonce":nonce}
                        response["signature"]=key.sign(RECOVERY_ANCHOR_READ_DOMAIN+canonical(response)).hex()
                    else:
                        expected=req.get("expected_head"); new=req.get("new_head")
                        if not _valid_hash(expected) or not _valid_hash(new): raise ValueError("bad hash")
                        with sqlite3.connect(database,timeout=5,isolation_level=None) as db:
                            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
                            current=db.execute("SELECT head FROM anchor_state WHERE singleton=1").fetchone()[0]
                            accepted=current==expected
                            if accepted: db.execute("UPDATE anchor_state SET head=? WHERE singleton=1",(new,))
                            db.commit()
                        response={"anchor_id":anchor_id,"expected_head":expected,"new_head":new,
                            "accepted":accepted,"nonce":nonce}
                        response["signature"]=key.sign(RECOVERY_ANCHOR_CAS_DOMAIN+canonical(response)).hex()
                except Exception:
                    response={"error":"DENIED"}
                body=json.dumps(response,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)
if __name__=="__main__":
    serve(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],int(sys.argv[6]),int(sys.argv[7]))
