"""Dedicated session-holder signing service.

The holder private key remains in a separate process/UID. A designated client
may request a holder proof for a capability/request/fresh challenge. The
service signs only when the capability is bound to its own public key.

Optionally, access can be pinned to one Linux process instance by UID, PID, and
/proc start time. This protects against a replacement process under the same
UID until explicit re-enrollment. It is not protection against root/kernel
compromise, PID namespace manipulation by a privileged actor, or same-process
model replacement.
"""
import json,os,socket,socketserver,struct,sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import make_holder_proof

MAX_REQUEST=65536

def _unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key]=value
    return out

def process_start_time(pid):
    if type(pid) is not int or pid<=0:
        raise ValueError("invalid process id")
    with open(f"/proc/{pid}/stat","r",encoding="utf-8") as stream:
        raw=stream.read()
    tail=raw.rsplit(") ",1)[1].split()
    # After the process name, element 0 is stat field 3. starttime is field 22.
    if len(tail)<20:
        raise ValueError("malformed proc stat")
    value=int(tail[19])
    if value<0:
        raise ValueError("invalid process start time")
    return value

def load_or_create_key(private_path,public_path):
    if os.path.exists(private_path):
        if os.stat(private_path).st_mode & 0o077:
            raise PermissionError("holder key permissions too broad")
        key=serialization.load_pem_private_key(open(private_path,"rb").read(),password=None)
        if not isinstance(key,Ed25519PrivateKey):
            raise ValueError("wrong key type")
    else:
        key=Ed25519PrivateKey.generate()
        data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        fd=os.open(private_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
    fd=os.open(public_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o644)
    with os.fdopen(fd,"w") as stream:
        stream.write(public); stream.flush(); os.fsync(stream.fileno())
    return key

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            if not hasattr(socket,"SO_PEERCRED"):
                return
            raw=self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
            pid,uid,_=struct.unpack("3i",raw)
            if uid!=self.server.allowed_uid:
                self.wfile.write(b'{"status":"DENIED"}\n')
                return
            if self.server.allowed_pid is not None:
                if (pid!=self.server.allowed_pid
                    or process_start_time(pid)!=self.server.allowed_start_time):
                    self.wfile.write(b'{"status":"DENIED"}\n')
                    return
            line=self.rfile.readline(MAX_REQUEST+1)
            if len(line)>MAX_REQUEST or not line.endswith(b"\n"):
                raise ValueError("oversized request")
            env=json.loads(line,object_pairs_hook=_unique)
            if type(env) is not dict or set(env)!={"capability","request","challenge"}:
                raise ValueError("invalid holder proof request")
            proof=make_holder_proof(self.server.private_key,env["capability"],env["request"],env["challenge"])
            response={"status":"PROOF","proof":proof}
        except (ValueError,TypeError,KeyError,PermissionError,UnicodeError,OSError):
            response={"status":"DENIED"}
        self.wfile.write(json.dumps(response,separators=(",",":")).encode()+b"\n")

class HolderServer(socketserver.UnixStreamServer):
    allow_reuse_address=False
    def __init__(self,socket_path,private_key,allowed_uid,allowed_pid=None):
        if type(allowed_uid) is not int or allowed_uid<0:
            raise ValueError("allowed client UID required")
        if allowed_pid is not None and (type(allowed_pid) is not int or allowed_pid<=0):
            raise ValueError("allowed client PID must be positive")
        self.private_key=private_key
        self.allowed_uid=allowed_uid
        self.allowed_pid=allowed_pid
        self.allowed_start_time=(process_start_time(allowed_pid)
            if allowed_pid is not None else None)
        super().__init__(str(socket_path),_Handler)
        os.chmod(socket_path,0o600)

def request_holder_proof(socket_path,capability,request,challenge,timeout=3):
    payload=json.dumps({"capability":capability,"request":request,"challenge":challenge},
        separators=(",",":"),ensure_ascii=False).encode()+b"\n"
    if len(payload)>MAX_REQUEST:
        raise PermissionError("holder request too large")
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout); conn.connect(str(socket_path)); conn.sendall(payload)
            data=b""
            while not data.endswith(b"\n") and len(data)<=MAX_REQUEST:
                part=conn.recv(4096)
                if not part:
                    break
                data+=part
        response=json.loads(data)
        if (type(response) is not dict or set(response)!={"status","proof"}
            or response["status"]!="PROOF"):
            raise PermissionError("holder proof denied")
        return response["proof"]
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise PermissionError("holder proof denied") from exc

def serve(socket_path,private_path,public_path,allowed_uid,allowed_gid,allowed_pid=None):
    key=load_or_create_key(private_path,public_path)
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    with HolderServer(socket_path,key,allowed_uid,allowed_pid) as server:
        os.chown(socket_path,-1,allowed_gid); os.chmod(socket_path,0o660)
        server.serve_forever(poll_interval=.05)

if __name__=="__main__":
    allowed_pid=int(sys.argv[6]) if len(sys.argv)>6 else None
    serve(sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),int(sys.argv[5]),allowed_pid)
