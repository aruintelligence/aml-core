"""Separate-UID holder service that accepts only authenticated broker challenges."""
import json,os,socket,socketserver,struct,sys
from broker_authenticated_holder import make_broker_authenticated_holder_proof
from session_holder_service import load_or_create_key,process_start_time

MAX_REQUEST=65536

def _unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key]=value
    return out

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw=self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
            pid,uid,_=struct.unpack("3i",raw)
            if uid!=self.server.allowed_uid:
                self.wfile.write(b'{"status":"DENIED"}\n'); return
            if self.server.allowed_pid is not None:
                if (pid!=self.server.allowed_pid
                    or process_start_time(pid)!=self.server.allowed_start_time):
                    self.wfile.write(b'{"status":"DENIED"}\n'); return
            line=self.rfile.readline(MAX_REQUEST+1)
            if len(line)>MAX_REQUEST or not line.endswith(b"\n"):
                raise ValueError("oversized request")
            env=json.loads(line,object_pairs_hook=_unique)
            if type(env) is not dict or set(env)!={"execution_challenge","capability","request"}:
                raise ValueError("invalid authenticated holder request")
            proof=make_broker_authenticated_holder_proof(self.server.private_key,
                env["execution_challenge"],self.server.broker_public_hex,
                self.server.broker_id,self.server.audience,env["capability"],env["request"])
            response={"status":"PROOF","proof":proof}
        except (ValueError,TypeError,KeyError,PermissionError,UnicodeError,OSError):
            response={"status":"DENIED"}
        self.wfile.write(json.dumps(response,separators=(",",":")).encode()+b"\n")

class BrokerAuthenticatedHolderServer(socketserver.UnixStreamServer):
    allow_reuse_address=False
    def __init__(self,socket_path,private_key,allowed_uid,broker_public_hex,
                 broker_id,audience,allowed_pid=None):
        if type(allowed_uid) is not int or allowed_uid<0:
            raise ValueError("allowed client UID required")
        if allowed_pid is not None and (type(allowed_pid) is not int or allowed_pid<=0):
            raise ValueError("allowed client PID must be positive")
        raw=bytes.fromhex(broker_public_hex)
        if len(raw)!=32 or type(broker_id) is not str or not broker_id or type(audience) is not str or not audience:
            raise ValueError("invalid pinned broker configuration")
        self.private_key=private_key; self.allowed_uid=allowed_uid
        self.allowed_pid=allowed_pid
        self.allowed_start_time=(process_start_time(allowed_pid) if allowed_pid is not None else None)
        self.broker_public_hex=broker_public_hex; self.broker_id=broker_id; self.audience=audience
        super().__init__(str(socket_path),_Handler)
        os.chmod(socket_path,0o600)

def request_authenticated_holder_proof(socket_path,execution_challenge,capability,request,timeout=3):
    payload=json.dumps({"execution_challenge":execution_challenge,
        "capability":capability,"request":request},separators=(",",":"),ensure_ascii=False).encode()+b"\n"
    if len(payload)>MAX_REQUEST:
        raise PermissionError("authenticated holder request too large")
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout); conn.connect(str(socket_path)); conn.sendall(payload)
            data=b""
            while not data.endswith(b"\n") and len(data)<=MAX_REQUEST:
                part=conn.recv(4096)
                if not part: break
                data+=part
        response=json.loads(data)
        if (type(response) is not dict or set(response)!={"status","proof"}
            or response["status"]!="PROOF"):
            raise PermissionError("authenticated holder proof denied")
        return response["proof"]
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise PermissionError("authenticated holder proof denied") from exc

def serve(socket_path,private_path,public_path,allowed_uid,allowed_gid,
          broker_public_hex,broker_id,audience,allowed_pid=None):
    key=load_or_create_key(private_path,public_path)
    try: os.unlink(socket_path)
    except FileNotFoundError: pass
    with BrokerAuthenticatedHolderServer(socket_path,key,allowed_uid,broker_public_hex,
            broker_id,audience,allowed_pid) as server:
        os.chown(socket_path,-1,allowed_gid); os.chmod(socket_path,0o660)
        server.serve_forever(poll_interval=.05)

if __name__=="__main__":
    allowed_pid=int(sys.argv[9]) if len(sys.argv)>9 else None
    serve(sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),int(sys.argv[5]),
          sys.argv[6],sys.argv[7],sys.argv[8],allowed_pid)
