"""Unix-domain IPC for session-bound capability challenge and execution."""
import json,os,socket,socketserver,struct
MAX_REQUEST=65536
def reject_duplicate_keys(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise ValueError("duplicate JSON key")
        out[k]=v
    return out
class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw=self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
            _,uid,_=struct.unpack("3i",raw)
            if uid not in self.server.allowed_uids:
                self.wfile.write(b'{"status":"DENIED"}\n'); return
        except Exception:
            return
        line=self.rfile.readline(MAX_REQUEST+1)
        if len(line)>MAX_REQUEST or not line.endswith(b"\n"):
            self.wfile.write(b'{"status":"DENIED"}\n'); return
        try:
            env=json.loads(line,object_pairs_hook=reject_duplicate_keys)
            if type(env) is not dict or env.get("op") not in ("challenge","execute"):
                raise ValueError("invalid operation")
            if env["op"]=="challenge":
                if set(env)!={"op","operation_id"}: raise ValueError("invalid challenge envelope")
                challenge=self.server.broker.issue_execution_challenge(env["operation_id"])
                response={"status":"CHALLENGE","challenge":challenge}
            else:
                required={"op","request","attestations","capability","holder_proof","challenge"}
                if set(env)!=required: raise ValueError("invalid execute envelope")
                status=self.server.broker.execute(env["request"],env["attestations"],env["capability"],
                    env["holder_proof"],env["challenge"])
                if status not in ("APPLIED","ALREADY_APPLIED","DENIED"): status="DENIED"
                response={"status":status}
        except (ValueError,TypeError,KeyError,PermissionError,UnicodeError):
            response={"status":"DENIED"}
        self.wfile.write(json.dumps(response,separators=(",",":")).encode()+b"\n")
class SessionBrokerServer(socketserver.UnixStreamServer):
    allow_reuse_address=False
    def __init__(self,socket_path,broker,allowed_uids):
        if type(allowed_uids) is not frozenset or not allowed_uids:
            raise ValueError("allowed UIDs required")
        from broker_isolation_guard import validate_isolation
        if not validate_isolation(broker.path,os.geteuid(),allowed_uids):
            raise ValueError("unsafe broker isolation")
        import pathlib
        if pathlib.Path(socket_path).resolve().parent==pathlib.Path(broker.path).resolve().parent:
            raise ValueError("socket cannot share private DB directory")
        self.allowed_uids=allowed_uids; self.broker=broker
        super().__init__(str(socket_path),_Handler)
        os.chmod(socket_path,0o600)
def grant_socket_group(socket_path,gid):
    import pathlib,stat
    path=pathlib.Path(socket_path)
    if path.is_symlink() or not path.exists() or not stat.S_ISSOCK(path.stat().st_mode):
        raise ValueError("invalid socket")
    os.chown(path,-1,gid); os.chmod(path,0o660)
def _call(socket_path,envelope,timeout=3):
    payload=json.dumps(envelope,separators=(",",":"),ensure_ascii=False).encode()+b"\n"
    if len(payload)>MAX_REQUEST: return {"status":"DENIED"}
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout); conn.connect(str(socket_path)); conn.sendall(payload)
            data=b""
            while not data.endswith(b"\n") and len(data)<=MAX_REQUEST:
                part=conn.recv(4096)
                if not part: break
                data+=part
        obj=json.loads(data)
        return obj if type(obj) is dict else {"status":"DENIED"}
    except Exception:
        return {"status":"DENIED"}
def request_challenge(socket_path,operation_id,timeout=3):
    response=_call(socket_path,{"op":"challenge","operation_id":operation_id},timeout)
    if set(response)=={"status","challenge"} and response["status"]=="CHALLENGE":
        return response["challenge"]
    raise PermissionError("challenge denied")
def request_execute(socket_path,request,attestations,capability,holder_proof,challenge,timeout=3):
    response=_call(socket_path,{"op":"execute","request":request,"attestations":attestations,
        "capability":capability,"holder_proof":holder_proof,"challenge":challenge},timeout)
    return response.get("status","DENIED") if type(response) is dict else "DENIED"
