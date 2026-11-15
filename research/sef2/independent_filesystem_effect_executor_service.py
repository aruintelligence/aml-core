"""Separate-UID service for independently verified real filesystem effects."""
import json,os,socket,struct,sys
from independent_filesystem_effect_executor import IndependentFilesystemEffectExecutor
from session_epoch_anchor import RemoteSessionEpochAnchor

MAX_FRAME=262144
def read_exact(conn,size):
    parts=[]
    while size:
        chunk=conn.recv(size)
        if not chunk: raise ValueError("truncated frame")
        parts.append(chunk); size-=len(chunk)
    return b"".join(parts)
def unique(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise ValueError("duplicate JSON key")
        out[k]=v
    return out
def serve(sock_path,database,effect_dir,allowed_uid,allowed_gid,issuer,issuer_public_hex,
          audience,broker_id,broker_public_hex,evaluator_id,evaluator_public_hex,witness,
          epoch_anchor_socket):
    executor=IndependentFilesystemEffectExecutor(database,effect_dir,issuer,issuer_public_hex,
        audience,broker_id,broker_public_hex,evaluator_id,evaluator_public_hex,witness,
        RemoteSessionEpochAnchor(epoch_anchor_socket))
    try: os.unlink(sock_path)
    except FileNotFoundError: pass
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(sock_path); os.chown(sock_path,-1,allowed_gid); os.chmod(sock_path,0o660)
        server.listen(32)
        while True:
            conn,_=server.accept()
            with conn:
                conn.settimeout(3)
                try:
                    if not hasattr(socket,"SO_PEERCRED"): raise PermissionError("SO_PEERCRED unavailable")
                    _,uid,_=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid!=allowed_uid: raise PermissionError("untrusted effect submitter UID")
                    size=struct.unpack("!I",read_exact(conn,4))[0]
                    if size<2 or size>MAX_FRAME: raise ValueError("invalid frame")
                    req=json.loads(read_exact(conn,size),object_pairs_hook=unique)
                    required={"request","capability","execution_challenge","holder_proof","evaluator_authorization"}
                    if type(req) is not dict or set(req)!=required: raise ValueError("invalid request")
                    status=executor.execute(req["request"],req["capability"],req["execution_challenge"],
                        req["holder_proof"],req["evaluator_authorization"])
                    if status not in ("APPLIED","ALREADY_APPLIED","DENIED"): status="DENIED"
                except Exception:
                    status="DENIED"
                body=json.dumps({"status":status},separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)
if __name__=="__main__":
    serve(sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),int(sys.argv[5]),*sys.argv[6:])
