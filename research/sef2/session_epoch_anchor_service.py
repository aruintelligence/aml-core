"""Separate-UID service for monotonic session revocation epochs."""
import json,os,socket,struct,sys
from session_epoch_anchor import SessionEpochAnchor
MAX=65536
def read_exact(conn,size):
    parts=[]
    while size:
        chunk=conn.recv(size)
        if not chunk: raise ValueError("truncated frame")
        parts.append(chunk); size-=len(chunk)
    return b"".join(parts)
def reject_duplicate_keys(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise ValueError("duplicate JSON key")
        out[k]=v
    return out
def serve(sock_path,database,allowed_uid,allowed_gid):
    anchor=SessionEpochAnchor(database)
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
                    if uid!=allowed_uid: raise PermissionError("untrusted broker UID")
                    size=struct.unpack("!I",read_exact(conn,4))[0]
                    if size<2 or size>MAX: raise ValueError("invalid frame")
                    req=json.loads(read_exact(conn,size),object_pairs_hook=reject_duplicate_keys)
                    if req.get("op")=="INITIALIZE" and set(req)=={"op","audience","epoch"}:
                        response={"status":"OK","epoch":anchor.initialize(req["audience"],req["epoch"])}
                    elif req.get("op")=="READ" and set(req)=={"op","audience"}:
                        try:
                            response={"status":"OK","epoch":anchor.read_epoch(req["audience"])}
                        except ValueError:
                            response={"status":"MISSING"}
                    elif req.get("op")=="CAS" and set(req)=={"op","audience","expected","new"}:
                        response={"status":"OK","accepted":anchor.compare_and_set(req["audience"],req["expected"],req["new"])}
                    else: raise ValueError("invalid operation")
                except Exception:
                    response={"status":"DENIED"}
                body=json.dumps(response,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)
if __name__=="__main__":
    serve(sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]))
