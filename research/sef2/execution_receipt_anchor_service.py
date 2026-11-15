"""Separate-UID anchor for signed execution-consumption receipt heads."""
import json,os,socket,struct,sys
from execution_receipt_anchor import ExecutionReceiptAnchor
from authorized_execution_consumption import AuthorizedExecutionReceiptAnchor
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

def serve(sock_path,database,allowed_uid,allowed_gid,witness_id,witness_public_hex):
    anchor=ExecutionReceiptAnchor(database,witness_id,witness_public_hex)
    authorized_anchor=AuthorizedExecutionReceiptAnchor(database,witness_id,witness_public_hex)
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
                    if size<2 or size>MAX_FRAME: raise ValueError("invalid frame")
                    req=json.loads(read_exact(conn,size),object_pairs_hook=reject_duplicate_keys)
                    if type(req) is not dict or set(req)!={"op","receipt"}:
                        raise ValueError("invalid anchor request")
                    if req["op"]=="ANCHOR":
                        anchor.accept(req["receipt"])
                    elif req["op"]=="ANCHOR_AUTHORIZED":
                        authorized_anchor.accept(req["receipt"])
                    else:
                        raise ValueError("unsupported execution anchor operation")
                    response={"status":"ANCHORED"}
                except Exception:
                    response={"status":"DENIED"}
                body=json.dumps(response,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)
if __name__=="__main__":
    serve(sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),sys.argv[5],sys.argv[6])
