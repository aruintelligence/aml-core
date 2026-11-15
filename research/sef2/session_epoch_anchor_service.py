"""Separate-UID service for monotonic session revocation epochs.

A writer UID may initialize/read/advance epochs. Optional reader UIDs may only
read. Filesystem socket access remains an independent deployment prerequisite.
"""
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

def serve(sock_path,database,writer_uid,writer_gid,reader_uids=frozenset()):
    if (type(writer_uid) is not int or writer_uid<0 or type(writer_gid) is not int
        or writer_gid<0 or type(reader_uids) is not frozenset
        or any(type(uid) is not int or uid<0 for uid in reader_uids)):
        raise ValueError("invalid epoch-anchor client identities")
    anchor=SessionEpochAnchor(database)
    try: os.unlink(sock_path)
    except FileNotFoundError: pass
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(sock_path); os.chown(sock_path,-1,writer_gid); os.chmod(sock_path,0o660); server.listen(32)
        while True:
            conn,_=server.accept()
            with conn:
                conn.settimeout(3)
                try:
                    if not hasattr(socket,"SO_PEERCRED"): raise PermissionError("SO_PEERCRED unavailable")
                    _,uid,_=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    size=struct.unpack("!I",read_exact(conn,4))[0]
                    if size<2 or size>MAX: raise ValueError("invalid frame")
                    req=json.loads(read_exact(conn,size),object_pairs_hook=reject_duplicate_keys)
                    op=req.get("op")
                    if op=="READ" and set(req)=={"op","audience"}:
                        if uid!=writer_uid and uid not in reader_uids:
                            raise PermissionError("untrusted epoch reader UID")
                        try:
                            response={"status":"OK","epoch":anchor.read_epoch(req["audience"])}
                        except ValueError:
                            response={"status":"MISSING"}
                    elif op=="INITIALIZE" and set(req)=={"op","audience","epoch"}:
                        if uid!=writer_uid: raise PermissionError("epoch initialization requires writer UID")
                        response={"status":"OK","epoch":anchor.initialize(req["audience"],req["epoch"])}
                    elif op=="CAS" and set(req)=={"op","audience","expected","new"}:
                        if uid!=writer_uid: raise PermissionError("epoch update requires writer UID")
                        response={"status":"OK","accepted":anchor.compare_and_set(req["audience"],req["expected"],req["new"])}
                    else:
                        raise ValueError("invalid operation")
                except Exception:
                    response={"status":"DENIED"}
                body=json.dumps(response,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)

if __name__=="__main__":
    readers=frozenset(int(x) for x in sys.argv[5].split(",") if x) if len(sys.argv)>5 else frozenset()
    serve(sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),readers)
