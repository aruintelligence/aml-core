"""Separate-UID Unix-socket witness service. Synthetic Linux reference only."""
import json
import os
import socket
import struct
import sys
from signer_witness import SignerWitness

def read_exact(conn,size):
    chunks=[]
    while size:
        chunk=conn.recv(size)
        if not chunk: raise ValueError("truncated frame")
        chunks.append(chunk); size-=len(chunk)
    return b"".join(chunks)

def reject_duplicate_keys(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError("duplicate JSON key")
        result[key]=value
    return result

def serve(sock_path,database,allowed_uid,allowed_gid):
    witness=SignerWitness(database)
    try: os.unlink(sock_path)
    except FileNotFoundError: pass
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(sock_path)
        os.chown(sock_path,-1,allowed_gid)
        os.chmod(sock_path,0o660)
        server.listen(32)
        while True:
            conn,_=server.accept()
            with conn:
                conn.settimeout(3.0)
                try:
                    if not hasattr(socket,"SO_PEERCRED"):
                        raise PermissionError("SO_PEERCRED unavailable")
                    _,uid,_=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid!=allowed_uid:
                        raise PermissionError("untrusted signer UID")
                    size=struct.unpack("!I",read_exact(conn,4))[0]
                    if size>65536: raise ValueError("request too large")
                    request=json.loads(read_exact(conn,size),object_pairs_hook=reject_duplicate_keys)
                    if type(request) is not dict or set(request)!={"challenge","operation_id","request"}:
                        raise ValueError("invalid request schema")
                    witness.consume(request["challenge"],request["operation_id"],request["request"])
                    response={"status":"CONSUMED"}
                except Exception:
                    response={"status":"DENIED"}
                body=json.dumps(response,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)

if __name__=="__main__":
    serve(sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]))
