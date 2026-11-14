"""Separate-UID Unix-socket witness service with signed append receipts."""
import json
import os
import socket
import struct
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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

def load_signing_key(private_path,public_path):
    if os.path.exists(private_path):
        if os.stat(private_path).st_mode & 0o077:
            raise PermissionError("witness private key permissions too broad")
        key=serialization.load_pem_private_key(open(private_path,"rb").read(),password=None)
        if not isinstance(key,Ed25519PrivateKey): raise ValueError("wrong witness key type")
    else:
        key=Ed25519PrivateKey.generate()
        data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
        fd=os.open(private_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
    raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    fd=os.open(public_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o644)
    with os.fdopen(fd,"w") as stream: stream.write(raw.hex()); stream.flush(); os.fsync(stream.fileno())
    return key

def serve(sock_path,database,allowed_uid,allowed_gid,private_path,public_path):
    key=load_signing_key(private_path,public_path)
    witness=SignerWitness(database,key)
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
                    if not hasattr(socket,"SO_PEERCRED"): raise PermissionError("SO_PEERCRED unavailable")
                    _,uid,_=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid!=allowed_uid: raise PermissionError("untrusted signer UID")
                    size=struct.unpack("!I",read_exact(conn,4))[0]
                    if size>65536: raise ValueError("request too large")
                    request=json.loads(read_exact(conn,size),object_pairs_hook=reject_duplicate_keys)
                    if type(request) is not dict or set(request)!={"challenge","operation_id","request"}:
                        raise ValueError("invalid request schema")
                    receipt=witness.consume(request["challenge"],request["operation_id"],request["request"])
                    response={"status":"CONSUMED","receipt":receipt}
                except Exception:
                    response={"status":"DENIED","receipt":None}
                body=json.dumps(response,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)

if __name__=="__main__":
    serve(sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),sys.argv[5],sys.argv[6])
