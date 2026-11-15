"""Separate-UID single-use execution consumption witness service."""
import json,os,socket,struct,sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_consumption_witness import ExecutionConsumptionWitness,make_consumption_receipt_from_entry
from authorized_execution_consumption import AuthorizedExecutionConsumptionWitness,make_authorized_consumption_receipt
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

def load_or_create_key(private_path,public_path):
    if os.path.exists(private_path):
        info=os.stat(private_path,follow_symlinks=False)
        if info.st_mode & 0o077:
            raise PermissionError("execution witness key permissions too broad")
        key=serialization.load_pem_private_key(open(private_path,"rb").read(),password=None)
        if not isinstance(key,Ed25519PrivateKey): raise ValueError("wrong execution witness key type")
    else:
        key=Ed25519PrivateKey.generate()
        data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        fd=os.open(private_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    public_hex=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
    fd=os.open(public_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o644)
    with os.fdopen(fd,"w") as stream:
        stream.write(public_hex); stream.flush(); os.fsync(stream.fileno())
    return key

def serve(sock_path,database,allowed_uid,allowed_gid,witness_id=None,private_key_path=None,public_key_path=None):
    witness=ExecutionConsumptionWitness(database)
    authorized_witness=AuthorizedExecutionConsumptionWitness(database)
    signed=all(value is not None for value in (witness_id,private_key_path,public_key_path))
    if any(value is not None for value in (witness_id,private_key_path,public_key_path)) and not signed:
        raise ValueError("signed execution witness configuration must be complete")
    key=load_or_create_key(private_key_path,public_key_path) if signed else None
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
                    if size<2 or size>MAX_FRAME: raise ValueError("invalid frame size")
                    req=json.loads(read_exact(conn,size),object_pairs_hook=reject_duplicate_keys)
                    if type(req) is not dict or "op" not in req:
                        raise ValueError("invalid consume request")
                    if req["op"]=="CONSUME":
                        if set(req)!={"op","request","capability","challenge"}:
                            raise ValueError("invalid legacy consume request")
                        if signed:
                            entry=witness.consume_record(req["request"],req["capability"],req["challenge"])
                            receipt=make_consumption_receipt_from_entry(key,witness_id,entry)
                            response={"status":"CONSUMED","receipt":receipt}
                        else:
                            witness.consume(req["request"],req["capability"],req["challenge"])
                            response={"status":"CONSUMED"}
                    elif req["op"]=="CONSUME_AUTHORIZED":
                        required={"op","request","capability","challenge","holder_proof","evaluator_authorization"}
                        if set(req)!=required or not signed:
                            raise ValueError("invalid full-authorization consume request")
                        entry=authorized_witness.consume_record(req["request"],req["capability"],
                            req["challenge"],req["holder_proof"],req["evaluator_authorization"])
                        receipt=make_authorized_consumption_receipt(key,witness_id,entry)
                        response={"status":"CONSUMED","receipt":receipt}
                    else:
                        raise ValueError("unsupported execution consumption operation")
                except Exception:
                    response={"status":"DENIED"}
                body=json.dumps(response,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)
if __name__=="__main__":
    extra=sys.argv[5:8]
    serve(sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),
          *(extra if extra else (None,None,None)))
