"""Separate-UID service for independently verified synthetic effects.

The service owns the effect database and re-verifies authority, broker, holder,
evaluator and revocation evidence. Optional execution-consumption witness and
receipt-anchor services make the effect single-use across executor DB rollback.
"""
import json,os,socket,struct,sys
from independent_effect_executor import IndependentEffectExecutor
from session_epoch_anchor import RemoteSessionEpochAnchor
from execution_receipt_anchor import AnchoredRemoteExecutionConsumptionWitness

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
    for key,value in pairs:
        if key in out: raise ValueError("duplicate JSON key")
        out[key]=value
    return out

def serve(sock_path,database,allowed_uid,allowed_gid,issuer,issuer_public_hex,audience,
          broker_id,broker_public_hex,evaluator_id,evaluator_public_hex,witness,
          epoch_anchor_socket,execution_witness_socket=None,execution_witness_id=None,
          execution_witness_public_hex=None,execution_anchor_socket=None):
    epoch_anchor=RemoteSessionEpochAnchor(epoch_anchor_socket)
    execution_witness=None
    supplied=(execution_witness_socket,execution_witness_id,
              execution_witness_public_hex,execution_anchor_socket)
    if any(v is not None for v in supplied):
        if not all(v is not None for v in supplied):
            raise ValueError("execution witness configuration must be complete")
        execution_witness=AnchoredRemoteExecutionConsumptionWitness(
            execution_witness_socket,execution_witness_id,
            execution_witness_public_hex,execution_anchor_socket)
    executor=IndependentEffectExecutor(database,issuer,issuer_public_hex,audience,
        broker_id,broker_public_hex,evaluator_id,evaluator_public_hex,witness,
        epoch_anchor,execution_witness)
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
                    required={"request","capability","execution_challenge","holder_proof",
                              "evaluator_authorization"}
                    if type(req) is not dict or set(req)!=required:
                        raise ValueError("invalid effect request")
                    status=executor.execute(req["request"],req["capability"],
                        req["execution_challenge"],req["holder_proof"],
                        req["evaluator_authorization"])
                    response={"status":status}
                except Exception:
                    response={"status":"DENIED"}
                body=json.dumps(response,separators=(",",":")).encode()
                conn.sendall(struct.pack("!I",len(body))+body)

if __name__=="__main__":
    fixed=sys.argv[1:14]
    extra=sys.argv[14:18]
    serve(fixed[0],fixed[1],int(fixed[2]),int(fixed[3]),*fixed[4:],
          *(extra if extra else (None,None,None,None)))
