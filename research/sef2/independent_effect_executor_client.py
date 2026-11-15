"""Client for separate-UID independent effect executor."""
import json,socket,struct

def request_effect(socket_path,request,capability,execution_challenge,holder_proof,
                   evaluator_authorization,timeout=3):
    payload={"request":request,"capability":capability,
        "execution_challenge":execution_challenge,"holder_proof":holder_proof,
        "evaluator_authorization":evaluator_authorization}
    body=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
    if len(body)>262144: raise PermissionError("effect request too large")
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout); conn.connect(str(socket_path))
            conn.sendall(struct.pack("!I",len(body))+body)
            header=_read(conn,4); size=struct.unpack("!I",header)[0]
            if size>4096: raise PermissionError("effect response too large")
            response=json.loads(_read(conn,size))
        if type(response) is not dict or set(response)!={"status"}:
            raise PermissionError("invalid effect response")
        if response["status"] not in ("APPLIED","ALREADY_APPLIED","DENIED"):
            raise PermissionError("invalid effect status")
        return response["status"]
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise PermissionError("independent effect request failed") from exc

def _read(conn,size):
    parts=[]
    while size:
        chunk=conn.recv(size)
        if not chunk: raise PermissionError("effect executor connection ended")
        parts.append(chunk); size-=len(chunk)
    return b"".join(parts)
