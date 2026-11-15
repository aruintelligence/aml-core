"""Client for the separate-UID holder proof service."""
import json,socket,struct
class HolderProofClient:
    def __init__(self,socket_path,timeout=3): self.socket_path=str(socket_path); self.timeout=timeout
    def _call(self,payload):
        body=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout); conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            size=struct.unpack("!I",self._read(conn,4))[0]
            if size>131072: raise PermissionError("holder service response too large")
            return json.loads(self._read(conn,size))
    def register(self,capability,request):
        response=self._call({"op":"REGISTER","capability":capability,"request":request})
        if response!={"status":"REGISTERED"}: raise PermissionError("holder registration denied")
    def prove(self,capability,request,challenge):
        response=self._call({"op":"PROVE","capability":capability,"request":request,"challenge":challenge})
        if type(response) is not dict or set(response)!={"status","proof"} or response["status"]!="PROVED":
            raise PermissionError("holder proof denied")
        return response["proof"]
    @staticmethod
    def _read(conn,size):
        parts=[]
        while size:
            chunk=conn.recv(size)
            if not chunk: raise PermissionError("holder service connection ended")
            parts.append(chunk); size-=len(chunk)
        return b"".join(parts)
