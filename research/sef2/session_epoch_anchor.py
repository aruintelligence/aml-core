"""Monotonic external epoch anchor for session capability revocation.

Reference SQLite implementation. Security against broker rollback exists only
when this state is retained outside the broker's rollback/administrative domain.
"""
import sqlite3

class SessionEpochAnchor:
    def __init__(self,path,anchor_id="session-epoch-anchor"):
        if type(anchor_id) is not str or not anchor_id: raise ValueError("invalid anchor id")
        self.path=str(path); self.anchor_id=anchor_id
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS session_epoch_anchor (
                audience TEXT PRIMARY KEY, epoch INTEGER NOT NULL CHECK(epoch>=0))""")
            db.commit()
    def initialize(self,audience,epoch=0):
        if type(audience) is not str or not audience or type(epoch) is not int or epoch<0:
            raise ValueError("invalid epoch anchor initialization")
        with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT epoch FROM session_epoch_anchor WHERE audience=?",(audience,)).fetchone()
            if row is None:
                db.execute("INSERT INTO session_epoch_anchor VALUES (?,?)",(audience,epoch)); return epoch
            if row[0]!=epoch: raise ValueError("anchor already initialized at different epoch")
            return row[0]
    def read_epoch(self,audience):
        with sqlite3.connect(self.path) as db:
            row=db.execute("SELECT epoch FROM session_epoch_anchor WHERE audience=?",(audience,)).fetchone()
        if row is None: raise ValueError("anchor audience not initialized")
        return row[0]
    def compare_and_set(self,audience,expected,new):
        if (type(expected) is not int or type(new) is not int or expected<0
            or new!=expected+1):
            return False
        with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            cur=db.execute("UPDATE session_epoch_anchor SET epoch=? WHERE audience=? AND epoch=?",
                (new,audience,expected))
            return cur.rowcount==1


class RemoteSessionEpochAnchor:
    """Unix-socket client for a separately owned monotonic epoch anchor."""
    def __init__(self,socket_path,timeout=3):
        self.socket_path=str(socket_path); self.timeout=timeout
    def _call(self,payload):
        import json,socket,struct
        body=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout); conn.connect(self.socket_path)
            conn.sendall(struct.pack("!I",len(body))+body)
            header=self._read(conn,4); size=struct.unpack("!I",header)[0]
            if size>4096: raise PermissionError("epoch anchor response too large")
            response=json.loads(self._read(conn,size))
        if type(response) is not dict: raise PermissionError("invalid epoch anchor response")
        return response
    def initialize(self,audience,epoch=0):
        response=self._call({"op":"INITIALIZE","audience":audience,"epoch":epoch})
        if set(response)!={"status","epoch"} or response["status"]!="OK": raise PermissionError("anchor initialization denied")
        return response["epoch"]
    def read_epoch(self,audience):
        response=self._call({"op":"READ","audience":audience})
        if response=={"status":"MISSING"}: raise ValueError("anchor audience not initialized")
        if set(response)!={"status","epoch"} or response["status"]!="OK": raise PermissionError("anchor read denied")
        return response["epoch"]
    def compare_and_set(self,audience,expected,new):
        response=self._call({"op":"CAS","audience":audience,"expected":expected,"new":new})
        return response=={"status":"OK","accepted":True}
    @staticmethod
    def _read(conn,size):
        parts=[]
        while size:
            chunk=conn.recv(size)
            if not chunk: raise PermissionError("epoch anchor connection ended")
            parts.append(chunk); size-=len(chunk)
        return b"".join(parts)
