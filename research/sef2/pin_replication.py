"""Evaluator-independent replicated pin-state gate (synthetic research only).

Each replica is separately administered, append-only SQLite. The evaluator
supplies all replica paths explicitly. A quorum cannot repair a rolled-back
registry automatically; disagreement fails closed. Compromise/rollback of a
quorum of replicas remains outside the guarantee.
"""
import pathlib
import sqlite3
from pin_registry import _pin

class PinReplica:
    def __init__(self,path):
        self.path=str(path)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS history (witness TEXT NOT NULL, generation INTEGER NOT NULL, pin TEXT NOT NULL, PRIMARY KEY(witness,generation))")
    def record(self,witness,generation,pin):
        if type(witness) is not str or not witness or type(generation) is not int or generation<0 or not _pin(pin):
            raise ValueError("invalid replica record")
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT generation,pin FROM history WHERE witness=? ORDER BY generation DESC LIMIT 1",(witness,)).fetchone()
            if row==(generation,pin):
                return "REPLAY"
            if row is None:
                if generation!=0:
                    raise ValueError("must enroll genesis first")
            elif generation!=row[0]+1:
                raise ValueError("non-monotonic replica transition")
            db.execute("INSERT INTO history VALUES (?,?,?)",(witness,generation,pin))
            return "RECORDED"
    def latest(self,witness):
        with sqlite3.connect("file:"+pathlib.Path(self.path).resolve().as_posix()+"?mode=ro",uri=True) as db:
            row=db.execute("SELECT generation,pin FROM history WHERE witness=? ORDER BY generation DESC LIMIT 1",(witness,)).fetchone()
        if row is None:
            raise ValueError("missing replica enrollment")
        return row

def verified_state(registry,witness,replicas,threshold):
    """Accept only unanimous replica state among a required independently supplied quorum.

    Deliberately rejects any stale/advanced/missing replica; this trades
    availability for clear fail-closed semantics.
    """
    if (type(replicas) is not list or type(threshold) is not int or threshold<2
        or len(replicas)<threshold
        or any(type(r) is not PinReplica for r in replicas)
        or len({pathlib.Path(r.path).resolve() for r in replicas})!=len(replicas)
        or pathlib.Path(registry.path).resolve() in {pathlib.Path(r.path).resolve() for r in replicas}):
        raise ValueError("invalid independent replica configuration")
    state=registry.state(witness)
    expected=(state["generation"],state["active"])
    for replica in replicas:
        if replica.latest(witness)!=expected:
            raise ValueError("registry and independent replica disagreement")
    return state

def replicate_committed(registry,witness,replicas,threshold):
    """Record a completed transition; any unavailable replica fails closed."""
    state=registry.state(witness)
    if (type(replicas) is not list or type(threshold) is not int or len(replicas)<threshold or threshold<2):
        raise ValueError("insufficient replicas")
    # Before writing, require all replicas to be at the same predecessor
    # (or already at the target after an interrupted replication).
    target=(state["generation"],state["active"])
    latests=[replica.latest(witness) for replica in replicas]
    predecessors={row for row in latests if row!=target}
    if (len(predecessors)>1 or
        any(row[0]!=state["generation"]-1 for row in predecessors)):
        raise ValueError("replica cannot be advanced safely")
    for replica in replicas:
        replica.record(witness,state["generation"],state["active"])
    return verified_state(registry,witness,replicas,threshold)
