"""Experimental effect authority: crash-safe local effect commit, not external execution proof.

The only effect is a row in a private SQLite database. The caller must not
have filesystem access to this database. All authorization checks must be
performed by a separately trusted authority before calling commit().
"""
import hashlib
import json
import os
import sqlite3

SCHEMA = "AML-SEF2-EFFECT-V1"

def canonical(effect):
    if (type(effect) is not dict or set(effect) != {"operation_id", "kind", "target", "value"}
        or type(effect["operation_id"]) is not str or not 1 <= len(effect["operation_id"]) <= 128
        or not effect["operation_id"].isascii() or not effect["operation_id"].isprintable()
        or effect["kind"] != "fixture:write"
        or effect["target"] != "fixture:protected"
        or type(effect["value"]) is not int or not 0 <= effect["value"] <= 100):
        raise ValueError("invalid effect")
    return json.dumps(effect, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

class EffectAuthority:
    """The authorization callback is trusted and runs inside the isolated boundary.

    authorize(operation_id, digest, policy_generation) returns exactly True or
    False; its state MUST be independently protected and monotonic. This adapter
    does not itself provide cryptographic authorization or external anti-rollback.
    """
    def __init__(self, path, authorize, external_floor=None, require_existing=False, reserve_operation=None):
        if not callable(authorize):
            raise TypeError("trusted authorize callback required")
        self.path = str(path)
        if type(require_existing) is not bool:
            raise TypeError("require_existing must be bool")
        if require_existing and not os.path.isfile(self.path):
            raise ValueError("effect database absent: explicit bootstrap required")
        self.authorize = authorize
        if external_floor is not None and not callable(external_floor):
            raise TypeError("external floor must be callable")
        self.external_floor = external_floor
        if reserve_operation is not None and not callable(reserve_operation):
            raise TypeError('reservation callback must be callable')
        self.reserve_operation = reserve_operation
        # Initialize only a genuinely empty database. Missing security state in
        # an existing database is corruption/tampering, never a reset signal.
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            existing = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if not existing and require_existing:
                db.execute("ROLLBACK")
                raise ValueError("existing effect database has no security state")
            if not existing:
                db.execute("CREATE TABLE effects (operation_id TEXT PRIMARY KEY, digest TEXT NOT NULL, generation INTEGER NOT NULL, value INTEGER NOT NULL)")
                db.execute("CREATE TABLE policy_floor (singleton INTEGER PRIMARY KEY CHECK (singleton=1), generation INTEGER NOT NULL CHECK (generation>=0))")
                db.execute("INSERT INTO policy_floor VALUES (1, 0)")
            elif not {"effects", "policy_floor"}.issubset(existing):
                db.execute("ROLLBACK")
                raise ValueError("existing effect database has missing security tables")
            floor = db.execute("SELECT generation FROM policy_floor WHERE singleton=1").fetchall()
            if len(floor) != 1 or type(floor[0][0]) is not int or floor[0][0] < 0:
                db.execute("ROLLBACK")
                raise ValueError("existing effect database has invalid policy floor")
            db.execute("COMMIT")

    def advance_policy_floor(self, generation):
        """Local monotonic revocation floor; NOT resistant to database rollback."""
        if type(generation) is not int or generation < 0:
            return False
        try:
            with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                updated = db.execute("UPDATE policy_floor SET generation = MAX(generation, ?) WHERE singleton=1", (generation,))
                if updated.rowcount != 1:
                    db.execute("ROLLBACK")
                    return False
                db.execute("COMMIT")
            return True
        except sqlite3.Error:
            return False

    def commit(self, effect, policy_generation):
        try:
            body = canonical(effect)
            if type(policy_generation) is not int or policy_generation < 0:
                return "DENIED"
            digest = hashlib.sha256(SCHEMA.encode() + bytes([0]) + body).hexdigest()
            with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                floor = db.execute("SELECT generation FROM policy_floor WHERE singleton=1").fetchone()
                # A separately trusted monotonic checkpoint detects stale local
                # state. Refuse execution until local state catches up.
                external = self.external_floor() if self.external_floor is not None else None
                if (floor is None
                    or (self.external_floor is not None and
                        (type(external) is not int or external < 0 or floor[0] < external))
                    or policy_generation < floor[0]):
                    db.execute("ROLLBACK")
                    return "DENIED"
                existing = db.execute("SELECT digest FROM effects WHERE operation_id=?", (effect["operation_id"],)).fetchone()
                if existing is not None:
                    db.execute("ROLLBACK")
                    return "ALREADY_APPLIED" if existing[0] == digest else "DENIED"
                # Fail closed on authorization errors. No effects may occur first.
                if self.authorize(effect["operation_id"], digest, policy_generation) is not True:
                    db.execute("ROLLBACK")
                    return "DENIED"
                # Independently durable reservation must precede local effect.
                # Failed reservation or exception denies without local effect.
                if (self.reserve_operation is not None and
                    self.reserve_operation(effect["operation_id"], digest, policy_generation) is not True):
                    db.execute("ROLLBACK")
                    return "DENIED"
                db.execute("INSERT INTO effects VALUES (?,?,?,?)", (effect["operation_id"], digest, policy_generation, effect["value"]))
                db.execute("COMMIT")
            return "APPLIED"
        except Exception:  # A failing trusted authorizer must never commit an effect
            return "DENIED"
