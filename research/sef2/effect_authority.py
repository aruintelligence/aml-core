"""Experimental effect authority: crash-safe local effect commit, not external execution proof.

The only effect is a row in a private SQLite database. The caller must not
have filesystem access to this database. All authorization checks must be
performed by a separately trusted authority before calling commit().
"""
import hashlib
import json
import sqlite3

SCHEMA = "AML-SEF2-EFFECT-V1"

def canonical(effect):
    if (type(effect) is not dict or set(effect) != {"operation_id", "kind", "target", "value"}
        or type(effect["operation_id"]) is not str or not effect["operation_id"]
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
    def __init__(self, path, authorize):
        if not callable(authorize):
            raise TypeError("trusted authorize callback required")
        self.path = str(path)
        self.authorize = authorize
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS effects (operation_id TEXT PRIMARY KEY, digest TEXT NOT NULL, generation INTEGER NOT NULL, value INTEGER NOT NULL)")

    def commit(self, effect, policy_generation):
        try:
            body = canonical(effect)
            if type(policy_generation) is not int or policy_generation < 0:
                return "DENIED"
            digest = hashlib.sha256(SCHEMA.encode() + bytes([0]) + body).hexdigest()
            with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute("SELECT digest FROM effects WHERE operation_id=?", (effect["operation_id"],)).fetchone()
                if existing is not None:
                    db.execute("ROLLBACK")
                    return "ALREADY_APPLIED" if existing[0] == digest else "DENIED"
                # Fail closed on authorization errors. No effects may occur first.
                if self.authorize(effect["operation_id"], digest, policy_generation) is not True:
                    db.execute("ROLLBACK")
                    return "DENIED"
                db.execute("INSERT INTO effects VALUES (?,?,?,?)", (effect["operation_id"], digest, policy_generation, effect["value"]))
                db.execute("COMMIT")
            return "APPLIED"
        except Exception:  # A failing trusted authorizer must never commit an effect
            return "DENIED"
