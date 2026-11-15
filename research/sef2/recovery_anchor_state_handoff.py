"""Dual-consent state handoff for recovery-anchor council rotation.

The policy-rotation proof changes who is trusted. This protocol separately binds
the exact monotonic pin state that the successor council is allowed to inherit.
Both outgoing and incoming councils approve the same handoff before a fresh
RecoveryAnchorWitness database can be bootstrapped.
"""
import hashlib,sqlite3
from signed_receipt import canonical
from threshold_recovery import (POLICY_SCHEMA as RECOVERY_POLICY_SCHEMA,
    RecoveryAuthoritySigner,make_approval_bundle,verify_approval_bundle)
from recovery_anchor_quorum import RecoveryAnchorWitness,validate_anchor_policy,policy_digest
from recovery_anchor_policy_rotation import verify_anchor_policy_rotation

SCHEMA="AML-SEF2-RECOVERY-ANCHOR-STATE-HANDOFF-V1"

def _shadow(policy):
    return {"schema":RECOVERY_POLICY_SCHEMA,"policy_id":policy["policy_id"],
        "threshold":policy["threshold"],"max_faults":policy["max_faults"],
        "authorities":dict(policy["authorities"])}

def _hex64(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def validate_targets(targets):
    return (type(targets) in (list,tuple) and len(targets)>0
        and all(type(target) is str and target for target in targets)
        and list(targets)==sorted(set(targets)))

def validate_state_snapshot(snapshot,expected_targets):
    if (type(snapshot) is not dict or not snapshot or list(snapshot)!=sorted(snapshot)
        or not validate_targets(expected_targets) or set(snapshot)!=set(expected_targets)):
        return False
    for target,state in snapshot.items():
        if (type(target) is not str or not target or type(state) is not dict
            or set(state)!={"sequence","pin_sha256"}
            or type(state["sequence"]) is not int or state["sequence"]<0
            or not _hex64(state["pin_sha256"])):
            return False
    return True

def make_anchor_state_handoff(current_policy,next_policy,rotation,expected_generation,
                              expected_previous_anchor_pin,expected_targets,state_snapshot,
                              outgoing_signers,incoming_signers):
    if not verify_anchor_policy_rotation(current_policy,next_policy,rotation,
            expected_generation,expected_previous_anchor_pin):
        raise ValueError("invalid anchor policy rotation")
    if not validate_state_snapshot(state_snapshot,expected_targets):
        raise ValueError("invalid or incomplete anchor state snapshot")
    if (type(outgoing_signers) is not dict or type(incoming_signers) is not dict
        or any(not isinstance(s,RecoveryAuthoritySigner) for s in outgoing_signers.values())
        or any(not isinstance(s,RecoveryAuthoritySigner) for s in incoming_signers.values())):
        raise ValueError("durable anti-equivocation signers required for anchor state handoff")
    payload={"schema":SCHEMA,"generation":expected_generation,
        "rotation_sha256":hashlib.sha256(canonical(rotation)).hexdigest(),
        "previous_policy_sha256":policy_digest(current_policy),
        "next_policy_sha256":policy_digest(next_policy),
        "tracked_targets":list(expected_targets),
        "state_snapshot":state_snapshot}
    return {"payload":payload,
        "outgoing_state_approval":make_approval_bundle(payload,_shadow(current_policy),outgoing_signers),
        "incoming_state_acceptance":make_approval_bundle(payload,_shadow(next_policy),incoming_signers)}

def verify_anchor_state_handoff(current_policy,next_policy,rotation,handoff,
                                expected_generation,expected_previous_anchor_pin,
                                expected_targets):
    try:
        if not verify_anchor_policy_rotation(current_policy,next_policy,rotation,
                expected_generation,expected_previous_anchor_pin):
            return False
        if type(handoff) is not dict or set(handoff)!={"payload",
            "outgoing_state_approval","incoming_state_acceptance"}:
            return False
        p=handoff["payload"]
        if type(p) is not dict or set(p)!={"schema","generation","rotation_sha256",
            "previous_policy_sha256","next_policy_sha256","tracked_targets","state_snapshot"}:
            return False
        if (p["schema"]!=SCHEMA or p["generation"]!=expected_generation
            or p["rotation_sha256"]!=hashlib.sha256(canonical(rotation)).hexdigest()
            or p["previous_policy_sha256"]!=policy_digest(current_policy)
            or p["next_policy_sha256"]!=policy_digest(next_policy)
            or p["tracked_targets"]!=list(expected_targets)
            or not validate_state_snapshot(p["state_snapshot"],expected_targets)):
            return False
        return (verify_approval_bundle(p,handoff["outgoing_state_approval"],_shadow(current_policy))
            and verify_approval_bundle(p,handoff["incoming_state_acceptance"],_shadow(next_policy)))
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False


def _validate_successor_database_schema(con,witness):
    """Reject pre-seeded triggers, views, tables, and altered table layouts."""
    objects=con.execute("""SELECT type,name FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name""").fetchall()
    allowed={"anchor_meta","anchor_state","anchor_votes","anchor_policy_handoff"}
    if any(kind!="table" or name not in allowed for kind,name in objects):
        raise ValueError("successor anchor database contains unexpected schema objects")
    names={name for kind,name in objects}
    required={"anchor_meta","anchor_state","anchor_votes"}
    if not required.issubset(names):
        raise ValueError("successor anchor database schema is incomplete")
    expected={
        "anchor_meta":("key","value"),
        "anchor_state":("target_authority_id","sequence","pin_sha256","policy_id","policy_sha256"),
        "anchor_votes":("target_authority_id","sequence","policy_id","policy_sha256",
            "previous_pin_sha256","checkpoint_pin_sha256","payload_sha256","signature"),
        "anchor_policy_handoff":("generation","handoff_sha256","rotation_sha256")}
    for table in names:
        columns=tuple(row[1] for row in con.execute("PRAGMA table_info("+table+")"))
        if columns!=expected[table]:
            raise ValueError("successor anchor database table layout is not canonical")
    metadata=dict(con.execute("SELECT key,value FROM anchor_meta").fetchall())
    key_hash=hashlib.sha256(witness.public_key().public_bytes_raw()).hexdigest()
    if metadata!={"anchor_id":witness.anchor_id,"anchor_key_sha256":key_hash}:
        raise ValueError("successor anchor database identity metadata mismatch")

def bootstrap_successor_anchor(witness,current_policy,next_policy,rotation,handoff,
                               expected_generation,expected_previous_anchor_pin,
                               expected_targets):
    if not isinstance(witness,RecoveryAnchorWitness):
        raise ValueError("RecoveryAnchorWitness required")
    if not verify_anchor_state_handoff(current_policy,next_policy,rotation,handoff,
            expected_generation,expected_previous_anchor_pin,expected_targets):
        raise ValueError("invalid anchor state handoff")
    if (witness.anchor_id not in next_policy["authorities"]
        or witness.public_key().public_bytes_raw().hex()!=next_policy["authorities"][witness.anchor_id]):
        raise ValueError("successor anchor identity/key mismatch")
    snapshot=handoff["payload"]["state_snapshot"]
    with sqlite3.connect(witness.database_path,timeout=10) as con:
        con.execute("PRAGMA synchronous=FULL"); con.execute("BEGIN IMMEDIATE")
        _validate_successor_database_schema(con,witness)
        if con.execute("SELECT COUNT(*) FROM anchor_state").fetchone()[0]:
            raise ValueError("successor anchor database already contains state")
        if con.execute("SELECT COUNT(*) FROM anchor_votes").fetchone()[0]:
            raise ValueError("successor anchor database already contains votes")
        con.execute("""CREATE TABLE IF NOT EXISTS anchor_policy_handoff (
            generation INTEGER PRIMARY KEY, handoff_sha256 TEXT NOT NULL,
            rotation_sha256 TEXT NOT NULL)""")
        if con.execute("SELECT COUNT(*) FROM anchor_policy_handoff").fetchone()[0]:
            raise ValueError("successor anchor database already contains a handoff")
        pd=policy_digest(next_policy)
        for target,state in snapshot.items():
            con.execute("INSERT INTO anchor_state VALUES (?,?,?,?,?)",
                (target,state["sequence"],state["pin_sha256"],next_policy["policy_id"],pd))
        con.execute("INSERT INTO anchor_policy_handoff VALUES (?,?,?)",
            (expected_generation,hashlib.sha256(canonical(handoff)).hexdigest(),
             hashlib.sha256(canonical(rotation)).hexdigest()))
    return "BOOTSTRAPPED"
