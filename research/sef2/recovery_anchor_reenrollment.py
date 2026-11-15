"""Dual-consent state transfer for fresh recovery anchor witnesses after policy rotation."""
import hashlib,sqlite3
from signed_receipt import canonical
from threshold_recovery import POLICY_SCHEMA as RECOVERY_POLICY_SCHEMA,make_approval_bundle,verify_approval_bundle
from recovery_anchor_quorum import validate_anchor_policy,policy_digest,RecoveryAnchorWitness
from recovery_anchor_policy_rotation import verify_anchor_policy_rotation
SCHEMA="AML-SEF2-RECOVERY-ANCHOR-REENROLLMENT-V1"
def _shadow(policy):
 return {"schema":RECOVERY_POLICY_SCHEMA,"policy_id":policy["policy_id"],"threshold":policy["threshold"],"max_faults":policy["max_faults"],"authorities":dict(policy["authorities"])}
def make_anchor_reenrollment(current_policy,next_policy,rotation,rotation_generation,rotation_previous_pin,target_authority_id,current_sequence,current_pin,old_signers,new_signers):
 if not verify_anchor_policy_rotation(current_policy,next_policy,rotation,rotation_generation,rotation_previous_pin): raise ValueError("invalid anchor policy rotation")
 if type(target_authority_id) is not str or not target_authority_id: raise ValueError("invalid target authority")
 if type(current_sequence) is not int or current_sequence<0: raise ValueError("invalid current sequence")
 if type(current_pin) is not str or len(current_pin)!=64 or any(c not in "0123456789abcdef" for c in current_pin): raise ValueError("invalid current pin")
 payload={"schema":SCHEMA,"witness_id":target_authority_id,"generation":rotation_generation,
  "previous_state_sha256":hashlib.sha256(canonical({"sequence":current_sequence,"pin":current_pin})).hexdigest(),
  "rotation_sha256":hashlib.sha256(canonical(rotation)).hexdigest(),
  "previous_policy_sha256":policy_digest(current_policy),"next_policy_sha256":policy_digest(next_policy),
  "target_authority_id":target_authority_id,"current_sequence":current_sequence,"current_pin":current_pin}
 return {"schema":SCHEMA,"payload":payload,
  "outgoing_state_approval":make_approval_bundle(payload,_shadow(current_policy),old_signers),
  "incoming_state_acceptance":make_approval_bundle(payload,_shadow(next_policy),new_signers)}
def verify_anchor_reenrollment(current_policy,next_policy,rotation,proof,expected_rotation_generation,expected_rotation_previous_pin,expected_target_authority_id,expected_sequence,expected_pin):
 try:
  if not verify_anchor_policy_rotation(current_policy,next_policy,rotation,expected_rotation_generation,expected_rotation_previous_pin): return False
  if type(proof) is not dict or set(proof)!={"schema","payload","outgoing_state_approval","incoming_state_acceptance"}: return False
  p=proof["payload"]; required={"schema","witness_id","generation","previous_state_sha256","rotation_sha256","previous_policy_sha256","next_policy_sha256","target_authority_id","current_sequence","current_pin"}
  if type(p) is not dict or set(p)!=required: return False
  state_digest=hashlib.sha256(canonical({"sequence":expected_sequence,"pin":expected_pin})).hexdigest()
  if (proof["schema"]!=SCHEMA or p["schema"]!=SCHEMA or p["witness_id"]!=expected_target_authority_id
      or p["target_authority_id"]!=expected_target_authority_id or p["generation"]!=expected_rotation_generation
      or p["current_sequence"]!=expected_sequence or p["current_pin"]!=expected_pin
      or p["previous_state_sha256"]!=state_digest or p["rotation_sha256"]!=hashlib.sha256(canonical(rotation)).hexdigest()
      or p["previous_policy_sha256"]!=policy_digest(current_policy) or p["next_policy_sha256"]!=policy_digest(next_policy)): return False
  return verify_approval_bundle(p,proof["outgoing_state_approval"],_shadow(current_policy)) and verify_approval_bundle(p,proof["incoming_state_acceptance"],_shadow(next_policy))
 except (ValueError,TypeError,KeyError,AttributeError,OverflowError): return False
def install_anchor_reenrollment(witness,current_policy,next_policy,rotation,proof,expected_rotation_generation,expected_rotation_previous_pin,target_authority_id,current_sequence,current_pin):
 if not isinstance(witness,RecoveryAnchorWitness): return "INVALID_WITNESS"
 if not verify_anchor_reenrollment(current_policy,next_policy,rotation,proof,expected_rotation_generation,expected_rotation_previous_pin,target_authority_id,current_sequence,current_pin): return "INVALID_REENROLLMENT"
 if witness.anchor_id not in next_policy["authorities"]: return "WITNESS_NOT_IN_SUCCESSOR_POLICY"
 if witness.public_key().public_bytes_raw().hex()!=next_policy["authorities"][witness.anchor_id]: return "WITNESS_KEY_MISMATCH"
 try:
  with sqlite3.connect(witness.database_path,timeout=10) as con:
   con.execute("PRAGMA synchronous=FULL"); con.execute("BEGIN IMMEDIATE")
   row=con.execute("SELECT sequence,pin_sha256,policy_id,policy_sha256 FROM anchor_state WHERE target_authority_id=?",(target_authority_id,)).fetchone()
   expected=(current_sequence,current_pin,next_policy["policy_id"],policy_digest(next_policy))
   if row is not None: return "ALREADY_INSTALLED" if tuple(row)==expected else "STATE_CONFLICT"
   votes=con.execute("SELECT COUNT(*) FROM anchor_votes WHERE target_authority_id=?",(target_authority_id,)).fetchone()[0]
   if votes: return "STATE_CONFLICT"
   con.execute("INSERT INTO anchor_state VALUES (?,?,?,?,?)",(target_authority_id,current_sequence,current_pin,next_policy["policy_id"],policy_digest(next_policy)))
  return "INSTALLED"
 except sqlite3.Error: return "STORE_ERROR"
