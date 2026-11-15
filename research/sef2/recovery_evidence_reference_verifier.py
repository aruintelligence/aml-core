"""Independent verifier for a complete recovery-authority evidence bundle."""
import argparse,hashlib,sys
from pathlib import Path
from recovery_ledger_reference_verifier import verify_ledger
from recovery_anchor_reference_verifier import verify_anchor_certificate,verify_json_bundle
BUNDLE_SCHEMA="AML-SEF2-RECOVERY-EVIDENCE-BUNDLE-V1"
def _hash(value): return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)
def verify_recovery_evidence(bundle,authority_public_key_hex,anchor_policy,expected_anchor_sequence,expected_previous_anchor_pin):
 try:
  if type(bundle) is not dict or set(bundle)!={"schema","authority_id","ledger","checkpoint","anchor_payload","anchor_certificate"}: return False
  if bundle["schema"]!=BUNDLE_SCHEMA or type(bundle["authority_id"]) is not str or not bundle["authority_id"]: return False
  ledger=bundle["ledger"]; checkpoint=bundle["checkpoint"]; payload=bundle["anchor_payload"]; certificate=bundle["anchor_certificate"]
  if type(checkpoint) is not dict or set(checkpoint)!={"schema","authority_id","authority_key_sha256","sequence","head_hash"}: return False
  if checkpoint["authority_id"]!=bundle["authority_id"] or type(checkpoint["sequence"]) is not int or checkpoint["sequence"]<0 or not _hash(checkpoint["authority_key_sha256"]) or not _hash(checkpoint["head_hash"]): return False
  raw_key=bytes.fromhex(authority_public_key_hex)
  if len(raw_key)!=32 or hashlib.sha256(raw_key).hexdigest()!=checkpoint["authority_key_sha256"]: return False
  if not verify_ledger(ledger,authority_public_key_hex,checkpoint["head_hash"]): return False
  if ledger.get("authority_id")!=bundle["authority_id"]: return False
  if not verify_anchor_certificate(payload,certificate,anchor_policy,expected_anchor_sequence,expected_previous_anchor_pin,bundle["authority_id"],checkpoint["authority_key_sha256"]): return False
  if payload.get("checkpoint")!=checkpoint: return False
  return True
 except (ValueError,TypeError,KeyError,OverflowError,AttributeError): return False
def parse_json(path):
 raw=Path(path).read_bytes(); value=verify_json_bundle(raw)
 if value is None: raise ValueError("invalid JSON or duplicate keys")
 return value
def main(argv=None):
 p=argparse.ArgumentParser(description="Verify an AML recovery authority evidence bundle")
 p.add_argument("bundle",type=Path); p.add_argument("--authority-public-key",required=True)
 p.add_argument("--anchor-policy",type=Path,required=True); p.add_argument("--anchor-sequence",type=int,required=True)
 p.add_argument("--previous-anchor-pin",required=True); a=p.parse_args(argv)
 try: bundle=parse_json(a.bundle); policy=parse_json(a.anchor_policy)
 except (OSError,ValueError) as exc: print("UNREADABLE:",exc,file=sys.stderr); return 2
 if not verify_recovery_evidence(bundle,a.authority_public_key,policy,a.anchor_sequence,a.previous_anchor_pin):
  print("INVALID: recovery evidence linkage, signatures, quorum, or pins failed"); return 1
 print("VALID: recovery ledger, checkpoint, authority key, and anchor quorum are linked"); return 0
if __name__=="__main__": raise SystemExit(main())
