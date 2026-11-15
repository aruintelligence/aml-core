"""Independent reference verifier for recovery anchor quorum certificates.

Deliberately does not import recovery_anchor_quorum or its policy helpers.
The verifier receives the policy and expected predecessor pin from a trusted
out-of-band channel. It checks the complete certificate deterministically.
"""
import hashlib,json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

POLICY_SCHEMA="AML-SEF2-RECOVERY-ANCHOR-POLICY-V1"
PAYLOAD_SCHEMA="AML-SEF2-RECOVERY-ANCHOR-PAYLOAD-V1"
CERT_SCHEMA="AML-SEF2-RECOVERY-ANCHOR-CERTIFICATE-V1"
CHECKPOINT_SCHEMA="AML-SEF2-RECOVERY-AUTHORITY-LEDGER-CHECKPOINT-V1"
DOMAIN=b"AML-SEF2-INDEPENDENT-RECOVERY-ANCHOR-V1\x00"

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode("utf-8")

def _unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError("duplicate JSON key")
        result[key]=value
    return result

def _hash(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def _policy_ok(policy):
    if type(policy) is not dict or set(policy)!={"schema","policy_id","threshold","max_faults","authorities","administrative_domains"}:
        return False
    if policy["schema"]!=POLICY_SCHEMA or type(policy["policy_id"]) is not str or not policy["policy_id"]:
        return False
    members=policy["authorities"]; q=policy["threshold"]; f=policy["max_faults"]; domains=policy["administrative_domains"]
    if (type(members) is not dict or type(q) is not int or type(f) is not int
        or type(domains) is not dict or set(domains)!=set(members)): return False
    n=len(members)
    if f<0 or n<3*f+1 or q<1 or q>n-f or 2*q-n<=f: return False
    keys=set(); seen_domains=set()
    for name,encoded in members.items():
        if type(name) is not str or not name or type(encoded) is not str: return False
        try: raw=bytes.fromhex(encoded)
        except ValueError: return False
        domain=domains[name]
        if type(domain) is not str or not domain or domain in seen_domains: return False
        if len(raw)!=32 or raw in keys: return False
        keys.add(raw); seen_domains.add(domain)
    return True

def verify_anchor_certificate(payload,certificate,policy,expected_sequence,
        expected_previous_pin,expected_target_authority_id,expected_authority_key_sha256):
    try:
        if not _policy_ok(policy): return False
        if type(payload) is not dict or set(payload)!={"schema","policy_id","target_authority_id",
            "sequence","previous_pin_sha256","checkpoint","checkpoint_pin_sha256"}: return False
        if type(expected_sequence) is not int or expected_sequence<1: return False
        if not _hash(expected_previous_pin) or not _hash(expected_authority_key_sha256): return False
        if type(expected_target_authority_id) is not str or not expected_target_authority_id: return False
        checkpoint=payload["checkpoint"]
        if type(checkpoint) is not dict or set(checkpoint)!={"schema","authority_id",
            "authority_key_sha256","sequence","head_hash"}: return False
        if (checkpoint["schema"]!=CHECKPOINT_SCHEMA or type(checkpoint["sequence"]) is not int
            or checkpoint["sequence"]<0 or not _hash(checkpoint["authority_key_sha256"])
            or not _hash(checkpoint["head_hash"])): return False
        checkpoint_pin=hashlib.sha256(canonical(checkpoint)).hexdigest()
        if (payload["schema"]!=PAYLOAD_SCHEMA or payload["policy_id"]!=policy["policy_id"]
            or type(payload["sequence"]) is not int or payload["sequence"]!=expected_sequence
            or payload["previous_pin_sha256"]!=expected_previous_pin
            or payload["target_authority_id"]!=expected_target_authority_id
            or checkpoint["authority_id"]!=expected_target_authority_id
            or checkpoint["authority_key_sha256"]!=expected_authority_key_sha256
            or payload["checkpoint_pin_sha256"]!=checkpoint_pin):
            return False
        if type(certificate) is not dict or set(certificate)!={"schema","policy_sha256","payload_sha256","approvals"}:
            return False
        policy_sha256=hashlib.sha256(canonical(policy)).hexdigest()
        payload_sha256=hashlib.sha256(canonical(payload)).hexdigest()
        approvals=certificate["approvals"]
        if (certificate["schema"]!=CERT_SCHEMA or certificate["policy_sha256"]!=policy_sha256
            or certificate["payload_sha256"]!=payload_sha256 or type(approvals) is not list
            or len(approvals)<policy["threshold"]): return False
        statement=DOMAIN+canonical({"policy_sha256":policy_sha256,"payload_sha256":payload_sha256})
        identities=[]
        for item in approvals:
            if type(item) is not dict or set(item)!={"anchor_id","signature"}: return False
            identity=item["anchor_id"]
            if type(identity) is not str or identity not in policy["authorities"] or identity in identities: return False
            identities.append(identity)
            signature=bytes.fromhex(item["signature"])
            if len(signature)!=64: return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy["authorities"][identity])).verify(signature,statement)
        return identities==sorted(identities)
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,AttributeError,UnicodeDecodeError):
        return False

def verify_json_bundle(raw):
    """Parse a JSON evidence object with duplicate-key rejection."""
    try:
        if type(raw) is bytes: raw=raw.decode("utf-8")
        if type(raw) is str: return json.loads(raw,object_pairs_hook=_unique_object)
        return None
    except (ValueError,UnicodeDecodeError,TypeError):
        return None
