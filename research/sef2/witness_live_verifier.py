"""Fail-closed live witness challenge verification for strict enterprise bundles."""
import json
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from witness_freshness import challenge,verify_fresh
from verify_quorum import verify_with_quorum
from verify_trusted import load_unique

def collect_latest(endpoints,nonce,timeout=2):
    results=[]
    for url in endpoints:
        if type(url) is not str or not url.startswith("http://127.0.0.1:"):
            raise ValueError("research client accepts loopback witness URLs only")
        request=urllib.request.Request(url,data=json.dumps({"challenge":nonce}).encode(),
            headers={"Content-Type":"application/json"},method="POST")
        with urllib.request.urlopen(request,timeout=timeout) as response:
            if response.status!=200:
                raise ValueError("witness failed")
            raw=response.read(8193)
            if len(raw)>8192:
                raise ValueError("oversize witness response")
        results.append(json.loads(raw))
    return results

def verify_live(directory,manifest_path,manifest_pin,history_db,approver_public_hex,
                checkpoint_path,checkpoint_pin,expected_epoch,witness_keys_path,
                attestations_path,threshold,endpoints,nonce=None):
    if not verify_with_quorum(directory,manifest_path,manifest_pin,history_db,
                              approver_public_hex,checkpoint_path,checkpoint_pin,expected_epoch,
                              witness_keys_path,attestations_path,threshold):
        return False
    try:
        if type(endpoints) is not list or len(endpoints)<threshold:
            return False
        pins=load_unique(witness_keys_path)
        keys={name:Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw))
              for name,raw in pins.items()}
        n=challenge() if nonce is None else nonce
        responses=collect_latest(endpoints,n)
        return verify_fresh(responses,n,keys,threshold,load_unique(checkpoint_path))=="FRESH_QUORUM_CONSISTENT"
    except (OSError,ValueError,KeyError,TypeError,TimeoutError,OverflowError,Exception) as exc:
        # The network gate is fail-closed. Do not disclose or log signing secrets.
        return False
