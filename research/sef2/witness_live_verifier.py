"""Fail-closed live witness challenge verification for strict enterprise bundles."""
import json
import pathlib
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent/'evaluation_kit'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from witness_freshness import challenge,verify_fresh
from verify_quorum import verify_with_quorum
from verify_trusted import load_unique
from external_witness_anchor import anchor_pin,unique
from checkpoint_council import DOMAIN
from signed_receipt import canonical
from cryptography.exceptions import InvalidSignature

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('witness redirect rejected')

DIRECT=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

def collect_latest(endpoints,nonce,timeout=2):
    results=[]
    for url in endpoints:
        if type(url) is not str or not (urlsplit(url).scheme=="http" and urlsplit(url).hostname=="127.0.0.1" and urlsplit(url).port is not None and urlsplit(url).path=="/latest" and not urlsplit(url).query and not urlsplit(url).fragment and not urlsplit(url).username and not urlsplit(url).password):
            raise ValueError("research client accepts loopback witness URLs only")
        request=urllib.request.Request(url,data=json.dumps({"challenge":nonce}).encode(),
            headers={"Content-Type":"application/json"},method="POST")
        with DIRECT.open(request,timeout=timeout) as response:
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
    except (OSError,ValueError,KeyError,TypeError,TimeoutError,OverflowError,urllib.error.URLError):
        # The network gate is fail-closed. Do not disclose or log signing secrets.
        return False

def verify_pinned_live(directory,manifest_path,manifest_pin,history_db,approver_public_hex,
                       checkpoint_path,checkpoint_pin,expected_epoch,witness_keys_path,
                       attestations_path,threshold,endpoints,anchor_files,anchor_pins,nonce=None):
    """Strict live verification additionally requires independently supplied anchor pins."""
    if not verify_live(directory,manifest_path,manifest_pin,history_db,approver_public_hex,
                       checkpoint_path,checkpoint_pin,expected_epoch,witness_keys_path,
                       attestations_path,threshold,endpoints,nonce):
        return False
    try:
        if (type(anchor_files) is not dict or type(anchor_pins) is not dict
            or set(anchor_files)!=set(anchor_pins) or len(anchor_files)!=len(endpoints)):
            return False
        keys=load_unique(witness_keys_path)
        if not set(anchor_files).issubset(set(keys)) or len(set(endpoints))!=len(endpoints):
            return False
        expected=load_unique(checkpoint_path)
        if len(anchor_files)<threshold:
            return False
        for name,path in anchor_files.items():
            anchor=json.loads(pathlib.Path(path).read_text(),object_pairs_hook=unique)
            pin=anchor_pins[name]
            if (type(pin) is not str or len(pin)!=64 or anchor_pin(anchor)!=pin
                or anchor["witness_id"]!=name or anchor["witness_public_hex"]!=keys[name]
                or anchor["checkpoint"]!=expected):
                return False
            payload=anchor["witness_envelope"]["payload"]
            if payload!={"version":1,"witness_id":name,"checkpoint":expected}:
                return False
            key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[name]))
            key.verify(bytes.fromhex(anchor["witness_envelope"]["signature"]),
                       DOMAIN+canonical(payload))
        return True
    except (OSError,ValueError,KeyError,TypeError,InvalidSignature,OverflowError):
        return False
