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
from checkpoint_council import DOMAIN,valid_checkpoint
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
        results.append(json.loads(raw,object_pairs_hook=unique))
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
    """Fail-closed explicit witness-id to endpoint binding and pinned live quorum.

    endpoints MUST be a dict {witness_id: exact_loopback_url}.  A list or an
    unbound endpoint is rejected; each response must name the requested identity.
    All participating witness anchors must be pinned independently.
    """
    if not verify_with_quorum(directory,manifest_path,manifest_pin,history_db,
                              approver_public_hex,checkpoint_path,checkpoint_pin,
                              expected_epoch,witness_keys_path,attestations_path,threshold):
        return False
    try:
        if (type(endpoints) is not dict or type(anchor_files) is not dict
            or type(anchor_pins) is not dict or type(threshold) is not int
            or threshold<2 or len(endpoints)<threshold
            or set(endpoints)!=set(anchor_files) or set(endpoints)!=set(anchor_pins)
            or len(set(endpoints.values()))!=len(endpoints)):
            return False
        keys_hex=load_unique(witness_keys_path)
        attestations=load_unique(attestations_path)
        if type(attestations) is not list or len(attestations)<threshold:
            return False
        attested=[]
        for receipt in attestations:
            if type(receipt) is not dict or type(receipt.get("payload")) is not dict:
                return False
            identity=receipt["payload"].get("witness_id")
            if type(identity) is not str or not identity:
                return False
            attested.append(identity)
        if (len(set(attested))!=len(attested) or set(endpoints)!=set(attested)
            or not set(endpoints).issubset(keys_hex)
            or len(set(keys_hex.values()))!=len(keys_hex)):
            return False
        keys={name:Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys_hex[name]))
              for name in endpoints}
        expected=load_unique(checkpoint_path)
        if not valid_checkpoint(expected):
            return False
        for name in endpoints:
            anchor=json.loads(pathlib.Path(anchor_files[name]).read_text(),object_pairs_hook=unique)
            pin=anchor_pins[name]
            if (type(pin) is not str or len(pin)!=64
                or type(anchor) is not dict
                or set(anchor)!={"schema","witness_id","witness_public_hex","checkpoint","witness_envelope"}
                or anchor["schema"]!="AML-SEF2-EXTERNAL-WITNESS-ANCHOR-V1"
                or anchor_pin(anchor)!=pin
                or anchor["witness_id"]!=name or anchor["witness_public_hex"]!=keys_hex[name]
                or anchor["checkpoint"]!=expected):
                return False
            envelope=anchor["witness_envelope"]
            if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
                return False
            payload=envelope["payload"]
            if payload!={"version":1,"witness_id":name,"checkpoint":expected}:
                return False
            keys[name].verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(payload))
        n=challenge() if nonce is None else nonce
        responses=[]
        for name,url in endpoints.items():
            response=collect_latest([url],n)[0]
            if (type(response) is not dict or type(response.get("payload")) is not dict
                or response["payload"].get("witness_id")!=name):
                return False
            responses.append(response)
        return verify_fresh(responses,n,keys,threshold,expected)=="FRESH_QUORUM_CONSISTENT"
    except (OSError,ValueError,KeyError,TypeError,InvalidSignature,OverflowError,
            TimeoutError,urllib.error.URLError):
        return False
