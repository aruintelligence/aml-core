"""Independent negative-control exercise over real witness subprocesses."""
import json
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_publication import sign_checkpoint
from durable_checkpoint_witness import DurableWitness
from witness_freshness import challenge,verify_fresh
from witness_live_verifier import collect_latest

ROOT=pathlib.Path(__file__).resolve().parent
def cp(epoch=1,head="a"*64):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

def exercise():
    checks={}
    evidence={}
    with tempfile.TemporaryDirectory() as tmp:
        root=pathlib.Path(tmp)
        approver=Ed25519PrivateKey.generate()
        pub=root/"approver.pub"
        pub.write_text(approver.public_key().public_bytes_raw().hex())
        keys={}
        children=[]
        urls={}
        ports={}
        secrets={}
        def launch(name):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1",0))
                port=sock.getsockname()[1]
            process=subprocess.Popen([sys.executable,"-u",str(ROOT/"witness_http_service.py"),
                "--db",str(root/(name+".sqlite")),"--witness-id",name,
                "--private-key-file",str(secrets[name]),"--approver-public-file",str(pub),
                "--port",str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(process)
            ready,_,_=select.select([process.stdout],[],[],5)
            if not ready or "WITNESS_READY" not in process.stdout.readline():
                raise RuntimeError("witness did not become ready")
            ports[name]=port
            urls[name]="http://127.0.0.1:%d"%port
            return process
        def post(name,envelope):
            request=urllib.request.Request(urls[name]+"/publish",
                data=json.dumps(envelope).encode(),method="POST")
            with urllib.request.urlopen(request,timeout=2) as response:
                return json.loads(response.read())
        def fresh(pins=None):
            nonce=challenge()
            responses=collect_latest([urls[n]+"/latest" for n in ("north","south")],nonce)
            return verify_fresh(responses,nonce,keys if pins is None else pins,2,cp())
        try:
            for name in ("north","south"):
                private=Ed25519PrivateKey.generate()
                keys[name]=private.public_key()
                secret=root/(name+".key")
                secret.write_text(private.private_bytes_raw().hex())
                secret.chmod(0o600)
                secrets[name]=secret
                launch(name)
                if post(name,sign_checkpoint(approver,cp()))["status"]!="PUBLISHED":
                    raise AssertionError("initial publication rejected")
            evidence["initial_pids"]=[p.pid for p in children]
            checks["initial_live_quorum"]=fresh()=="FRESH_QUORUM_CONSISTENT"
            substituted=dict(keys)
            substituted["north"]=Ed25519PrivateKey.generate().public_key()
            checks["substituted_pin_rejected"]=fresh(substituted)!="FRESH_QUORUM_CONSISTENT"
            checks["original_pins_restored"]=fresh()=="FRESH_QUORUM_CONSISTENT"
            newer=cp(2,"b"*64)
            checks["authenticated_advance_accepted"]=post("south",sign_checkpoint(approver,newer))["status"]=="PUBLISHED"
            try:
                post("south",sign_checkpoint(approver,cp()))
                checks["authenticated_rollback_rejected"]=False
            except urllib.error.HTTPError as error:
                checks["authenticated_rollback_rejected"]=error.code==409
            checks["cross_witness_fork_rejected"]=fresh()!="FRESH_QUORUM_CONSISTENT"
            # Retain north SQLite across a true process termination and restart.
            old=children[0]
            old.terminate()
            old.wait(timeout=3)
            launch("north")
            evidence["restarted_north_pid"]=children[-1].pid
            checks["restart_preserves_north_checkpoint"]=DurableWitness(
                str(root/"north.sqlite"),"north",
                Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secrets["north"].read_text()))
            ).latest()["payload"]["checkpoint"]==cp()
            checks["restart_does_not_hide_south_fork"]=fresh()!="FRESH_QUORUM_CONSISTENT"
        finally:
            for process in children:
                if process.poll() is None:
                    process.terminate()
            for process in children:
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=3)
    result={"schema":"AML-SEF2-ADVERSARIAL-WITNESS-REPORT-V1",
        "synthetic_only":True,"external_independence_proven":False,
        "checks":checks,"evidence":evidence,
        "result":"PASS" if all(checks.values()) else "FAIL"}
    return result

class WitnessRecoveryControls(unittest.TestCase):
    def test_restart_rollback_fork_and_pins(self):
        result=exercise()
        self.assertEqual(result["result"],"PASS",result)

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--output",required=True)
    a=p.parse_args()
    result=exercise()
    pathlib.Path(a.output).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True,indent=2))
    sys.exit(0 if result["result"]=="PASS" else 2)
