"""Real four-process recovery anchor quorum under distinct Linux UIDs."""
import os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from test_cross_uid_boundary import drop,HERE
from threshold_recovery import SignedRecoveryHeadAnchor,QuorumRecoveryHeadAnchor
from recovery_head_anchor_service import UnixRecoveryHeadAnchorTransport

def start(account,anchor_id,sock,state,lib,signer,env):
    private=state/"key.pem"; public=state/"key.pub"; db=state/"anchor.sqlite"
    proc=subprocess.Popen([sys.executable,str(lib/"recovery_head_anchor_service.py"),anchor_id,
        str(sock),str(db),str(private),str(public),str(signer.pw_uid),str(signer.pw_gid)],
        preexec_fn=drop(account.pw_uid,account.pw_gid,(signer.pw_gid,)),env=env,
        stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    for _ in range(200):
        if proc.poll() is not None: raise AssertionError("anchor exited: "+proc.stderr.read())
        if sock.exists() and public.exists():
            time.sleep(.03); return proc,public,db
        time.sleep(.02)
    proc.terminate(); raise AssertionError("anchor startup timeout")
def stop(proc):
    proc.terminate()
    try: proc.communicate(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.communicate(timeout=5)
def main():
    if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
    signer=pwd.getpwnam("aml_signer_test"); client=pwd.getpwnam("aml_client_test")
    accounts=[pwd.getpwnam(f"aml_ra{i}_test") for i in range(4)]
    assert len({signer.pw_uid,client.pw_uid,*[a.pw_uid for a in accounts]})==6
    with tempfile.TemporaryDirectory(prefix="aml-recovery-anchor-process-") as tmp:
        root=pathlib.Path(tmp); root.chmod(0o755)
        lib=root/"lib"; lib.mkdir(mode=0o755)
        for name in ("recovery_head_anchor_service.py","threshold_recovery.py","signed_receipt.py"):
            target=lib/name; shutil.copyfile(HERE/name,target); target.chmod(0o644)
        env=dict(os.environ,PYTHONPATH=str(lib))
        procs=[]; anchors=[]; dbs=[]
        try:
            for i,account in enumerate(accounts):
                state=root/f"state-{i}"; state.mkdir(mode=0o700); os.chown(state,account.pw_uid,account.pw_gid)
                ipc=root/f"ipc-{i}"; ipc.mkdir(mode=0o711); os.chown(ipc,account.pw_uid,account.pw_gid)
                sock=ipc/"anchor.sock"
                proc,public,db=start(account,f"anchor-{i}",sock,state,lib,signer,env); procs.append(proc); dbs.append(db)
                key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(public.read_text().strip()))
                anchors.append(SignedRecoveryHeadAnchor(f"anchor-{i}",key,UnixRecoveryHeadAnchorTransport(sock)))
            quorum=QuorumRecoveryHeadAnchor(anchors,3,1)
            zero="0"*64; first="a"*64; second="b"*64
            # The anchor services intentionally accept only the signer UID.
            # Exercise the client as that principal rather than root; root is
            # reserved for provisioning and lifecycle management in this harness.
            os.setegid(signer.pw_gid); os.seteuid(signer.pw_uid)
            try:
                assert quorum.read_head()==zero
                assert quorum.compare_and_set(zero,first)
                assert quorum.read_head()==first
            finally:
                os.seteuid(0); os.setegid(0)
            stop(procs[3]); procs[3]=None
            os.setegid(signer.pw_gid); os.seteuid(signer.pw_uid)
            try:
                assert quorum.compare_and_set(first,second)
                assert quorum.read_head()==second
                assert anchors[0].read_head()==second and anchors[1].read_head()==second and anchors[2].read_head()==second
            finally:
                os.seteuid(0); os.setegid(0)
            # Restart the fourth process from its durable stale state. Its response
            # is correctly signed but must remain a minority and cannot roll back the quorum.
            stale_state=root/"state-3"; stale_sock=(root/"ipc-3")/"anchor.sock"
            proc,public,_=start(accounts[3],"anchor-3",stale_sock,stale_state,lib,signer,env)
            procs[3]=proc
            stale_key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(public.read_text().strip()))
            anchors[3]=SignedRecoveryHeadAnchor("anchor-3",stale_key,UnixRecoveryHeadAnchorTransport(stale_sock))
            restarted_quorum=QuorumRecoveryHeadAnchor(anchors,3,1)
            os.setegid(signer.pw_gid); os.seteuid(signer.pw_uid)
            try:
                assert anchors[3].read_head()==first
                assert restarted_quorum.read_head()==second
            finally:
                os.seteuid(0); os.setegid(0)
            print("RECOVERY_ANCHOR_STALE_MINORITY_REJECTED: signed stale restart could not roll back quorum")
            # Untrusted client UID cannot use the signer-group socket.
            sock=pathlib.Path(anchors[0].transport.socket_path)
            code='from recovery_head_anchor_service import UnixRecoveryHeadAnchorTransport\nimport sys\ntry: UnixRecoveryHeadAnchorTransport(sys.argv[1]).read_head("x"*64)\nexcept Exception: print("UNTRUSTED_RECOVERY_ANCHOR_CLIENT_DENIED")\nelse: raise SystemExit(3)'
            denied=subprocess.run([sys.executable,"-c",code,str(sock)],
                preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=8)
            assert denied.returncode==0,(denied.stdout,denied.stderr)
            assert "UNTRUSTED_RECOVERY_ANCHOR_CLIENT_DENIED" in denied.stdout
            print("RECOVERY_ANCHOR_PROCESS_QUORUM_OK: 3-of-4 signed separate-UID anchors")
        finally:
            for proc in procs:
                if proc is not None and proc.poll() is None: stop(proc)
if __name__=="__main__": main()
