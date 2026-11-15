"""Standalone evaluator for dual-quorum recovery council rotation."""
import argparse,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from recovery_policy_rotation import verify_policy_rotation
from threshold_recovery import policy_digest

def load_unique(path):
    def reject(pairs):
        out={}
        for k,v in pairs:
            if k in out: raise ValueError("duplicate JSON key")
            out[k]=v
        return out
    return json.loads(pathlib.Path(path).read_text(),object_pairs_hook=reject)

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--current-policy",required=True)
    p.add_argument("--next-policy",required=True)
    p.add_argument("--rotation",required=True)
    p.add_argument("--pinned-current-policy-sha256",required=True)
    p.add_argument("--expected-generation",required=True,type=int)
    a=p.parse_args(argv)
    try:
        current=load_unique(a.current_policy)
        nxt=load_unique(a.next_policy)
        rotation=load_unique(a.rotation)
        ok=(policy_digest(current)==a.pinned_current_policy_sha256
            and verify_policy_rotation(current,nxt,rotation,a.expected_generation))
    except (OSError,ValueError,TypeError,KeyError,UnicodeDecodeError):
        ok=False
    print("RECOVERY_POLICY_ROTATION_VERIFIED" if ok else "RECOVERY_POLICY_ROTATION_REJECTED")
    return 0 if ok else 2

if __name__=="__main__": sys.exit(main())
