"""Standalone evaluator for threshold recovery transparency bundles."""
import argparse,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from recovery_transparency import verify_recovery_transparency_bundle

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
    p.add_argument("--bundle",required=True)
    p.add_argument("--current-state",required=True)
    p.add_argument("--policy",required=True)
    p.add_argument("--pinned-policy-sha256",required=True)
    p.add_argument("--authority-heads",required=True)
    a=p.parse_args(argv)
    try:
        ok=verify_recovery_transparency_bundle(
            load_unique(a.bundle),load_unique(a.current_state),load_unique(a.policy),
            a.pinned_policy_sha256,load_unique(a.authority_heads))
    except (OSError,ValueError,TypeError,KeyError,UnicodeDecodeError):
        ok=False
    print("RECOVERY_TRANSPARENCY_VERIFIED" if ok else "RECOVERY_TRANSPARENCY_REJECTED")
    return 0 if ok else 2

if __name__=="__main__": sys.exit(main())
