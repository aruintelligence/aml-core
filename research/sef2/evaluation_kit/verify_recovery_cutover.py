"""Standalone verifier for recovery policy cutover certificates."""
import argparse,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from recovery_cutover import verify_independent_cutover_certificate

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
    p.add_argument("--certificate",required=True)
    p.add_argument("--rotation",required=True)
    p.add_argument("--next-policy-sha256",required=True)
    p.add_argument("--generation",required=True,type=int)
    p.add_argument("--verifier-keys",required=True)
    p.add_argument("--verifier-domains",required=True)
    p.add_argument("--pinned-verifier-domains-sha256",required=True)
    p.add_argument("--threshold",required=True,type=int)
    p.add_argument("--max-faults",required=True,type=int)
    a=p.parse_args(argv)
    try:
        ok=verify_independent_cutover_certificate(load_unique(a.certificate),load_unique(a.rotation),
            a.next_policy_sha256,a.generation,load_unique(a.verifier_keys),
            a.threshold,a.max_faults,load_unique(a.verifier_domains),
            a.pinned_verifier_domains_sha256)
    except (OSError,ValueError,TypeError,KeyError,UnicodeDecodeError):
        ok=False
    print("RECOVERY_CUTOVER_VERIFIED" if ok else "RECOVERY_CUTOVER_REJECTED")
    return 0 if ok else 2

if __name__=="__main__": sys.exit(main())
