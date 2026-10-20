# Reproduce the action-boundary evidence

Use a full clone of the pinned release commit. Install Node.js 22+, Python
3.12+, Perl with core `JSON::PP` and `Digest::SHA`, and OpenSSL. No cloud
credentials or live website access are needed to verify the published files.

```sh
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
bash reproduction/action-boundary/reproduce.sh
```

The command verifies 475 exact project-authored challenge cases and receipts,
including 375 stress cases, in the maintained bindings; the actual Chrome observation;
the ten paired controlled-site sources, DOM snapshots and screenshots; the
four adapters and 28 original blocked variants plus 16 observed revocation
paths and four policy-epoch comparisons; and the append-only registry. It
recomputes the [file manifest](manifest.json) and prints the receipt count,
registry chain root, and SHA-256 of the registry file. The full
[specification](SPEC.md), raw artifacts and runnable implementations are in
this repository at the same commit.

Expected at this checkpoint: **508 indexed receipts** with the first 504 rows
unchanged, **100/100 expanded and 375/375 stress matches in each of five
maintained bindings**, **ten paired browser pilots**, and
**four original adapter callbacks with 28 blocked variants**, plus four
revocation records with 16 blocked paths and zero callbacks, plus four
policy-epoch comparisons where an A→B→A change goes from four local callbacks
to zero. These are
project-maintained reproductions; no independent party is counted.
