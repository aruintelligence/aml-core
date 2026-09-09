# AML-LIB-006 — Reproducible Interface Decisions

**Status: SHIPPED**

A useful interface policy should not depend on who clicks the demo.

ĀML includes deterministic replay paths so the same declared intent, policy context, timestamp, and stream inputs can reproduce the same receipt material. That matters because a decision that cannot be replayed is difficult to audit, compare, or challenge.

The public proof package demonstrates this principle with a suppressible urgency pattern and a normal allowed action.

Local path:

```bash
node demos/undeniable-proof/replay-proof.mjs
```

CI requires the deterministic replay proof to stay green.

Reproducibility does not prove the policy is correct. It proves the implementation can be asked the same question twice and held accountable for answering consistently under fixed inputs.

That distinction is central to ĀML: reproducibility first, stronger human-outcome claims only when evidence supports them.
