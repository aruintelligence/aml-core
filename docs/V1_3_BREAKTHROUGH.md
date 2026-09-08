# ĀML™ v1.3 — Trust, Difference, Accessibility, and Runtime Accountability

ĀML v1.3 extends accountable execution in six directions: signed policy packs, semantic diffs, policy diffs, runtime audit streams, executable accessibility policies, and cumulative attention accounting.

## 1. Signed policy packs

Policy packs are deliberately **data-only**. They may reference installed policy IDs, but they cannot embed executable JavaScript. This keeps signing meaningful: a signed pack identifies a specific declarative policy composition rather than silently transporting code.

```json
{
  "id": "human_first_org_policy",
  "issuer": "Example Organization",
  "policies": [
    "restorative_v1",
    "consent_guard_v1",
    "privacy_guard_v1",
    "reduced_motion_v1",
    "contrast_safety_v1",
    "cognitive_load_guard_v1",
    "session_attention_budget_v1"
  ]
}
```

```bash
aml sign-policy-pack policy-pack.json private-key.pem signed-policy-pack.json
aml verify-policy-pack signed-policy-pack.json
```

The signature uses Ed25519 and includes a SHA-256 public-key fingerprint and canonical pack hash.

## 2. Semantic diff

A text diff answers which characters changed. `aml semantic-diff` compares compiled Abstract Meaning Trees and reports added, removed, changed, and unchanged meaning-bearing nodes.

```bash
aml semantic-diff before.aml after.aml
```

Changes are grouped into structural, property, and meaning-metadata differences.

## 3. Policy diff

`aml policy-diff` holds source and runtime context constant while changing the policy or policy profile.

```bash
aml policy-diff interface.aml restorative_v1 attention_conservative_v1
aml policy-diff interface.aml calm_default human_first context.json
```

The output identifies decisions whose allow/suppress result or rationale changed.

## 4. Runtime audit streams

The runtime audit stream is an append-only SHA-256 hash chain. Each entry commits to its own payload and the previous entry hash.

```text
event 0 → hash 0
event 1 + hash 0 → hash 1
event 2 + hash 1 → hash 2
```

Mutating an earlier event invalidates verification for the stream.

Accountable execution receipts can now carry the audit stream and bind it into the receipt hash.

## 5. Accessibility policies

v1.3 introduces executable policies for runtime accessibility context:

- `reduced_motion_v1`
- `contrast_safety_v1`
- `cognitive_load_guard_v1`

It also adds two profiles:

- `accessibility_first`
- `human_first`

Example context:

```json
{
  "prefers_reduced_motion": true,
  "high_contrast_required": true,
  "max_cognitive_load": 4,
  "attention_budget_remaining": 12
}
```

Accessibility policy is not presented as a substitute for WCAG conformance or assistive-technology testing. It is an executable policy layer that can complement established accessibility engineering.

## 6. Cumulative attention accounting

Earlier attention-budget policy could compare a single element against a remaining budget. v1.3 adds a session ledger that records consumption across multiple allowed render decisions.

```text
initial budget: 10
node A cost: 3 → remaining 7
node B cost: 4 → remaining 3
node C cost: 5 → suppressed by cumulative budget
```

The accountable execution pipeline can regenerate final HTML after cumulative enforcement so a later component cannot render merely because each component individually fit the original budget.

## Combined architecture

```text
AI intent
  ↓
ĀML source
  ↓
meaning tree
  ↓
policy/profile evaluation
  ↓
accessibility + privacy + consent constraints
  ↓
cumulative attention ledger
  ↓
final render decisions
  ↓
HTML
  ↓
hash-chained runtime audit stream
  ↓
execution receipt
  ↓
optional Ed25519 attestation
```

## Evidence boundary

These mechanisms improve inspectability, reproducibility, integrity, and policy control. They do not prove that a policy is morally correct, that an accessibility rule is sufficient for all users, or that modeled attention values are validated measurements of human cognition.
