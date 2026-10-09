# ĀML™ Enterprise Pilot — 30 Minutes

This reproducible pilot runs the actual ĀML API against three small, public fixtures. It shows a calm explanation allowed, a consent-gated proposal suppressed, and the same proposal allowed after the declared consent context changes. It produces a full decision report that a second command replays and verifies.

## Run and verify

From the repository root, with Node.js 20 or later:

```bash
node pilots/enterprise-30min/run.mjs > /tmp/aml-enterprise-pilot.json
node pilots/enterprise-30min/verify-report.mjs /tmp/aml-enterprise-pilot.json
```

Both commands must exit successfully. The second command checks the report digest, fixture hashes, all three expected decisions, every receipt's internal integrity, View Meaning output, a deterministic replay, and rejection of a mutated receipt. CI also saves the report as a workflow artifact for a reviewer to download and rerun.

The report contains the **full demo receipts**, including intent and context. Review it before sharing. Do not put actual customer data into these fixtures or publish real customer receipts without a separate data-handling review.

## Integration pattern

```text
AI or app proposes interface intent
  → ĀML evaluates a declared profile and runtime context
  → app receives allow/suppress decision and receipt
  → existing renderer applies the decision
```

This pilot does not itself install an enforcement boundary in another application. The application must ensure that every relevant rendering path goes through its chosen gate.

## What to inspect

- `intent-allowed.json` and `intent-sensitive.json`: declared purpose and prototype attention/restoration values.
- `context-denied.json` and `context-allowed.json`: the consent and privacy context used for the comparison.
- `scenarios[].receipt`: the actual decision and internal audit evidence.
- `scenarios[].meaning`: a compact View Meaning interpretation.
- `report_sha256`: SHA-256 of the compact JSON serialization of the report with this field omitted. It detects changes to this report representation; it is **not a signature or proof of authorship**.

The fixed decision timestamp and stream IDs make the three receipts replayable against the same version of the code and fixtures. The verifier uses the repository's own implementation, so its success is **project-authored evidence**, not independent validation. A reviewer can challenge the behavior using an independent implementation or the repository's external verifier protocols.

## Deployment decision

Before a production trial, document the exact application, policy owner, authentication and authorization boundaries, data retention, accessibility behavior after suppression, failure mode, rollback owner, and independent security review. See the [security evaluation checklist](../../docs/SECURITY_EVALUATION_CHECKLIST.md).

This is a research prototype. The values are declared inputs, not objective measurements of human attention, restoration, welfare, or conversion. The pilot does not establish regulatory compliance, certification, or production approval.

The software is available under the repository's MIT License. Official ĀML branding, OEM/co-branding, managed infrastructure, and enterprise services are separate. Contact: **Office@aruintelligence.com**.
