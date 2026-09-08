# ĀML Security Threat Model

ĀML is an accountability and policy layer. It does not replace normal application security. This document describes threats specific to meaning declarations, policies, receipts, provenance, and AI-mediated UI generation.

## Assets worth protecting

- declared machine/human intent;
- generated ĀML source;
- policy packs and profile selection;
- consent/privacy state;
- render decisions and rationales;
- cumulative attention ledgers;
- runtime audit streams;
- execution receipts and signatures;
- provenance and Merkle inclusion proofs.

## Threats

### 1. Dishonest declared intent
An AI or application can label a manipulative element with a benign purpose.

**Mitigation direction:** provenance, independent policy signals, semantic-diff review, external testing, and explicit recognition that declarations are claims rather than truth.

### 2. Policy downgrade
An application may swap a stricter user policy for a permissive profile.

**Mitigations:** policy identity in decisions/receipts, policy diffs, user-owned policy-profile RFC, signed policy packs, and audit logs.

### 3. Receipt tampering
An attacker modifies a receipt after execution.

**Mitigations:** canonical hashing, receipt verification, Ed25519 signatures, Merkle inclusion proofs.

### 4. Audit-history rewriting
An attacker alters or removes earlier runtime events.

**Mitigations:** SHA-256 hash chaining and signed audit checkpoints. Deletion of an entire unanchored stream remains a deployment-level risk.

### 5. Replay of consent
An expired or revoked consent grant is replayed.

**Mitigations:** time-scoped consent entries, explicit revocation, timestamps, future nonce/session binding.

### 6. Malicious policy pack
A policy package attempts to transport arbitrary executable code.

**Mitigation:** current signed policy packs are deliberately data-only and reference installed policy IDs.

### 7. Attention-ledger manipulation
A client resets or alters cumulative consumption to bypass a session budget.

**Mitigations:** ledger verification and integrity-bound receipts. Stronger remote/session anchoring is future work.

### 8. Accessibility laundering
A component claims accessible metadata that does not match actual behavior.

**Mitigation:** AML audits are declarations/tests, not a WCAG replacement. Browser, assistive-technology, and human testing remain required.

### 9. Signature-key compromise
A valid signing key is stolen.

**Mitigations:** operational key rotation, short-lived credentials, hardware-backed keys where appropriate, published revocation strategy. AML signatures prove key possession, not trustworthiness.

### 10. Privacy leakage through accountability
Receipts or policy passports may accidentally collect more user context than necessary.

**Mitigations:** data minimization, scoped context, selective disclosure research, expiration, and separation between accountability and analytics.

## Trust boundaries

```text
AI / application
      |
      v
intent declaration  <-- untrusted claim
      |
      v
AML compiler + policy runtime
      |
      +--> user/org runtime context
      |
      v
render decision
      |
      +--> browser/application output
      +--> receipt/audit/provenance artifacts
```

The compiler can make the process inspectable; it cannot guarantee the upstream AI is truthful or the downstream application faithfully presents the allowed output unless those boundaries are also verified.

## Security research wanted

Contributions are specifically invited for replay protection, canonicalization attacks, malformed policy packs, signature misuse, audit truncation, provenance ambiguity, privacy-preserving selective disclosure, and adversarial intent declarations.

Report vulnerabilities according to `SECURITY.md` where applicable. Do not include live secrets, private keys, or sensitive personal data in public issues.