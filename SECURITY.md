# ĀML™ Security Policy

ĀML is a working research prototype with compiler, policy, receipt, interoperability, trust, and official-authorization surfaces. Security review is encouraged. This policy describes how to report a vulnerability. It is not a certification, a vulnerability-free claim, or a promise that the reference implementation is suitable for every production environment.

## Reporting vulnerabilities

Please use a **private channel first** for any potentially exploitable issue.

1. **Preferred:** GitHub private vulnerability reporting, via **Security → Report a vulnerability** on [aruintelligence/aml-core](https://github.com/aruintelligence/aml-core/security/advisories/new), when that feature is enabled for the repository.
2. **Current reliable path:** email **Office@aruintelligence.com** with the subject line `ĀML security report`.

Please do not post active private keys, confidential customer information, exploit details that create immediate harm, or unreleased credential material in a public issue, pull request, or discussion.

This repository does not currently promise a bug bounty or payment for reports unless a separate written program explicitly says otherwise.

We aim to acknowledge a clearly described report within a few business days. That is a stewardship goal, not a contractual service-level agreement.

## Supported versions

| Version | Security updates |
|---|---|
| This repository's default branch and current development snapshots | Investigated as they stand |
| `v1.4.0-rc.2` prerelease snapshot | Investigated; the preview channel may change |
| `v1.3.0` stable package/CLI/capability contract | Investigated for the published contract |
| Older tags and experimental branches | Best-effort, as resources allow |

Name the exact commit or tag in your report whenever possible.

## Security scope

High-value areas include:

### Compiler and parser

- malformed-input crashes
- parser confusion
- output injection
- unsafe HTML emission
- compiler-state corruption
- inconsistent AST/AMT interpretation

### Policy and accountability

- policy bypasses
- incorrect ALLOW/SUPPRESS outcomes
- missing-vs-zero semantic regressions
- falsified policy identity or rationale
- receipt forgery or mutation that still verifies
- signed policy-pack verification bypass
- audit-chain mutation that remains accepted
- attention-ledger or consent-ledger tampering

### Cryptographic integrity

- invalid Ed25519 signatures accepted as valid
- public-key fingerprint mismatches not detected
- canonicalization disagreements that change signatures/hashes
- Merkle inclusion proof forgery
- threshold-authorization signer duplication/bypass
- trust-delegation chain bypass

### Wire and federation

- replay-protection bypass
- capability downgrade or negotiation confusion
- incompatible runtimes silently treated as compatible
- malformed wire envelopes accepted
- content-addressed bundle mutation not detected
- causal graph cycles/missing parents accepted

### Capability and authority security

- capability-token scope escalation
- audience/subject confusion
- expired authority accepted
- revoked artifacts accepted as active
- revocation-registry tampering

### Official AML authorization

- self-signed credentials treated as official
- untrusted signing keys treated as active ĀRU trust roots
- revoked trust roots accepted
- trust-root/public-key fingerprint drift
- credential scope/expiration bypass

The canonical production public trust root is published in `BRAND_TRUST_ROOTS.json`. Production private key material must never be committed to GitHub.

### HTTP service

The reference AML HTTP service is intentionally minimal. Review areas include:

- request-size enforcement
- malformed JSON handling
- unsafe default CORS behavior
- denial-of-service paths
- receipt/authorization verification mismatches

The reference service does **not** replace production authentication, authorization, TLS, rate limits, logging, secret management, network isolation, or normal application-security controls.

### Browser surfaces

For View Meaning™ and the browser-extension prototype:

- permission expansion
- unintended page-content collection
- remote upload of inspected page data
- credential leakage
- incorrect local receipt verification
- incorrect official-brand trust verification

The extension prototype is designed around user-invoked `activeTab` inspection rather than persistent browsing-history access.

## What to include in a report

Please include, when possible:

- affected version/commit
- affected file or protocol surface
- reproduction steps
- expected behavior
- actual behavior
- security impact
- proof-of-concept input with sensitive data removed
- suggested mitigation, if known

## Coordinated disclosure

For issues with realistic exploitation risk, allow reasonable time for reproduction, remediation, tests, and release coordination before public disclosure.

A security report does not grant permission to access systems, accounts, credentials, or data you are not authorized to access.

## Evidence boundary

Breaking a current policy assumption is not automatically a cryptographic vulnerability. Likewise, a cryptographically valid artifact is not automatically ethically correct or institutionally trustworthy.

Security claims should distinguish among:

- software integrity
- policy semantics
- key possession
- trust-root membership
- institutional authorization
- human-outcome claims

Further reading: [SECURITY_THREAT_MODEL.md](SECURITY_THREAT_MODEL.md) and [docs/SECURITY_EVALUATION_CHECKLIST.md](docs/SECURITY_EVALUATION_CHECKLIST.md).

## Stewardship

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**.
