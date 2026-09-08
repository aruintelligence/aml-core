# ĀML™ Security Policy

ĀML is a working research prototype with compiler, policy, receipt, interoperability, trust, and official-authorization surfaces. Security review is encouraged.

## Reporting vulnerabilities

For a potentially exploitable security issue, please use a private channel first.

**Contact:** Office@aruintelligence.com

Please do not post active private keys, confidential customer information, exploit details that create immediate harm, or unreleased credential material in a public issue.

This repository does not currently promise a bug bounty or payment for reports unless a separate written program explicitly says otherwise.

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

## Stewardship

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**.
