# ĀML™ JavaScript API

ĀML exposes a public JavaScript API for compiling meaning-bearing interfaces, evaluating policy, producing accountability evidence, negotiating across runtimes, and verifying trust artifacts.

The repository remains the reference implementation. Import directly from `index.js` after cloning the repository.

```js
import {
  createInterfaceFirewall,
  executeAccountableIntent,
  verifyExecutionReceipt,
  viewMeaning
} from "./index.js";
```

## Compiler and meaning

### `compileSource(source, options?)`
Pure in-memory AML compilation.

Returns tokens, AST, Abstract Meaning Tree, render decisions, HTML, and related compiler structures without writing files.

### `compileAML(inputPath, outputDir, options?)`
Filesystem compiler. Writes browser output and accountability artifacts.

### `generateAMLFromIntent(intent)`
Deterministically translates constrained machine-readable intent into AML source.

### `semanticDiff(leftSource, rightSource)`
Compares Abstract Meaning Trees rather than raw text lines.

### `semanticRiskDiff(leftSource, rightSource)`
Classifies meaning changes by accountability significance.

### `policyDiff(source, leftTarget, rightTarget, options?)`
Runs identical meaning/context through two policy or profile targets and reports outcome/rationale differences.

### `policyMatrix(source, targets, options?)`
Evaluates one AML source against multiple policy targets and surfaces agreement/disagreement per meaning-bearing node.

### `buildProvenanceGraph(...)` / `verifyProvenanceGraph(...)`
Builds and verifies hash-bound execution provenance.

### `analyzeAMT(amt)` / `explainCompilation(result)`
Semantic diagnostics and compact explanation output.

## Accountable execution

### `executeAccountableIntent(intent, options?)`
Runs the accountable pipeline:

```text
machine intent
→ generated AML
→ AST / AMT
→ policy simulations
→ selected policy/profile
→ cumulative attention enforcement
→ audit stream
→ final render
→ execution receipt
```

Typical usage:

```js
const receipt = executeAccountableIntent(intent, {
  profile: "human_first",
  context: {
    consent_granted: true,
    attention_budget_remaining: 8
  }
});
```

### `verifyExecutionReceipt(receipt)`
Recomputes receipt integrity and verifies bound runtime artifacts. A receipt
missing its audit stream or attention ledger, or carrying a non-array audit,
cannot verify even if its outer hash is recalculated.

### `signExecutionReceipt(receipt, privateKeyPem, options?)`
Adds an Ed25519 attestation to a valid receipt. Rejects private keys of other algorithm types.

### `verifySignedExecutionReceipt(signedReceipt)`
Verifies receipt integrity, the actual Ed25519 public-key type and signature, canonical base64 signature bytes, and signer fingerprint. This does not supply an external trust anchor; a host must pin trusted fingerprints separately.

### `evaluateLockedHttpAndRender(options)`

Sends an intent to a host-configured locked HTTP service with a fresh request nonce. Before invoking the host's `render(html)` callback, it checks the signed receipt against separately configured trusted public-key fingerprints, the nonce, expected intent/profile/context, and the enforce/closed effective decision. It uses a 5-second exchange deadline and an 8 MiB response limit by default; configure `timeoutMs` and `maxResponseBytes` to fit the integration.

```js
import { evaluateLockedHttpAndRender } from "aml-core";

const result = await evaluateLockedHttpAndRender({
  url: process.env.AML_EVALUATION_URL,
  token: process.env.AML_API_TOKEN,
  intent,
  profile: "human_first",
  context: trustedContext,
  trustedReceiptFingerprints: trustedFingerprints,
  render: async html => hostRender(html)
});
```

The host must derive `trustedContext` and `trustedFingerprints` independently of the response. Results are `rendered`, `blocked`, or `unknown`; `unknown` means a callback was attempted and may have changed the UI before throwing. The exchange deadline does not interrupt a render callback after verification. HTTP errors, timeouts, oversized or malformed responses, missing signer trust, and invalid receipts block before rendering. The request flow also rejects duplicate object keys in the raw HTTP JSON, including differently escaped names, with `reason: "ambiguous_json"`. The embedding application must prevent other render paths from bypassing this gate. See the [runnable signed pilot](pilots/enterprise-http-gate/README.md) and [locked service configuration](docs/LOCKED_HTTP_POLICY.md).

This entry point is available in the current repository package. Check the installed release before using it from a registry package; adding it to `main` does not publish a new version.

### `applyLockedHttpDecision(options)`

Checks a response already parsed by the host using the same signed receipt and policy bindings. The host supplies its outstanding `requestNonce` and the HTTP status alongside its trusted inputs. Use the function above for the ordinary request flow, including nonce generation, rejection of ambiguous raw JSON, and bounded transport handling. A parsed object alone cannot reveal duplicate keys in its original wire bytes.

## AI Interface Firewall™

### `createInterfaceFirewall(options?)`
Creates a reusable policy-aware interface firewall.

```js
const firewall = createInterfaceFirewall({ profile: "human_first" });
const result = firewall.enforce(intent);

if (result.allowed) {
  render(result.html);
}
```

### `enforceInterfaceIntent(intent, options?)`
One-shot equivalent for applications that do not need a persistent firewall instance.

## Policy engines and profiles

### Built-in policy APIs

- `BUILTIN_POLICIES`
- `resolvePolicy(idOrPolicy)`
- `listPolicies()`
- `BUILTIN_POLICY_PROFILES`
- `resolvePolicyProfile(idOrProfile)`
- `listPolicyProfiles()`
- `composePolicies(policies, options?)`
- `policyFromProfile(profile, options?)`
- `simulatePolicies(source, targets, options?)`
- `createPolicyConsensus(results, options?)`

Policy consensus supports explicit disagreement rather than flattening every policy result into one opaque Boolean.

## Signed policy packs

- `normalizePolicyPack(pack)`
- `hashPolicyPack(pack)`
- `signPolicyPack(pack, privateKeyPem, options?)`
- `verifySignedPolicyPack(pack)`

Signed policy packs are data-only references to installed policy IDs. A signature does not make a policy morally correct or universally trustworthy.

## Runtime audit and attention accounting

### Audit streams

- `createAuditStream(options?)`
- `appendAuditEvent(stream, event)`
- `verifyAuditStream(stream)`
- `signAuditCheckpoint(stream, privateKeyPem, options?)`
- `verifyAuditCheckpoint(checkpoint, stream)`

Audit streams are hash-chained and tamper-evident. They are not described as globally immutable unless an external append-only storage system provides that property.

### Attention accounting

- `createAttentionLedger(options?)`
- `consumeAttention(ledger, request)`
- `accountRenderDecisions(decisions, budget)`
- `enforceCumulativeAttentionBudget(decisions, budget)`
- `attentionContext(ledger)`
- `verifyAttentionLedger(ledger)`
- `attentionLedgerSummary(ledger)`

Attention values are model inputs. They are not claimed to be validated objective measurements of human cognition.

## Consent continuity

- `createConsentLedger(options?)`
- `grantConsent(ledger, grant)`
- `revokeConsent(ledger, revocation)`
- `verifyConsentLedger(ledger)`
- `resolveConsent(ledger, scope, options?)`
- `consentContext(ledger, scopes, options?)`

Consent grants can expire and be explicitly revoked.

## Accessibility analysis

- `auditAccessibilityNode(node, context?)`
- `auditAccessibilityTree(amt, context?)`

Current checks include reduced-motion declarations, contrast safety, keyboard accessibility, text alternatives, and cognitive-load constraints. These APIs do **not** replace WCAG conformance or assistive-technology testing.

## Receipt batching and Merkle inclusion

- `buildReceiptMerkleTree(receiptHashes)`
- `createReceiptInclusionProof(tree, index)`
- `verifyReceiptInclusionProof(proof)`

These prove inclusion in a committed batch; they do not prove the truthfulness of the underlying receipt content.

## Cross-system interoperability

### Capability negotiation

`negotiateCapabilities(local, remote, requirements?)`

Determines whether two runtimes can exchange the required AML artifacts without silent capability downgrade.

### Policy passports

- `createPolicyPassport(input)`
- `verifyPolicyPassport(passport)`
- `passportContext(passport)`

Portable user/organization policy preferences can be integrity-bound and time-scoped.

### Content-addressed bundles

- `hashContent(value)`
- `createContentAddressedBundle(artifacts)`
- `verifyContentAddressedBundle(bundle)`

### Selective disclosure commitments

- `createDisclosureCommitment(claims)`
- `discloseClaims(commitment, names)`
- `verifyDisclosureProof(proof)`

This is a selective-disclosure commitment mechanism, not a claim of general zero-knowledge proof capability.

### Federated exchange

`createFederatedExchange(options)`

Negotiates capabilities, verifies the supplied policy passport, content-addresses artifacts, and creates a wire-ready exchange object.

### Causal execution graphs

- `createCausalEvent(input)`
- `createCausalExecutionGraph(events)`
- `verifyCausalExecutionGraph(graph)`

Supports multi-parent lineage across prior agents, policies, receipts, or systems.

## Trust fabric

### Delegation

- `createTrustDelegation(input)`
- `verifyTrustDelegation(delegation)`
- `verifyDelegationChain(chain)`

### Transparency logs

- `createTransparencyLog(options?)`
- `appendTransparencyEntry(log, entry)`
- `verifyTransparencyLog(log)`

### Threshold authorization

- `createThresholdAuthorization(input, signers, options?)`
- `verifyThresholdAuthorization(authorization)`

Supports M-of-N authorization by distinct Ed25519 signers.

### Bounded capability tokens

- `signCapabilityToken(input, privateKeyPem, options?)`
- `verifyCapabilityToken(token, options?)`

Capability tokens can bind issuer, subject, audience, scope, expiration, and nonce.

### Revocation

- `createRevocationRegistry(options?)`
- `revokeArtifact(registry, artifactHash, options?)`
- `verifyRevocationRegistry(registry)`
- `isRevoked(registry, artifactHash)`

### Proof-Carrying Interface™

- `createProofCarryingInterface(input)`
- `verifyProofCarryingInterface(manifest, options?)`

The manifest can bind rendered output to receipts, policy passports, provenance, conformance claims, or causal evidence.

## Official AML authorization verification

Open-source software rights and official brand rights are separate.

### Cryptographic credential APIs

- `signBrandAuthorization(request, privateKeyPem, options?)`
- `verifyBrandAuthorization(credential, options?)`

These verify credential integrity/signature/expiry and optional revocation.

### Official trust APIs

- `verifyBrandTrustRegistry(registry)`
- `verifyOfficialBrandAuthorization(credential, trustRegistry, options?)`

`verifyOfficialBrandAuthorization` adds the critical second step: the signer fingerprint must be present in the canonical active ĀRU trust-root registry and must not be revoked.

A self-signed credential can be cryptographically valid while still **not** being an official ĀRU authorization.

The public trust registry is `BRAND_TRUST_ROOTS.json`. Production private key material is intentionally not stored in GitHub.

## Wire protocol

- `canonicalize(value)`
- `canonicalJSONStringify(value)`
- `createWireEnvelope(input)`
- `validateWireEnvelope(envelope)`
- `negotiateWireSession(local, remote, options?)`
- `createReplayGuard(options?)`
- `acceptWireEnvelope(guard, envelope, options?)`

Canonical serialization and protocol vectors help independent implementations converge on the same hashes and signatures.
`validateWireEnvelope` rejects missing or unknown fields, repeated or malformed capabilities, invalid optional metadata, and malformed or expired timestamps. The portable timestamp profile requires a calendar-valid ISO date-time with an explicit timezone and at most millisecond precision. Callers that previously relied on permissive acceptance of other shapes should normalize their envelopes before upgrading. The [JavaScript/Python comparison](independent/python/WIRE_RUNTIME.md) records the selected shared cases.

## HTTP service

### `createAmlHttpServer(options?)`

Creates the dependency-free reference HTTP service.

Reference endpoints include:

- `GET /health`
- `GET /v1/capabilities`
- `POST /v1/evaluate`
- `POST /v1/deployment/evaluate` — deployment decision, shadow mode, failure behavior, and receipt
- `POST /v1/deployment/batch` — bounded batch evaluation with per-intent evidence
- `POST /v1/deployment/canary` — compare two profiles before rollout
- `POST /v1/verify-receipt`
- official authorization/trust verification endpoints documented in `protocol/aml-http.openapi.yaml`

The deployment routes are specified in [the OpenAPI contract](protocol/aml-http.openapi.yaml).
For an enforcement boundary, configure `locked_policy` so the server owns policy controls and
trusted context; this disables the canary and direct `/v1/evaluate` routes. Configure
`max_batch_items` for the unlocked server batch ceiling (100 by default). A configured
`request_auth.bearer_token` requires bearer authentication for POST requests; a `request_auth`
callback can use the embedding application's authentication. See [server-owned deployment policy](docs/LOCKED_HTTP_POLICY.md)
and [HTTP ingress authentication](docs/HTTP_INGRESS_AUTH.md).
Application authentication and trusted-context callbacks have a 5000 ms deadline by default;
configure `auth_timeout_ms` on each gateway and `locked_policy.resolve_context_timeout_ms`
for the respective limits. Both callbacks receive an optional second `{ signal }` argument
for cancelling their own downstream lookups. Timeouts return generic 503 errors.
Each gateway also limits concurrent POST requests to 100 by default; set
`max_inflight_requests` for a different per-instance ceiling. Excess work returns
`503 server_busy` with `Retry-After: 1` before authentication or evaluation.
The main service has a 10-second absolute deadline to receive each JSON request body.
Set `request_body_timeout_ms` (1 to 2,147,483,647 ms) to match your ingress
policy. An unfinished body returns `408 request_timeout` and closes the connection;
the deadline starts after the optional authentication callback succeeds.

Production deployments still require normal authentication, authorization, transport security, rate limiting, logging, and secure key management.

## React adoption

- `evaluateAccountableProps(props)`
- `createAccountableUI(React)`

These adapt ordinary React component metadata into the same accountable AML pipeline without requiring a complete application rewrite.

## View Meaning™ and CI tooling

### View Meaning

- `viewMeaning(receipt)`
- `formatMeaningReport(report)`

### Pull-request gate

- `evaluatePullRequestChange(input)`
- `formatPullRequestGate(result)`

### Conformance

- `AML_CONFORMANCE_LEVELS`
- `evaluateConformanceLevel(capabilities)`
- `createConformanceClaim(input)`
- `verifyConformanceClaim(claim)`

### Language tooling

- `getCompletionItems(context?)`
- `getHoverInfo(symbol)`
- `getLanguageCatalog()`

## Build integrity

- `verifyBuildManifest(path)`
- `signBuildManifest(path, privateKeyPem, options?)`
- `verifyBuildAttestation(attestation, manifestPath?)`

## Baseline EthicalRenderGate™

`ethicalRenderGate(element)` remains available as the inspectable baseline policy model.

The baseline equation is:

```text
render_allowed = restoration_value >= attention_cost
```

This is a declared research model, not a universal ethics standard or a validated cognitive measurement.

## Other entry points

- CLI: `bin/aml.js`
- Quickstart: `QUICKSTART.md`
- Out-of-the-box adoption: `docs/OUT_OF_THE_BOX.md`
- Enterprise pilot: `pilots/enterprise-30min/`
- Protocol discovery: `protocol/discovery.json`
- Conformance: `CONFORMANCE.json`
- Independent replication: `REPLICATION.md`
- Playground: https://aruintelligence.github.io/aml-core/playground.html
- View Meaning™: https://aruintelligence.github.io/aml-core/view-meaning.html
- Official AML verification: https://aruintelligence.github.io/aml-core/official-verify.html
