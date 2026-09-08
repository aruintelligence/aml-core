import fs from 'node:fs';

const required = [
  ['docs/proof.html', ['Copy this exact proof link', 'URLSearchParams', 'render_allowed = restoration_value', "lang === 'ar'", 'Declared purpose']],
  ['docs/proof-card.html', ['ĀML Proof Card', 'compileSourceBrowser', 'Open this proof', "lang==='ar'"]],
  ['docs/proof-manifest.json', ['"status": "SHIPPED"', '"suppress_example"', '"allow_example"']],
  ['docs/proof-links.json', ['"decision":"ALLOW"', '"decision":"SUPPRESS"']],
  ['docs/WITNESS_KIT.md', ['Local deterministic replay', 'A negative result is useful evidence']],
  ['docs/EMBED_PROOF.md', ['<iframe', 'proof-card.html?attention=5&restoration=1']],
  ['docs/aml-gate.js', ['customElements.define', 'compileSourceBrowser', 'aml-decision']],
  ['docs/AML_GATE_ELEMENT.md', ['<aml-gate>', 'SHIPPED prototype']],
  ['docs/aml-dom-gate.js', ['applyAMLDomGate', '__AML_DOM_DECISIONS__', 'compileSourceBrowser']],
  ['docs/HTML_BRIDGE.md', ['data-aml-attention-cost', 'data-aml-restoration-value']],
  ['docs/aml-live.js', ['MutationObserver', '__AML_RECEIPT__', '__AML_RECEIPT_HISTORY__', 'aml-receipt-sealed']],
  ['docs/aml-browser-integrity.js', ['SHA-256', 'verifyBrowserReceipt', 'AML_BROWSER_RECEIPT_HASH_MISMATCH', 'not a signature']],
  ['docs/aml-browser-evidence.js', ['aml-browser-evidence/1', '__AML_EVIDENCE__', 'verifyBrowserEvidence', 'zone_violations']],
  ['docs/browser-evidence-demo.html', ['ĀML Browser Evidence', 'Verify current evidence', 'Tamper with a copy and verify', 'TAMPER DETECTED']],
  ['docs/BROWSER_EVIDENCE.md', ['Browser evidence packets', 'aml-browser-evidence/1', 'SHA-256', 'does **not** prove']],
  ['docs/aml-verification-challenge.js', ['aml-verification-challenge/1', 'crypto.getRandomValues', 'AML_CHALLENGE_EXPIRED']],
  ['docs/aml-session-attestation.js', ['aml-session-attestation/1', 'ECDSA-P256-SHA256', 'challenge_nonce', 'AML_SESSION_CHALLENGE_MISMATCH']],
  ['docs/aml-witness-bundle.js', ['aml-witness-bundle/1', 'verifySessionAttestation', 'AML_WITNESS_BUNDLE_VALID']],
  ['docs/aml-verification-report.js', ['aml-verification-report/1', 'witnessVerificationReport', 'does not prove identity']],
  ['docs/aml-verification-quorum.js', ['aml-verification-quorum/1', 'AML_QUORUM_DUPLICATE_VERIFIER', 'disagreement_reasons']],
  ['docs/aml-signed-verification-report.js', ['aml-signed-verification-report/1', 'verifier_key_fingerprint', 'Key possession does not prove verifier identity']],
  ['docs/aml-signed-verification-quorum.js', ['aml-signed-verification-quorum/1', 'distinct_keys', 'Distinct keys do not prove distinct people']],
  ['docs/attest-evidence.html', ['ĀML Attest Evidence', 'Create signed witness bundle', 'Download bundle.json', 'aml-session-attestation.js']],
  ['docs/detached-verifier.html', ['ĀML Detached Verifier', 'Generate 2-minute challenge', 'Verify bundle against my challenge', 'Download verification-report.json', 'type="file"']],
  ['docs/aml-verifier-worker.js', ['verifyWitnessBundle', 'aml-web-worker', 'postMessage']],
  ['docs/worker-verifier.html', ['ĀML Worker Verifier', 'Verify in worker', "new Worker('./aml-verifier-worker.js'", 'without access to the page DOM']],
  ['docs/quorum-demo.html', ['ĀML Verifier Plurality', 'Build quorum', 'Threshold agreement is not truth or certification']],
  ['docs/signed-quorum-demo.html', ['ĀML Key-Distinct Verifier Quorum', 'Two verifier names, same key', 'does not represent external witnesses']],
  ['docs/witnesses.html', ['ĀML External Witnesses', 'external witness records', '0 external witnesses']],
  ['docs/VERIFIER_PLURALITY.md', ['One verifier can be wrong', 'aml-verification-quorum/1', 'does **not** prove']],
  ['docs/VERIFIER_NETWORK.md', ['DRAFT protocol direction', 'preserve disagreement', 'outside implementation']],
  ['docs/SESSION_ATTESTATION.md', ['ephemeral P-256', 'does **not** prove', 'aml-witness-bundle/1']],
  ['docs/DETACHED_VERIFIER.md', ['original bundle -> PASS', 'wrong challenge -> FAIL', 'window.AML']],
  ['docs/live-gate-demo.html', ['ĀML Live DOM Firewall', 'AI generates pressure CTA', 'aml-receipt']],
  ['docs/aml-page-manifest.js', ['application/aml+json', 'aml-page/1', 'MAX_ENTRIES = 100', 'MAX_TOTAL_MATCHES = 1000']],
  ['docs/page-manifest-demo.html', ['ĀML Page Manifest', 'application/aml+json', 'Create urgency to increase conversion']],
  ['docs/aml-zone.js', ['aml-zone-violation/1', '__AML_ZONE_VIOLATIONS__', "mode === 'strict'", 'node.hidden = true']],
  ['docs/strict-zone-demo.html', ['ĀML Strict Zone', 'Generate undeclared AI output', 'mode="strict"']],
  ['docs/aml.js', ['aml-browser-bootstrap/1', './aml-gate.js', './aml-zone.js', './aml-live.js', './aml-page-manifest.js', './aml-browser-evidence.js', 'globalThis.AML = api', 'createChallenge', 'verifyWitnessBundle', 'createVerificationQuorum', 'createSignedVerificationQuorum']],
  ['docs/ONE_SCRIPT_AML.md', ['One-script AML browser integration', 'window.__AML_RECEIPT__', '<aml-zone mode="strict">']],
  ['docs/one-script-demo.html', ['One script. Three AML declaration styles.', './aml.js', 'application/aml+json']],
  ['protocol/aml-page.schema.json', ['"aml-page/1"', '"maximum": 10']],
  ['protocol/aml-dom-receipt.schema.json', ['"aml-dom-receipt/1"', '"aml-integrity/1"', '"SHA-256"']],
  ['protocol/aml-browser-evidence.schema.json', ['"aml-browser-evidence/1"', '"zone_violations"', '"SHA-256"']],
  ['protocol/aml-verification-challenge.schema.json', ['"aml-verification-challenge/1"', '"expires_at"']],
  ['protocol/aml-session-attestation.schema.json', ['"aml-session-attestation/1"', '"ECDSA-P256-SHA256"', '"session_public_key_jwk"']],
  ['protocol/aml-witness-bundle.schema.json', ['"aml-witness-bundle/1"', '"integrity"']],
  ['protocol/aml-verification-report.schema.json', ['"aml-verification-report/1"', '"checks"', '"verifier"']],
  ['protocol/aml-verifier-manifest.schema.json', ['"aml-verifier-manifest/1"', '"artifact_types"', '"claim_boundary"']],
  ['protocol/aml-verification-quorum.schema.json', ['"aml-verification-quorum/1"', '"threshold_met"', '"unanimous"']],
  ['protocol/aml-signed-verification-report.schema.json', ['"aml-signed-verification-report/1"', '"verifier_key_fingerprint"', '"ECDSA-P256-SHA256"']],
  ['protocol/aml-signed-verification-quorum.schema.json', ['"aml-signed-verification-quorum/1"', '"distinct_keys"', '"threshold_met"']],
  ['protocol/aml-witness-record.schema.json', ['"aml-witness-record/1"', '"external_to_aml_core"', '"source_url"']],
  ['protocol/verifier-registry.json', ['"external_verifier_count": 0', '"WITNESSES.json"']],
  ['WITNESSES.json', ['"external_witness_count": 0', '"records": []', '"negative_results_allowed": true']],
  ['protocol/verification-report-vectors.json', ['"aml-verification-report-vectors/1"', '"threshold_met": true', '"unanimous": false']],
  ['protocol/browser-canonicalization-vectors.json', ['"aml-browser-canonicalization-vectors/1"', '"sorted-json-v1"', '"unicode"']],
  ['protocol/sorted-json-v1.md', ['Cross-language safe domain', 'must use a new canonicalization identifier', 'not an IETF']],
  ['protocol/aml-zone-violation.schema.json', ['"aml-zone-violation/1"', '"reason"']],
  ['independent/python/verify_witness.py', ['AML_PY_WITNESS_BUNDLE_VALID', 'verify_p256_raw_signature', 'does not prove identity']],
  ['independent/python/check_canonical_vectors.py', ['browser-canonicalization-vectors.json', 'canonical_json']],
  ['independent/python/README.md', ['does **not** count as an independent external witness', 'Python standard library']],
  ['docs/gallery.html', ['ĀML Decision Gallery', 'Ten simple examples', 'Replay this state']],
  ['docs/.well-known/aml.json', ['"web_component"', '"html_bridge"', '"detached_verifier"', 'not an Internet standard']],
  ['docs/proof-badge.svg', ['PROOF AVAILABLE']],
  ['docs/PROOF_BADGE.md', ['does not mean official certification']],
  ['docs/offline-proof.html', ['ĀML Offline Proof', 'without a network connection', 'render_allowed = restoration_value']],
  ['docs/OFFLINE_PROOF.md', ['SHIPPED single-file demonstrator', 'not', 'full AML compiler']],
  ['docs/worlds/ar.md', ['<div dir="rtl">']]
];

const failures = [];
for (const [path, needles] of required) {
  if (!fs.existsSync(path)) {
    failures.push(`${path}: missing`);
    continue;
  }
  const text = fs.readFileSync(path, 'utf8');
  for (const needle of needles) {
    if (!text.includes(needle)) failures.push(`${path}: missing ${JSON.stringify(needle)}`);
  }
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  surfaces: required.map(([path]) => path),
  promise: 'shareable + multilingual + embeddable + live-DOM + page-manifest + strict-zone + browser-integrity + evidence-packet + challenge-bound-session + detached-verifier + file-native-witness + verification-report + verifier-manifest + verifier-plurality + signed-verifier-report + key-distinct-quorum + witness-registry + worker-verifier + cross-language-python + canonical-vectors + one-script + offline AML proof surfaces remain present'
}, null, 2));
