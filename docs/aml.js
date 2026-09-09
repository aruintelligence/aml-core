// ĀML browser bootstrap — SHIPPED prototype surface.
// One module activates the reference browser adoption layers and exposes a small browser verification API.
import './aml-gate.js';
import './aml-zone.js';
import './aml-live.js';
import './aml-page-manifest.js';
import './aml-browser-evidence.js';

import { verifyBrowserEvidence } from './aml-browser-evidence.js';
import { createVerificationChallenge } from './aml-verification-challenge.js';
import { createSessionAttestation, verifySessionAttestation } from './aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle } from './aml-witness-bundle.js';
import { createVerificationReport, witnessVerificationReport } from './aml-verification-report.js';
import { createVerificationQuorum, verifyVerificationQuorum } from './aml-verification-quorum.js';
import { createVerifierKeyPair, signVerificationReport, verifySignedVerificationReport } from './aml-signed-verification-report.js';
import { createSignedVerificationQuorum } from './aml-signed-verification-quorum.js';
import {
  resolveAMLDeploymentMode,
  resolveAMLFailureMode,
  setAMLDeploymentMode,
  setAMLFailureMode,
  AML_BROWSER_DEPLOYMENT_MODES,
  AML_BROWSER_FAILURE_MODES
} from './aml-deployment-mode.js';

const api = Object.freeze({
  createChallenge: createVerificationChallenge,
  verifyEvidence: verifyBrowserEvidence,
  attest: ({ challenge, evidence = globalThis.__AML_EVIDENCE__ } = {}) =>
    createSessionAttestation({ challenge, evidence }),
  verifyAttestation: verifySessionAttestation,
  createWitnessBundle: ({ challenge, attestation, evidence = globalThis.__AML_EVIDENCE__ } = {}) =>
    createWitnessBundle({ challenge, attestation, evidence }),
  verifyWitnessBundle,
  createVerificationReport,
  witnessVerificationReport,
  createVerificationQuorum,
  verifyVerificationQuorum,
  createVerifierKeyPair,
  signVerificationReport,
  verifySignedVerificationReport,
  createSignedVerificationQuorum,
  getDeploymentMode: () => resolveAMLDeploymentMode(),
  setDeploymentMode: setAMLDeploymentMode,
  getFailureMode: () => resolveAMLFailureMode(),
  setFailureMode: setAMLFailureMode,
  deploymentModes: AML_BROWSER_DEPLOYMENT_MODES,
  failureModes: AML_BROWSER_FAILURE_MODES
});

const ready = {
  schema: 'aml-browser-bootstrap/1',
  prototype: true,
  web_component: Boolean(customElements.get('aml-gate')),
  strict_zone: Boolean(customElements.get('aml-zone')),
  live_dom: true,
  page_manifest: true,
  browser_integrity: 'SHA-256',
  challenge_bound_attestation: 'ECDSA-P256-SHA256',
  verification_report: 'aml-verification-report/1',
  verification_quorum: 'aml-verification-quorum/1',
  signed_verification_report: 'aml-signed-verification-report/1',
  signed_verification_quorum: 'aml-signed-verification-quorum/1',
  deployment_mode: resolveAMLDeploymentMode(),
  failure_mode: resolveAMLFailureMode(),
  browser_api_global: 'window.AML',
  receipt_global: 'window.__AML_RECEIPT__',
  receipt_history_global: 'window.__AML_RECEIPT_HISTORY__',
  evidence_global: 'window.__AML_EVIDENCE__',
  evidence_history_global: 'window.__AML_EVIDENCE_HISTORY__',
  session_attestation_global: 'window.__AML_SESSION_ATTESTATION__',
  zone_violation_global: 'window.__AML_ZONE_VIOLATIONS__'
};

globalThis.AML = api;
globalThis.__AML_BROWSER__ = ready;
document.dispatchEvent(new CustomEvent('aml-ready', { detail: ready }));

export { api as AML };
export default ready;
