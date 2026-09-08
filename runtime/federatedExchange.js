import { negotiateCapabilities } from "./capabilityNegotiation.js";
import { verifyPolicyPassport } from "./policyPassport.js";
import { createContentAddressedBundle } from "./contentAddressedBundle.js";
import { createWireEnvelope } from "../protocol/wireProtocol.js";

export function createFederatedExchange({
  local,
  remote,
  required = [],
  passport,
  artifacts = {},
  kind = "accountable-exchange"
} = {}) {
  const negotiation = negotiateCapabilities(local, remote, { required });
  if (!negotiation.compatible) {
    return { accepted: false, reason: "capability_negotiation_failed", negotiation };
  }

  const passportVerification = verifyPolicyPassport(passport);
  if (!passportVerification.valid) {
    return { accepted: false, reason: "policy_passport_invalid", passport_verification: passportVerification, negotiation };
  }

  const bundle = createContentAddressedBundle(artifacts);
  const envelope = createWireEnvelope({
    kind,
    version: negotiation.selected_version,
    capabilities: negotiation.common_capabilities,
    payload: {
      policy_passport_hash: passport.passport_hash,
      bundle_root: bundle.root,
      bundle_index: bundle.index
    }
  });

  return {
    accepted: true,
    reason: null,
    negotiation,
    passport_verification: passportVerification,
    bundle,
    envelope
  };
}
