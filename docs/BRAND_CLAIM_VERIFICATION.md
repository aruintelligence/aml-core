# Buyer-held brand claim verification

A credential can be correctly signed yet be irrelevant to the claim being made. A presenter could show a credential for a different company or use, or supply an older, internally valid trust/revocation snapshot. `verifyBrandClaim` checks **one exact proposed use** against snapshots the buyer has already pinned.

## Inputs

Keep these four files separate:

1. `credential.json`: the presented signed credential.
2. `brand-trust-roots.json`: a trust registry obtained through a channel the buyer trusts.
3. `revocations.json`: the applicable credential revocation registry, obtained through a trusted channel. A hash chain proves integrity of its entries, not that its head is the latest one.
4. `buyer-policy.json`: the buyer's independently held claim and snapshot pins. Do not let the presenter replace this file or derive its pins from the files the presenter supplies for this check.

The policy format is:

```json
{
  "type": "aml-brand-claim-policy/1",
  "grantee": "Example Integrator LLC",
  "mark": "ĀML Compatible™",
  "permitted_use": "official-compatible-badge",
  "trust_registry_sha256": "64 lowercase hex characters from the canonical trust registry",
  "revocation_head": null
}
```

`revocation_head` is `null` only when the buyer intentionally pins a verified empty registry. For a nonempty registry it is the last entry hash, a 64-character lowercase hex string. To calculate the trust-registry pin from a trusted copy, use the package's canonical JSON rules:

```js
import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJSONStringify, verifyBrandTrustRegistry, verifyRevocationRegistry } from "aml-core";

const roots = JSON.parse(fs.readFileSync("brand-trust-roots.json", "utf8"));
const revocations = JSON.parse(fs.readFileSync("revocations.json", "utf8"));
if (!verifyBrandTrustRegistry(roots).valid || !verifyRevocationRegistry(revocations).valid) {
  throw new Error("Invalid source snapshot");
}
const trust_registry_sha256 = crypto.createHash("sha256")
  .update(canonicalJSONStringify(roots)).digest("hex");
const revocation_head = revocations.head;
```

Those two values go into the buyer's policy. The example above illustrates the computation; it does not authenticate where `roots` or `revocations` came from. Keep the source location, retrieval time, and approval record with the policy outside the presented credential.

## Check the claim

```sh
aml-brand-verify credential.json brand-trust-roots.json revocations.json buyer-policy.json
```

With the fourth file, the command exits zero only for `claim_verified: true`; otherwise it exits one with a reason. Without it, the older official-signer check retains its existing behavior. The library call is `verifyBrandClaim(credential, roots, revocations, policy)`.

A positive result is limited to the **buyer-pinned snapshots at the verifier's local time**. Refresh the pins after any trusted registry update and before relying on the result for a new transaction. Even a positive result cannot establish that no newer revocation exists, authenticate an untrusted policy, grant trademark rights, or replace review of the written agreement.
