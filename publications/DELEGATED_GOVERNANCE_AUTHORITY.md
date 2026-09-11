# ĀML delegated governance authority

Long-lived AI interfaces need governance that can be changed without handing a permanent root signing key to every operator.

ĀML now supports project-defined delegated authority for protected live policy transitions.

A verifier may trust a governance root key while allowing that root to delegate the capability `governance-policy-transition` to an operational key. Signed delegation chains preserve issuer/delegate identity labels, cryptographic key continuity, capability scope, and optional expiry across multiple hops.

The leaf key still signs the exact live policy transition. That transition remains bound to the stream identifier, current policy epoch, prior policy-state SHA-256, and requested update. The stream refuses the mutation before state changes if the chain breaks, the capability is absent, the root is not trusted, a key is revoked, the leaf does not match the transition signer, or the verifier has not explicitly enabled delegated authority.

This creates a practical separation between **root trust** and **operational authority** while keeping the verifier in control of both.

It does not prove real-world identity, employment, organizational approval, regulation, certification, adoption, independent validation, or official ĀRU authorization. Root trust remains an external verifier decision.
