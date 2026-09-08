# ĀML Error Messages — Human, Short

**Status: DRAFT**

| Condition | Public message |
|---|---|
| Missing purpose | `Purpose is required.` |
| Missing attention cost | `Attention cost is required.` |
| Missing restoration value | `Restoration value is required.` |
| Invalid number | `Use a numeric value here.` |
| Suppressed by policy | `This element was suppressed by policy.` |
| Consent required | `Consent is required before this can render.` |
| Personal data blocked | `This element requests personal data that the active policy does not allow.` |
| Motion blocked | `Motion was suppressed because reduced motion is active.` |
| Contrast declaration missing | `Contrast safety is not declared.` |
| Keyboard declaration missing | `Keyboard accessibility is not declared.` |
| Receipt invalid | `Receipt verification failed.` |
| Receipt mutated | `Receipt content does not match its integrity hash.` |
| Credential self-signed only | `Signature is valid, but this is not an official ĀRU authorization.` |
| Credential revoked | `This authorization has been revoked.` |
| Credential expired | `This authorization has expired.` |
| Wire replay | `This message has already been used.` |
| Capability mismatch | `The two runtimes do not share the required capability.` |
| Unknown policy | `Policy not found.` |
| Invalid AML | `AML could not be parsed. Check the highlighted line.` |
| Internal failure | `AML could not complete this evaluation.` |

Errors should explain what failed without claiming ethical, legal, or accessibility certainty.
