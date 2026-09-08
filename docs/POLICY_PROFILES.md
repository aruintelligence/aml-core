# ĀML Policy Profiles

Policy profiles bundle multiple rendering policies into a user-owned or organization-owned policy contract.

## Built-in profiles

### `calm_default`

- `restorative_v1`
- `consent_guard_v1`

### `strict_attention`

- `attention_conservative_v1`
- `consent_guard_v1`
- `session_attention_budget_v1`

### `privacy_first`

- `restorative_v1`
- `consent_guard_v1`
- `privacy_guard_v1`
- `session_attention_budget_v1`

Profiles currently use an `all_must_allow` composition strategy: if any component policy suppresses a node, the composed profile suppresses it.

## Why profiles matter

The same AML source can be rendered under different policy preferences without rewriting the interface itself. That makes the policy regime explicit and versionable.

Potential future profiles include accessibility-first, child-safe, healthcare, education, enterprise, government, and user-authored personal policy packs.

## Runtime context

Built-in context-aware policies can inspect values such as:

```json
{
  "consent_granted": true,
  "privacy_consent": false,
  "attention_budget_remaining": 4
}
```

The context is recorded in accountable execution receipts so later reviewers can inspect which runtime facts influenced the result.

## API

```js
import {
  listPolicyProfiles,
  resolvePolicyProfile,
  policyFromProfile
} from "aml-core";
```

Policy profiles are an experimental mechanism, not a universal ethics standard. Their value is that policy choices become explicit, testable, replaceable, and auditable.
