// runtime/policyProfiles.js
// ĀML v1.2 — user-owned and organization-owned policy profiles.

export const BUILTIN_POLICY_PROFILES = Object.freeze({
  calm_default: {
    id: "calm_default",
    description: "Balanced restorative rendering with consent awareness.",
    policies: ["restorative_v1", "consent_guard_v1"]
  },
  strict_attention: {
    id: "strict_attention",
    description: "Stricter attention threshold plus consent awareness.",
    policies: ["attention_conservative_v1", "consent_guard_v1", "session_attention_budget_v1"]
  },
  privacy_first: {
    id: "privacy_first",
    description: "Require restorative value, explicit consent where declared, privacy consent for personal-data collection, and respect for session attention budget.",
    policies: ["restorative_v1", "consent_guard_v1", "privacy_guard_v1", "session_attention_budget_v1"]
  }
});

export function resolvePolicyProfile(profile = "calm_default") {
  if (typeof profile === "string") {
    const builtIn = BUILTIN_POLICY_PROFILES[profile];
    if (!builtIn) throw new Error(`Unknown ĀML policy profile: ${profile}`);
    return structuredClone(builtIn);
  }

  if (profile && typeof profile === "object" && Array.isArray(profile.policies)) {
    return {
      id: profile.id || "custom_profile",
      description: profile.description || "Custom ĀML policy profile.",
      policies: [...profile.policies]
    };
  }

  throw new Error("Invalid ĀML policy profile.");
}

export function listPolicyProfiles() {
  return Object.values(BUILTIN_POLICY_PROFILES).map(profile => ({
    id: profile.id,
    description: profile.description,
    policies: [...profile.policies]
  }));
}
