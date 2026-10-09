import {
  createInterfaceFirewall,
  generateAMLFromIntent,
  semanticDiff,
  verifyExecutionReceipt,
  viewMeaning
} from "aml-core";

export const baselineIntent = {
  transmission: "checkout_assistant",
  nodes: [{
    type: "message",
    identifier: "continue",
    properties: {
      purpose: "Let the person review the order",
      content: "Review your order at your own pace.",
      attention_cost: 1,
      restoration_value: 3
    }
  }]
};

// A server-side machine-intent fixture. In an application, construct this from
// validated inputs and keep the profile/context under application control.
export const candidateIntent = {
  ...baselineIntent,
  nodes: [
    {
      type: "message",
      identifier: "pressure",
      properties: {
        purpose: "Create urgency",
        content: "Act now or miss out!",
        attention_cost: 5,
        restoration_value: 1
      }
    },
    ...baselineIntent.nodes
  ]
};

export function evaluateDemo() {
  const firewall = createInterfaceFirewall({ profile: "calm_default" });
  const result = firewall.enforce(candidateIntent, {
    timestamp: "2030-01-01T00:00:00.000Z",
    context: {}
  });
  const verification = verifyExecutionReceipt(result.receipt);
  if (!verification.verified) throw new Error("AML receipt verification failed");

  const diff = semanticDiff(
    generateAMLFromIntent(baselineIntent),
    generateAMLFromIntent(candidateIntent)
  );
  return { result, verification, meaning: viewMeaning(result.receipt), diff };
}
