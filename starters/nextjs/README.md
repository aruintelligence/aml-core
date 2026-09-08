# ĀML Next.js Starter

ĀML can sit in front of a Next.js UI without replacing React or HTML.

A practical pattern is:

1. Generate or receive machine intent on the server.
2. Run the AML Interface Firewall on that intent.
3. Render only the allowed result.
4. Persist or expose the execution receipt for View Meaning.

```js
// app/pricing/page.js
import { createInterfaceFirewall } from "../../../index.js";

export default async function PricingPage() {
  const firewall = createInterfaceFirewall({ profile: "human_first" });

  const result = firewall.enforce({
    transmission: "pricing_page",
    nodes: [{
      type: "message",
      identifier: "pricing",
      properties: {
        purpose: "Explain pricing clearly",
        content: "Simple pricing",
        attention_cost: 1,
        restoration_value: 2
      }
    }]
  });

  if (!result.allowed) return <p>Withheld by AML policy.</p>;
  return <main dangerouslySetInnerHTML={{ __html: result.html }} />;
}
```

For production use, avoid blindly rendering untrusted HTML. Apply the normal framework security model and output sanitization appropriate to your application.

AML is an accountability layer; it does not replace application security.