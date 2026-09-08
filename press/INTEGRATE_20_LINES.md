# Integrate ĀML in about 20 lines

**Status: SHIPPED copy-paste integration note**

```js
import { createInterfaceFirewall } from "../index.js";

const firewall = createInterfaceFirewall({ profile: "human_first" });

const result = firewall.enforce({
  transmission: "pricing",
  nodes: [{
    type: "message",
    identifier: "offer",
    properties: {
      purpose: "Explain pricing",
      content: "Simple monthly price",
      attention_cost: 1,
      restoration_value: 2
    }
  }]
});

if (result.allowed) document.body.innerHTML = result.html;
else console.log(result.receipt);
```

The point is not to replace the frontend stack. The point is to put a reviewable policy boundary between machine intent and human-facing output.

Try AML first:
https://aruintelligence.github.io/aml-core/playground.html

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
