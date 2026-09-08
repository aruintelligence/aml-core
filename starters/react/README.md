# ĀML React Starter

Use the existing AML React adapter to put accountable policy evaluation around an existing component without rewriting the component itself.

```jsx
import React from "react";
import { createAccountableUI } from "../../index.js";

const AccountableUI = createAccountableUI(React);

export default function Pricing() {
  return (
    <AccountableUI
      id="pricing"
      purpose="Help the user understand pricing"
      attentionCost={1}
      restorationValue={2}
      policy="human_first"
      fallback={<p>Withheld by AML policy.</p>}
    >
      <section>
        <h2>Simple pricing</h2>
      </section>
    </AccountableUI>
  );
}
```

The adapter converts friendly React props into canonical AML intent and sends them through the same accountable execution pipeline used by native `.aml` source.

For an external app today, clone or vendor the AML repository until a registry package is independently verified as published.