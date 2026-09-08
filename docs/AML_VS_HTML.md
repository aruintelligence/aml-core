# ĀML™ and HTML: Different Jobs in the Stack

ĀML™ is not based on the claim that browsers have stopped using HTML. The current compiler deliberately produces browser-compatible output.

The distinction is architectural.

## HTML's job

HTML describes document structure and content. Combined with CSS and JavaScript, it forms the dominant presentation substrate of the web.

## ĀML's experimental job

ĀML adds a meaning-and-policy layer before rendering. It lets authored interface elements carry declared purpose and policy inputs that can be evaluated before output is emitted.

| Question | HTML-oriented stack | ĀML experiment |
|---|---|---|
| What exists? | Strong | Strong through compilation |
| How is it structured? | Strong | Compiles to browser structure |
| Why does it exist? | Usually implicit | Declared |
| What attention does it consume? | Usually external | Explicit model input |
| Can rendering be policy-gated? | Added separately | Core experiment |
| Is the decision inspectable? | Depends on application | Emits decision artifacts |

## The point is not replacement for its own sake

ĀML can be understood as a pre-render decision layer. Today it compiles to HTML because compatibility matters. Future targets could vary, but the research question remains the same: can interfaces carry enough declared meaning to make rendering decisions inspectable?

## Current EthicalRenderGate™ model

```text
render_allowed = restoration_value ≥ attention_cost
```

This rule is intentionally simple. It is not presented as universal ethics or validated human measurement. Its value is that it makes the decision process visible, reproducible, and open to criticism.

## Live implementation

https://aruintelligence.github.io/aml-core/

Repository:

https://github.com/aruintelligence/aml-core

ĀML™, ĀRU Meaning Language™, EthicalRenderGate™, and Meaning-Native Computing™ are claimed marks of ĀRU Intelligence Inc.™
