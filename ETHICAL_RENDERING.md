# ETHICAL_RENDERING.md

# ĀML Ethical Rendering Framework
## Version 1.0 Draft

---

# 1. Overview

The AML Ethical Rendering Framework defines how AML systems evaluate whether rendering should occur at all.

Traditional rendering systems primarily ask:
- can this render?

AML systems additionally ask:
- should this render?
- what cognitive cost does this impose?
- what restorative value does this provide?
- does this preserve coherence?
- does this protect human attention?

Rendering becomes an ethical decision rather than purely a technical operation.

---

# 2. Core Principle

The foundational AML rendering rule:

```aml id="jlwmq1"
render_allowed =
  restoration_value >= attention_cost
