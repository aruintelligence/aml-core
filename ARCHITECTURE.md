# ĀML Architecture

## System Overview

ĀML is composed of five primary layers:

1. Parser Layer
2. Compiler Layer
3. Ethical Rendering Runtime
4. Decision Audit Layer
5. Output Generation Layer

---

# 1. Parser Layer

Responsible for:
- parsing `.aml` syntax
- extracting metadata
- validating semantic structures
- constructing the render tree

Outputs:
- Abstract Meaning Tree (AMT)

---

# 2. Compiler Layer

Responsible for:
- semantic transformation
- render planning
- ethical evaluation preparation
- output generation

Outputs:
- HTML
- CSS
- JavaScript
- memory.json
- render_decision.json

---

# 3. Ethical Rendering Runtime

The runtime evaluates:

```aml
render_allowed = restoration_value >= attention_cost
