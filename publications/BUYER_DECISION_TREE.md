# ĀML Buyer Decision Tree

**Status: DRAFT buyer aid grounded in SHIPPED AML surfaces**

Use this to decide whether ĀML deserves a pilot.

## 1. Does your product generate or dynamically assemble user-facing interface elements?

- **No** → ĀML may not be urgent for you.
- **Yes** → continue.

## 2. Do you need to inspect why those elements appeared, not only what code rendered them?

- **No** → existing frontend controls may already be enough.
- **Yes** → continue.

## 3. Would a declared purpose + policy decision + receipt improve reviewability?

- **No** → do not force AML into the stack.
- **Yes / unsure** → run the public proof and a small pilot.

## 4. Can you tolerate a research-prototype integration?

- **No** → watch the project rather than treating it as production infrastructure.
- **Yes** → use the 15-minute evaluation and 30-minute enterprise pilot.

## 5. What must be proven before a larger commitment?

Choose concrete acceptance criteria:

- deterministic replay
- policy behavior your team understands
- evidence mutation detection
- independent verification
- integration effort
- reviewer comprehension
- performance
- accessibility implications

The correct outcome can be **adopt**, **continue testing**, or **reject with evidence**.
