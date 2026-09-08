# ĀML™ Open Research Program

ĀML™ is intentionally published as an executable research prototype rather than a closed claim. The next stage is to test which parts of meaning-native, policy-aware rendering survive contact with real developers, real users, accessibility requirements, adversarial inputs, and alternate policy models.

## Research tracks

### 1. Language and compiler

- richer semantic declarations
- malformed-input handling
- deterministic compiler behavior
- improved source diagnostics
- stable Abstract Meaning Tree representation
- additional output targets

### 2. Policy models

EthicalRenderGate™ currently uses a simple inspectable baseline. Research should compare alternate gates against the same source programs rather than assuming one formula is universally correct.

Questions include:

- How should policy inputs be defined?
- Which values should be user-controlled?
- How should uncertainty be represented?
- When should an interface degrade instead of suppress?
- How can conflicting policy models be compared reproducibly?

### 3. Accessibility

Meaning-native source should be tested against accessibility needs rather than treated as a substitute for established accessibility practice. Potential work includes semantic mappings, keyboard behavior, assistive technology testing, and accessibility-aware render gates.

### 4. AI-generated interfaces

A major research direction is requiring generated components to carry machine-readable purpose and policy metadata before rendering. This could create inspectable checkpoints between generative models and the final interface.

### 5. Measurement

The current attention and restoration values are declared model inputs, not validated human measurements. Serious deployment would require operational definitions, empirical protocols, replication, and independent review.

### 6. Security and adversarial behavior

Any system that accepts declared intent must assume authors or models may supply misleading declarations. Research should explore validation, provenance, conflicting evidence, and policy enforcement that does not blindly trust metadata.

## How to participate

Start with the working implementation, run the tests, reproduce the compiler outputs, and challenge the assumptions.

Repository: https://github.com/aruintelligence/aml-core

Live laboratory: https://aruintelligence.github.io/aml-core/

Contribution guide: https://github.com/aruintelligence/aml-core/blob/main/CONTRIBUTING.md

Security policy: https://github.com/aruintelligence/aml-core/blob/main/SECURITY.md

## Principle

ĀML does not need agreement to be useful as a research platform. It needs assumptions that can be seen, code that can be run, outputs that can be reproduced, and claims that can be challenged.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**
