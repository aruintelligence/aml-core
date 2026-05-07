# VERSIONING.md

# ĀML Versioning Strategy
## Version 1.0 Draft

---

# 1. Overview

This document defines the official versioning strategy for AML.

The AML versioning system exists to preserve:
- semantic stability
- compiler compatibility
- runtime interoperability
- deterministic evolution
- specification continuity
- long-term maintainability

Versioning should reduce fragmentation rather than increase it.

---

# 2. Core Principle

Language evolution must preserve meaning continuity whenever possible.

Breaking semantic continuity creates ecosystem instability.

AML prioritizes:
- stable interpretation
- inspectable evolution
- coherent migration paths
- deterministic compatibility

---

# 3. Version Format

AML follows semantic-style versioning:

```text id="jlwm8m"
MAJOR.MINOR.PATCH
