# ĀML™ Policy Expressions

ĀML v1.1 preserves simple comparison expressions used by policy-oriented source programs.

Example:

```aml
ethical_render_gate {
  rule: restoration_value >= attention_cost
}
```

The lexer recognizes comparison operators:

```text
>
>=
<
<=
=
==
!=
```

The parser stores a comparison property in two forms:

```json
{
  "type": "Property",
  "name": "rule",
  "value": "restoration_value >= attention_cost",
  "expression": {
    "left": "restoration_value",
    "operator": ">=",
    "right": "attention_cost"
  }
}
```

This preserves both a readable value and structured expression metadata for tooling.

## Current boundary

v1.1 supports a single binary comparison in a property value. It does not yet implement arbitrary arithmetic, boolean chaining, parentheses, function calls, or execution of user-authored expressions.

That limitation is deliberate: the language should gain expression power alongside explicit semantics, tests, and security boundaries rather than quietly becoming an unrestricted scripting language.

## Browser parity

The dependency-free browser compiler implements the same comparison-token and parser behavior, and automated parity tests compare its tokens, AST, AMT, and render decisions against the Node compiler.
