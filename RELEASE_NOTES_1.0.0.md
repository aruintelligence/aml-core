# ĀML Core v1.0.0

This release establishes the first versioned public baseline of the ĀML compiler and EthicalRenderGate™ research prototype.

## Included

- ĀML lexer, parser, meaning-tree builder, render evaluator, and HTML generator
- Command-line compiler
- Browser demonstration
- Machine-readable render decisions
- Example ĀML documents
- Automated gate and end-to-end compiler smoke tests
- Continuous integration

## Verify

```bash
npm test
node bin/aml.js compile examples/transmission-061.aml dist
```

## Scope

This is a research prototype. Attention cost and restoration value are explicit model inputs, not validated measurements of cognition, ethics, harm, or wellbeing.
