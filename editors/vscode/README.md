# ĀML™ VS Code Language Support

This folder contains a minimal VS Code language definition for `.aml` source files.

## Included

- `.aml` file recognition
- ĀML / AML language aliases
- line comments with `//`
- block comments with `/* ... */`
- bracket and quote pairing
- highlighting for core language blocks
- highlighting for policy fields
- highlighting for comparison operators
- numeric and string scopes

## Local development

Copy or symlink this folder into a VS Code extension-development workspace, then launch an Extension Development Host.

The extension currently provides declarative language support only. It does not yet bundle the compiler, semantic diagnostics, completion, hover documentation, go-to-definition, or a language server.

Those are natural next layers because the repository already exposes `compileSource()` and `analyzeAMT()` as programmatic APIs.

## Source of truth

Language behavior remains defined by the compiler and tests in the repository root. Editor highlighting should follow the language implementation rather than define new syntax independently.
