# ĀML Decision Core 1 — Black-Box Executable Protocol

This protocol lets the ĀML conformance runner test an implementation as an external process without importing its code.

## Invocation

The runner launches the implementation once per vector and writes exactly one JSON object to standard input.

Valid input example:

```json
{"attention_cost":5,"restoration_value":1}
```

A valid implementation response MUST exit `0` and write a JSON object containing exactly one decision value of `ALLOW` or `SUPPRESS`:

```json
{"decision":"SUPPRESS"}
```

Additional response fields MAY be present, but the `decision` field is normative for Decision Core 1.

## Invalid inputs

For a must-reject vector, an implementation MUST signal rejection in one of two ways:

1. exit with a non-zero status; or
2. exit `0` and emit a JSON object containing a non-empty `error` field and no valid decision.

Silently coercing an invalid input and returning `ALLOW` or `SUPPRESS` is a conformance failure.

## Process rules

- stdout SHOULD contain only the machine-readable response;
- diagnostics SHOULD go to stderr;
- the executable MUST NOT require network access for Decision Core 1;
- the executable MUST NOT depend on the ĀML reference runtime if it is being presented as an independent implementation;
- identical input MUST produce identical decision output.

## Generic runner

From the repository root:

```bash
node conformance/run-external.mjs -- python3 conformance/independent-python/decision_cli.py
node conformance/run-external.mjs -- node conformance/independent-javascript/decision_cli.mjs
```

Any language can participate as long as its executable follows this stdin/stdout contract.

Passing this runner means only that the external executable reproduced `aml-conformance/decision-core-1` for the published vectors at the tested commit.
