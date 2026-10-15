# Python AML wire runtime

This dependency-free Python implementation reads `protocol/discovery.json`, negotiates a wire version and required capabilities, validates `aml-wire/1` envelopes, and verifies policy passports, content-addressed bundles, selective-disclosure commitments, and causal execution graphs. It does not import the JavaScript interoperability modules. It is maintained **inside** `aml-core`, so it is not an external witness or independent adoption claim.

From the repository root:

```bash
node scripts/check-python-wire-runtime.mjs
python3 independent/python/wire_runtime.py negotiate protocol/discovery.json protocol/discovery.json --required policy-passports
python3 independent/python/wire_runtime.py verify passport path/to/passport.json --now 2030-01-01T12:00:00Z
```

The first command creates artifacts with the JavaScript runtime, compares 19 selected envelope cases against Python, checks five other artifact classes and mutations, prints a compact JSON report, and removes temporary vectors. CI uploads that report as `aml-wire-envelope-cross-runtime-<commit>`. The Python module itself is standalone. Its CLI exits 0 for a valid artifact or accepted session and 1 for an invalid artifact or rejected session, with a JSON report on stdout.

## Interoperability boundaries found

- RFC 0005 and 0006 describe object-key sorting but do not define numeric JSON serialization or the locale used for selective-disclosure claim ordering. This implementation accepts only safe integers in hashed JSON and lowercase ASCII-letter disclosure keys; other values fail explicitly. This is a documented subset, not a complete cross-language canonicalization contract.
- JavaScript and Python now agree on the selected envelope structure, capability, metadata, kind, and time mutation cases in `scripts/check-python-wire-runtime.mjs`. Both reject unknown fields and duplicate capabilities. The portable timestamp profile accepts a calendar-valid ISO date-time with a timezone and at most three fractional second digits. The published schema describes this subset; the validators should still be checked on any newly supported data shapes.
- The passport schema excludes extra fields, while the JavaScript verifier hashes whatever additional fields appear. Python rejects extra fields. Both implementations reject modified hash-bound preferences and expired passports on the tested subset.
- A disclosure commitment proves that the revealed values and hidden leaf hashes fit one root. It does not prove the hidden values, the holder's identity, or the truth of the claims.
- Causal graph verification proves the integrity of declared parent links and topology; it does not prove that the declared causal relationship is true.

These boundaries should be resolved in a versioned canonicalization contract before accepting arbitrary JSON numbers or internationalized claim keys as portable across runtimes. The positive and negative cases run in [the Python wire workflow](../../.github/workflows/python-wire-runtime.yml).
