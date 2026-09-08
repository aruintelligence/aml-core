# Meaning Gate

**Status: SHIPPED**

Meaning Gate brings semantic review into CI.

Instead of asking only whether code changed, it can ask whether the **meaning of the interface changed**.

Examples of changes worth surfacing:

- new personal-data collection
- consent requirement changes
- attention/restoration score changes
- policy regressions
- a previously calm flow becoming more pressuring

That enables a different pull-request question:

> Did this interface become materially more demanding or less accountable?

Example workflow:

```yaml
- uses: aruintelligence/aml-core/actions/meaning-gate@main
  with:
    before-file: before.aml
    after-file: after.aml
```

Meaning Gate is project-defined tooling, not a legal or ethical certification system.
