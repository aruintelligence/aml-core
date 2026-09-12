# Release monitoring state

`release-integrity-status.json` is intentionally explicit about the current registry-monitoring state. Before a confirmed npm publication of the stable target, the state is `inactive_until_publication`; this must never be interpreted as a passing live-registry integrity result. Synthetic rehearsals validate project logic only. After a real publication, the manual/scheduled live monitor is the evidence path that can establish a live registry result.
