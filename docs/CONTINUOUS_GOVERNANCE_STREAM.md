# ĀML Continuous Governance Stream

This surface exposes the existing streaming interface firewall across a process boundary using newline-delimited JSON (NDJSON).

Instead of waiting for a complete generated interface, a host can submit semantic interface nodes as they arrive and receive an ALLOW/SUPPRESS decision for each node before the stream is finalized.

## Protocol

A session begins with:

```json
{"protocol":"aml-governance-stream-open/1","transmission":"example","profile":"calm_default","mode":"enforce","failure_mode":"closed"}
```

Each generated node is then submitted as:

```json
{"protocol":"aml-governance-stream-node/1","node":{"type":"message","identifier":"cta","properties":{"purpose":"Create urgency","content":"Act now","attention_cost":5,"restoration_value":1}}}
```

The evaluator immediately emits:

```json
{"protocol":"aml-governance-stream-decision/1","identifier":"cta","aml_allowed":false,"effective_allowed":false,"would_suppress":true}
```

The stream ends with:

```json
{"protocol":"aml-governance-stream-finalize/1"}
```

and produces an `aml-governance-stream-result/1` summary.

## CLI

```bash
npm run governance-stream
```

or:

```bash
aml-governance-stream conformance/governance-stream/mixed.ndjson
```

The CLI accepts NDJSON from a file or standard input and emits one NDJSON result per accepted message.

## HTTP streaming gateway

```bash
npm run governance-stream:serve
```

Then stream NDJSON to:

```text
POST http://127.0.0.1:8791/v1/governance/stream
Content-Type: application/x-ndjson
```

The response is also NDJSON. Decisions are written as individual response lines rather than held until the full request has been evaluated.

## Why this is different from batch evaluation

Batch evaluation asks whether a completed group of intents passes policy. The continuous stream surface is designed for interfaces assembled incrementally by an agent or model. Governance can therefore remain between generation and rendering throughout the construction of the interface.

The stream tracks identifiers across the session and rejects duplicate identifiers. It also requires an explicit finalize message; silently truncated streams do not become successful final results.

## Evidence and production boundary

This is a project-defined research-prototype protocol. The current reference gateway is process-local on the ĀML side and uses HTTP/NDJSON only as the transport boundary. It does not claim distributed consensus, exactly-once network delivery, production authentication, authorization, rate limiting, or third-party protocol compatibility.

Project tests and the canonical fixture are E2-style project-controlled engineering evidence, not independent external reproduction.
