#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

node scripts/build-action-boundary-expanded.mjs --check
node scripts/verify-action-boundary-expanded.mjs --check
python3 scripts/verify-action-boundary-expanded.py
node scripts/build-action-five-runtime-report.mjs --check
node scripts/verify-action-browser-observation.mjs
node scripts/build-controlled-pilot-pages.mjs --check-before
node scripts/build-controlled-pilot-pages.mjs --check-after
node scripts/dispatch-controlled-pilot-pages.mjs --check
node scripts/build-action-site-browser-receipts.mjs --check
node scripts/build-action-receipt-adapters-report.mjs --check
node scripts/verify-action-receipt-registry.mjs --check
node scripts/build-action-release-manifest.mjs --check

node --test test/action-controlled-site-pilots.test.js \
  test/action-site-browser-evidence.test.js test/action-receipt-adapters.test.js
