#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
# Build, then run the binary directly: `go run` reports any non-zero exit as
# 1, which would erase the distinction between 3 (valid, not authorized) and
# 1 (invalid) or 2 (input error).
BIN_DIR="$(mktemp -d)"
trap 'rm -rf "$BIN_DIR"' EXIT
go build -o "$BIN_DIR/aml-go-verifier" .
set +e
"$BIN_DIR/aml-go-verifier" "$@"
status=$?
set -e
exit "$status"
