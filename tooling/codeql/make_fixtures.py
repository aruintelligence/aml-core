# Generates authz-bypass-fixtures.json (kept as data so the lexical checker
# never scans these intentionally vulnerable snippets as shipped code).
import json
F = {}
def add(lang, category, name, files, expect, field):
    F[name] = {"language": lang, "category": category, "files": files, "expect_flagged": expect, "field": field}
# 1. function arguments and helper returns
add("javascript","call-argument","js-call-argument",{"main.js":"function gate(ok) { if (ok) execute(); }\ngate(r.valid);\n"},True,"valid")
add("javascript","call-argument","js-helper-return-verified",{"main.js":"function fine(x) { return x.quorum_met; }\nprocess.exit(fine(r) ? 0 : 1);\n"},True,"quorum_met")
add("python","call-argument","py-call-argument",{"main.py":"def gate(ok):\n    if ok:\n        execute()\n\ngate(r[\"valid\"])\n"},True,"valid")
add("python","call-argument","py-helper-return-accepted",{"main.py":"import sys\n\ndef fine(x):\n    return x[\"accepted\"]\n\nsys.exit(0 if fine(r) else 1)\n"},True,"accepted")
# 2. object and container aliases
add("javascript","container","js-array-container",{"main.js":"const xs = [r.valid];\nif (xs[0]) execute();\n"},True,"valid")
add("javascript","container","js-object-container-verified",{"main.js":"const box = { inner: { go: r.verified } };\nif (box.inner.go) execute();\n"},True,"verified")
add("python","container","py-list-container",{"main.py":"box = [r[\"valid\"]]\nif box[0]:\n    execute()\n"},True,"valid")
add("python","container","py-dict-container-verified",{"main.py":"d = {\"go\": r[\"verified\"]}\nif d[\"go\"]:\n    execute()\n"},True,"verified")
# 3. computed property access
add("javascript","computed-property","js-computed-property",{"main.js":"const k = 'val' + 'id';\nif (r[k]) execute();\n"},True,"valid")
add("javascript","computed-property","js-computed-property-module",{"main.mjs":"export const run = r => { const key = 'quorum' + '_met'; if (r[key]) execute(); };\n"},True,"quorum_met")
add("python","computed-property","py-computed-key",{"main.py":"k = \"ver\" + \"ified\"\nif r[k]:\n    execute()\n"},True,"verified")
# 4. multiline expressions
add("javascript","multiline","js-multiline-ternary",{"main.js":"process.exit(r.valid\n  ? 0\n  : 1);\n"},True,"valid")
add("javascript","multiline","js-multiline-status",{"main.js":"function handler(req, res, r) {\n  return send(res,\n    r\n      .accepted\n      ? 200\n      : 403);\n}\n"},True,"accepted")
add("python","multiline","py-multiline-ifexp",{"main.py":"def main():\n    return (0\n            if r[\"valid\"]\n            else 1)\n"},True,"valid")
# 5. cross-file and imported values
add("javascript","cross-file","js-imported-value",{"main.mjs":"import { verdict } from './lib/value.mjs';\nif (verdict) execute();\n","lib/value.mjs":"export const verdict = globalThis.r.valid;\n"},True,"valid")
add("javascript","cross-file","js-package-import",{"main.mjs":"import { isOk } from 'aml-fixture-helpers';\nif (isOk(r)) execute();\n","package.json":"{\"name\":\"aml-fixture-root\",\"private\":true,\"type\":\"module\"}\n","packages/aml-fixture-helpers/package.json":"{\"name\":\"aml-fixture-helpers\",\"main\":\"index.mjs\"}\n","packages/aml-fixture-helpers/index.mjs":"export function isOk(r) { return r.official; }\n"},True,"official")
add("python","cross-file","py-imported-helper",{"main.py":"from helpers import is_ok\n\nif is_ok(r):\n    execute()\n","helpers.py":"def is_ok(r):\n    return r[\"valid\"]\n"},True,"valid")
# 6. Go aliases and wrappers
add("go","go-alias-wrapper","go-alias",{"go.mod":"module fixture\n\ngo 1.21\n","main.go":"package main\n\ntype Result struct{ Valid bool; Authorized bool }\n\nfunc decide(r Result) (string, int) {\n\tok := r.Valid\n\tout := \"x\"\n\tif ok {\n\t\treturn out, 0\n\t}\n\treturn out, 1\n}\n\nfunc main() { decide(Result{}) }\n"},True,"Valid")
add("go","go-alias-wrapper","go-wrapper-type-alias",{"go.mod":"module fixture\n\ngo 1.21\n","main.go":"package main\n\nimport \"os\"\n\ntype Result struct{ Verified bool }\ntype Res = Result\n\nfunc isOk(r Res) bool { return r.Verified }\n\nfunc main() {\n\tvar r Res\n\tif isOk(r) {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(1)\n}\n"},True,"Verified")
# authorization present only as an alternative (`||` / `or`) is not a decision
add("javascript","authorization-alternative","js-or-authorized",{"main.js":"if (r.valid || r.authorized) execute();\n"},True,"valid")
add("python","authorization-alternative","py-or-authorized",{"main.py":"if r[\"valid\"] or r[\"authorized\"]:\n    execute()\n"},True,"valid")
# negative controls: explicit authorization decision present
add("javascript","control","js-control-authorized",{"main.js":"if (r.authorized === true && r.verified) execute();\nprocess.exit(r.authorized === true && r.valid ? 0 : 3);\n"},False,None)
add("python","control","py-control-authorized",{"main.py":"if r[\"authorized\"] is True and r[\"verified\"]:\n    execute()\n"},False,None)
add("go","control","go-control-authorized",{"go.mod":"module fixture\n\ngo 1.21\n","main.go":"package main\n\nimport \"os\"\n\ntype Result struct{ Valid bool; Authorized bool }\n\nfunc main() {\n\tvar r Result\n\tif r.Authorized && r.Valid {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(3)\n}\n"},False,None)
json.dump({"schema":"aml-authz-dataflow-fixtures/1","note":"Intentionally vulnerable snippets for the Directive 010 data-flow queries. Data only; materialized into a temporary directory by scripts/check-authorization-dataflow.mjs.","fixtures":F}, open("authz-bypass-fixtures.json","w"), indent=1)
print(len(F))
