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
# 7. Directive 010 follow-up: Map contents, Reflect.get, getattr, and
#    authorization reads that do not control the success outcome
GOMOD = "module fixture\n\ngo 1.21\n"
add("javascript","map-container","js-map-container",{"main.js":"const m = new Map();\nm.set('go', r.valid);\nif (m.get('go')) execute();\n"},True,"valid")
add("javascript","map-container","js-map-unknown-key",{"main.js":"const m = new Map();\nm.set(keyOf(r), r.verified);\nif (m.get('x')) execute();\n"},True,"verified")
add("javascript","reflect","js-reflect-get",{"main.js":"if (Reflect.get(r, 'valid')) execute();\n"},True,"valid")
add("javascript","reflect","js-reflect-get-computed",{"main.js":"const k = 'quorum' + '_met';\nprocess.exit(Reflect.get(r, k) ? 0 : 1);\n"},True,"quorum_met")
add("python","getattr","py-getattr-computed",{"main.py":"k = 'val' + 'id'\nif getattr(r, k):\n    execute()\n"},True,"valid")
add("python","getattr","py-getattr-exit",{"main.py":"import sys\nsys.exit(0 if getattr(r, 'accepted', False) else 1)\n"},True,"accepted")
add("go","reflect","go-reflect-fieldbyname",{"go.mod":GOMOD,"main.go":"package main\n\nimport (\n\t\"os\"\n\t\"reflect\"\n)\n\ntype Result struct{ Valid bool }\n\nfunc main() {\n\tvar r Result\n\tif reflect.ValueOf(r).FieldByName(\"Valid\").Bool() {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(1)\n}\n"},True,"Valid")
add("javascript","authorization-not-controlling","js-authorized-other-branch",{"main.js":"const ok = r.valid;\nconst auth = r.authorized;\nprocess.exit(ok ? 0 : (auth ? 0 : 1));\n"},True,"valid")
add("javascript","authorization-not-controlling","js-authorized-other-branch-variable",{"main.js":"const code = r.accepted ? 200 : r.authorized ? 200 : 403;\nfunction h(res) { res.writeHead(code); }\nprocess.exitCode = r.verified ? 0 : r.authorized ? 0 : 1;\n"},True,"verified")
add("javascript","authorization-not-controlling","js-authorized-read-but-unused",{"main.js":"if (r.valid) {\n  if (r.authorized) log('ok');\n  execute();\n}\n"},True,"valid")
add("python","authorization-not-controlling","py-authorized-other-branch",{"main.py":"import sys\nsys.exit(0 if r['valid'] else (0 if r['authorized'] else 1))\n"},True,"valid")
add("python","authorization-not-controlling","py-authorized-other-branch-variable",{"main.py":"import sys\ncode = 0 if r['verified'] else 0 if r['authorized'] else 1\nsys.exit(code)\n"},True,"verified")
add("go","authorization-alternative","go-or-authorized",{"go.mod":GOMOD,"main.go":"package main\n\nimport \"os\"\n\ntype Result struct{ Valid bool; Authorized bool }\n\nfunc main() {\n\tvar r Result\n\tif r.Valid || r.Authorized {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(1)\n}\n"},True,"Valid")
add("go","authorization-not-controlling","go-authorized-read-but-unused",{"go.mod":GOMOD,"main.go":"package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\ntype Result struct{ Valid bool; Authorized bool }\n\nfunc main() {\n\tvar r Result\n\tif r.Authorized {\n\t\tfmt.Println(\"ok\")\n\t}\n\tif r.Valid {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(1)\n}\n"},True,"Valid")
add("javascript","authorization-not-controlling","js-guard-negated-authorized",{"main.js":"if (r.valid && !r.authorized) execute();\n"},True,"valid")
add("python","authorization-not-controlling","py-guard-negated-authorized",{"main.py":"if getattr(r, 'verified') and not r['authorized']:\n    execute()\n"},True,"verified")
add("go","authorization-not-controlling","go-guard-negated-authorized",{"go.mod":GOMOD,"main.go":"package main\n\nimport \"os\"\n\ntype Result struct{ Valid bool; Authorized bool }\n\nfunc main() {\n\tvar r Result\n\tif r.Valid && !r.Authorized {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(1)\n}\n"},True,"Valid")
add("javascript","authorization-not-controlling","js-early-return-wrong-polarity",{"main.js":"function f(r) {\n  if (r.authorized === true) return;\n  if (r.valid) execute();\n}\n"},True,"valid")
# negative controls: explicit authorization decision present
add("javascript","control","js-control-authorized",{"main.js":"if (r.authorized === true && r.verified) execute();\nprocess.exit(r.authorized === true && r.valid ? 0 : 3);\n"},False,None)
add("python","control","py-control-authorized",{"main.py":"if r[\"authorized\"] is True and r[\"verified\"]:\n    execute()\n"},False,None)
add("go","control","go-control-authorized",{"go.mod":"module fixture\n\ngo 1.21\n","main.go":"package main\n\nimport \"os\"\n\ntype Result struct{ Valid bool; Authorized bool }\n\nfunc main() {\n\tvar r Result\n\tif r.Authorized && r.Valid {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(3)\n}\n"},False,None)
add("javascript","control","js-control-map-authorized",{"main.js":"const m = new Map();\nm.set('go', r.authorized === true && r.valid);\nif (m.get('go')) execute();\n"},False,None)
add("javascript","control","js-control-ternary-chain",{"main.js":"process.exit(r.authorized === true ? 0 : Reflect.get(r, 'verified') ? 3 : 1);\n"},False,None)
add("python","control","py-control-ternary-chain",{"main.py":"import sys\nsys.exit(0 if r['authorized'] is True else 3 if getattr(r, 'verified') else 1)\n"},False,None)
add("go","control","go-control-reflect-authorized",{"go.mod":GOMOD,"main.go":"package main\n\nimport (\n\t\"os\"\n\t\"reflect\"\n)\n\ntype Result struct{ Valid bool; Authorized bool }\n\nfunc main() {\n\tvar r Result\n\tv := reflect.ValueOf(r)\n\tif v.FieldByName(\"Authorized\").Bool() && v.FieldByName(\"Valid\").Bool() {\n\t\tos.Exit(0)\n\t}\n\tos.Exit(3)\n}\n"},False,None)
add("javascript","control","js-control-early-return-deny",{"main.js":"function f(r) {\n  if (r.authorized !== true) return deny();\n  if (r.valid) execute();\n}\n"},False,None)
add("python","control","py-control-named-nonzero-exit",{"main.py":"import sys\nEXIT_NOT_AUTHORIZED = 3\n\ndef main():\n    return EXIT_NOT_AUTHORIZED if r['verified'] else 2\n\nsys.exit(main())\n","other.py":"EXIT_NOT_AUTHORIZED = 3\n"},False,None)
json.dump({"schema":"aml-authz-dataflow-fixtures/1","note":"Intentionally vulnerable snippets for the Directive 010 data-flow queries. Data only; materialized into a temporary directory by scripts/check-authorization-dataflow.mjs.","fixtures":F}, open("authz-bypass-fixtures.json","w"), indent=1)
print(len(F))
