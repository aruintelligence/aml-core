#!/usr/bin/env python3
"""AST data-flow pass for scripts/check-valid-field-decisions.mjs.

For each Python file, report names, functions and dict keys whose value is
derived only from a `valid` field (x["valid"], x.get("valid"), x.valid), so
the checker can treat their uses as reads of `valid`. Derivation follows
assignments (including tuple unpacking of literal tuples and augmented
boolean expressions), function return values (also across `from .mod
import f` within the scanned set), and dict literals. An expression that also
reads an explicit decision field is not valid-only. Standard library only.
"""
import ast
import json
import os
import sys

EXPLICIT = {"authorized", "verified", "requested_conditions_met", "official", "claim_verified", "policy_met",
            "threshold_met", "witness_met", "inputs_met", "trusted", "accepted", "signature_valid", "registry_valid"}


def is_valid_read(node):
    if isinstance(node, ast.Attribute) and node.attr == "valid":
        return True
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and key.value == "valid":
            return True
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
            and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "valid"):
        return True
    return False


def reads_explicit(node):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in EXPLICIT:
            return True
        if isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant) and sub.slice.value in EXPLICIT:
            return True
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "get" and \
                sub.args and isinstance(sub.args[0], ast.Constant) and sub.args[0].value in EXPLICIT:
            return True
    return False


def valid_only(node, names, functions):
    """Positive, valid-derived-only boolean expression."""
    if node is None or reads_explicit(node):
        return False
    if is_valid_read(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Call):
        func = node.func
        fname = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if fname == "bool" and len(node.args) == 1:
            return valid_only(node.args[0], names, functions)
        return fname in functions
    if isinstance(node, ast.BoolOp):
        return all(valid_only(v, names, functions) or (isinstance(v, ast.Constant) and v.value is True)
                   for v in node.values) and any(valid_only(v, names, functions) for v in node.values)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        right = node.comparators[0]
        if isinstance(node.ops[0], (ast.Is, ast.Eq)) and isinstance(right, ast.Constant) and right.value is True:
            return valid_only(node.left, names, functions)
    return False


def analyze(tree, imported_functions=()):
    names, functions, properties = set(), set(imported_functions), set()
    for _ in range(8):
        before = len(names) + len(functions) + len(properties)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                for target in targets:
                    if isinstance(target, ast.Name) and valid_only(value, names, functions):
                        names.add(target.id)
                    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
                        for t, v in zip(target.elts, value.elts):
                            if isinstance(t, ast.Name) and valid_only(v, names, functions):
                                names.add(t.id)
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value != "valid" \
                            and valid_only(v, names, functions):
                        properties.add(k.value)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
                for kw in node.keywords:
                    if kw.arg and kw.arg != "valid" and valid_only(kw.value, names, functions):
                        properties.add(kw.arg)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Return) and valid_only(sub.value, names, functions):
                        functions.add(node.name)
            if isinstance(node, ast.Lambda) and valid_only(node.body, names, functions):
                pass
        if len(names) + len(functions) + len(properties) == before:
            break
    return names, functions, properties


def main(argv):
    if len(argv) >= 2 and argv[0] == "--stdin":
        tree = ast.parse(sys.stdin.read())
        names, functions, properties = analyze(tree)
        print(json.dumps({argv[1]: {"names": sorted(names), "functions": sorted(functions),
                                    "properties": sorted(properties)}}))
        return 0
    base, files = argv[0], argv[1:]
    trees = {}
    for rel in files:
        with open(os.path.join(base, rel), encoding="utf-8") as handle:
            trees[rel] = ast.parse(handle.read(), filename=rel)
    exported = {rel: analyze(tree)[1] for rel, tree in trees.items()}
    out = {}
    for rel, tree in trees.items():
        imported = set()
        directory = os.path.dirname(rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module.replace(".", "/") + ".py"
                for candidate in (os.path.normpath(os.path.join(directory, mod)), mod):
                    for alias in node.names:
                        if alias.name in exported.get(candidate, ()):
                            imported.add(alias.asname or alias.name)
        names, functions, properties = analyze(tree, imported)
        out[rel] = {"names": sorted(names), "functions": sorted(functions), "properties": sorted(properties)}
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
