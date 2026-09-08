#!/usr/bin/env python3

import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS = ROOT / 'protocol' / 'browser-canonicalization-vectors.json'


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def main():
    data = json.loads(VECTORS.read_text(encoding='utf-8'))
    failures = []
    for vector in data['vectors']:
        rendered = canonical_json(vector['input'])
        digest = hashlib.sha256(rendered.encode('utf-8')).hexdigest()
        if rendered != vector['canonical']:
            failures.append(f"{vector['name']}: canonical mismatch")
        if digest != vector['sha256']:
            failures.append(f"{vector['name']}: sha256 mismatch")
    if failures:
        print(json.dumps({'valid': False, 'failures': failures}, indent=2, ensure_ascii=False))
        return 1
    print(json.dumps({
        'valid': True,
        'vectors': len(data['vectors']),
        'canonicalization': data['canonicalization']
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
