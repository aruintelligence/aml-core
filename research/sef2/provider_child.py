"""Isolated SEF/2 provider child for genuine process termination tests."""
import argparse
import os
from sef2 import start

p = argparse.ArgumentParser()
p.add_argument("--provider-db", required=True)
p.add_argument("--authority-url", required=True)
p.add_argument("--secret-hex", required=True)
p.add_argument("--fault", choices=["kill_after_claim", "kill_after_effect"])
p.add_argument("--port-file", required=True)
a = p.parse_args()
server, url = start("provider", a.provider_db, a.authority_url,
    bytes.fromhex(a.secret_hex), fault=a.fault)
with open(a.port_file + ".tmp", "w", encoding="ascii") as output:
    output.write(url)
    output.flush()
    os.fsync(output.fileno())
os.replace(a.port_file + ".tmp", a.port_file)
try:
    server.serve_forever()
finally:
    server.shutdown()
    server.server_close()
