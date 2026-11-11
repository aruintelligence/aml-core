#!/usr/bin/env python3
"""Untrusted lab client. Absence of a reply is uncertainty, never retry."""
import json
import os
from pathlib import Path
import sys
import time
import uuid


def exchange(inbox, outbox, raw):
    identifier = uuid.uuid4().hex
    request = Path(inbox) / (identifier + ".request")
    staged = Path(inbox) / (identifier + ".tmp")
    response = Path(outbox) / (identifier + ".response")
    try:
        # The synthetic lab queue is shared across two OS identities. Its
        # request bytes contain no production secrets; real deployments need
        # a dedicated authenticated transport and private queue ACLs.
        fd = os.open(staged, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, request)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if response.exists():
                result = json.loads(response.read_bytes())
                if isinstance(result, dict) and result.get("state") == "DENIED":
                    return result
                challenge = json.loads(raw).get("challenge")
                if isinstance(result, dict) and result.get("challenge") == challenge:
                    return result
                return {"state": "UNCERTAIN", "independent_confirmation": False}
            time.sleep(0.01)
    except (OSError, ValueError, TypeError):
        pass
    return {"state": "UNCERTAIN", "independent_confirmation": False}


if __name__ == "__main__":
    print(json.dumps(exchange(sys.argv[1], sys.argv[2], sys.stdin.buffer.read(65537))))
