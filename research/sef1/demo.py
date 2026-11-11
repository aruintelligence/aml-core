#!/usr/bin/env python3
"""Run the synthetic payables integration end to end without external effects."""
import json
from lab_test import Lab


def main():
    lab = Lab(methodName="runTest")
    lab.setUp()
    try:
        lab.start()
        payment = lab.request(amount=1250)
        approved = lab.send(payment)
        replay = lab.send(payment)
        changed = lab.request(amount=1250)
        changed["envelope"]["request_bytes"] = changed["envelope"]["request_bytes"].replace(
            "fixture:merchant-a", "fixture:merchant-b")
        diversion = lab.send(changed)
        result = {"environment": "synthetic only", "amount_minor": 1250,
                  "authorized_submission": approved["state"], "replay": replay["state"],
                  "changed_destination": diversion["state"], "provider_effect_count": lab.count(),
                  "completion_confirmed": False}
        assert (result["authorized_submission"], result["replay"], result["changed_destination"],
                result["provider_effect_count"]) == ("PROVIDER_REPORTED", "DENIED", "DENIED", 1)
        print(json.dumps(result, indent=2))
    finally:
        lab.doCleanups()


if __name__ == "__main__":
    main()
