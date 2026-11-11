#!/usr/bin/env python3
"""Linux two-UID falsification lab, with synthetic effects and root orchestration.

The AI host attacker runs as nobody; the execution service and its stores run
as aml_sef_lab. The root test orchestrator is trusted. This is not a remote
administrative domain, a real provider, or protection against root compromise.
"""
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time
import unittest

from lab_test import Lab, ROOT, observe, RESULTS

SERVICE_USER = "aml_sef_lab"
AGENT_USER = "nobody"


class TwoIdentityLab(Lab):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("root orchestrator required; run on disposable Linux runner")
        self.service_user = pwd.getpwnam(SERVICE_USER)
        self.agent_user = pwd.getpwnam(AGENT_USER)
        if self.service_user.pw_uid == self.agent_user.pw_uid:
            raise ValueError("separate_identity_required")
        super().setUp()
        # GitHub's checkout parent may be private to the runner account. Copy
        # only public fixture source into a readable temporary tree; the key
        # and databases stay under the distinct service-owned trusted path.
        self.code_root = self.base / "code"
        self.code_root.mkdir(mode=0o755)
        for name in ("research/sef1/service.py", "research/sef1/client.py",
                     "pilots/action-boundary/authorized_execution.py",
                     "pilots/action-boundary/sqlite_path.py"):
            target = self.code_root / name
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.parent.chmod(0o755)
            shutil.copyfile(ROOT / name, target)
            target.chmod(0o644)
        # The administrator provisions the issuer and both DBs before granting
        # the untrusted identity access to the public request inbox.
        os.chmod(self.base, 0o711)
        os.chown(self.trusted, self.service_user.pw_uid, self.service_user.pw_gid)
        for item in self.trusted.iterdir():
            os.chown(item, self.service_user.pw_uid, self.service_user.pw_gid)
        os.chown(self.inbox, self.agent_user.pw_uid, self.agent_user.pw_gid)
        os.chmod(self.inbox, 0o755)
        os.chown(self.outbox, self.service_user.pw_uid, self.service_user.pw_gid)
        os.chmod(self.outbox, 0o755)
        os.chown(self.agent, self.agent_user.pw_uid, self.agent_user.pw_gid)

    @staticmethod
    def as_user(user, *args):
        return ["setpriv", "--reuid", str(user.pw_uid), "--regid", str(user.pw_gid),
                "--init-groups", *map(str, args)]

    def start(self, fault=None):
        if self.process is not None:
            self.stop()
        command = [sys.executable, str(self.code_root / "research/sef1/service.py"),
                   "--inbox", str(self.inbox), "--outbox", str(self.outbox),
                   "--authority", str(self.authority), "--provider", str(self.provider),
                   "--public-key", str(self.public)]
        if fault:
            command += ["--fault", fault]
        self.process = subprocess.Popen(self.as_user(self.service_user, *command),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(0.1)
        if self.process.poll() is not None:
            raise RuntimeError(self.process.stderr.read().decode())

    def send(self, request, sandbox=True):
        raw = json.dumps(request, separators=(",", ":")).encode()
        child = subprocess.run(self.as_user(self.agent_user, sys.executable,
            self.code_root / "research/sef1/client.py", self.inbox, self.outbox),
            input=raw, capture_output=True, timeout=10)
        if child.returncode != 0:
            raise RuntimeError(child.stderr.decode())
        return json.loads(child.stdout)

    def test_separate_identity_denies_provider_and_key_access(self):
        self.start()
        request = self.request()
        first = self.send(request)
        observe("two_uid_authorized", "PROVIDER_REPORTED", first["state"], "local authorized effect")
        attack = ("import pathlib,sqlite3,sys\n"
                  "key,db,out=sys.argv[1:]\n"
                  "pathlib.Path(key).read_bytes()\n"
                  "sqlite3.connect(db).execute('DELETE FROM effects')\n"
                  "pathlib.Path(out).write_text('forged')\n")
        child = subprocess.run(self.as_user(self.agent_user, sys.executable, "-c", attack,
            self.private, self.provider, self.outbox / "forgery.response"), capture_output=True, timeout=10)
        observe("two_uid_key_denied", True, child.returncode != 0 and b"PermissionError" in child.stderr,
                "key custody boundary")
        # Test each route independently so early key denial does not mask a DB
        # or outbox permission mistake.
        for label, code, target in [
            ("two_uid_provider_write_denied", "import sqlite3,sys; sqlite3.connect(sys.argv[1]).execute('DELETE FROM effects')",
             self.provider),
            ("two_uid_receipt_forgery_denied", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('forged')",
             self.outbox / "forgery.response"),
        ]:
            result = subprocess.run(self.as_user(self.agent_user, sys.executable, "-c", code, target),
                                    capture_output=True, timeout=10)
            observe(label, True, result.returncode != 0 and
                    (b"PermissionError" in result.stderr or b"unable to open database file" in result.stderr)
                    and self.count() == 1,
                    "separate UID permissions")
        self.assertEqual(self.count(), 1)
        observe("two_uid_replay", "DENIED", self.send(request)["state"], "retained authority")
        observe("two_uid_status", first["effect_id"], self.status(request)["effect_id"],
                "same provider report")

    def test_attacker_cannot_restore_trusted_state(self):
        self.start()
        request = self.request()
        first = self.send(request)
        self.assertEqual(first["state"], "PROVIDER_REPORTED")
        self.stop()
        # The agent can restore its own inputs but cannot overwrite either
        # authority or provider state; restart of the service retains the claim.
        for path in (self.authority, self.provider):
            attack = subprocess.run(self.as_user(self.agent_user, sys.executable, "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'old snapshot')", path),
                capture_output=True, timeout=10)
            observe("two_uid_rollback_denied_" + path.stem, True,
                    attack.returncode != 0 and b"PermissionError" in attack.stderr,
                    "rollback-resistant under agent UID")
        self.start()
        observe("two_uid_host_replay", "DENIED", self.send(request)["state"], "retained claim")
        observe("two_uid_host_status", first["effect_id"], self.status(request)["effect_id"],
                "retained provider row")


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.TestSuite(TwoIdentityLab(name) for name in (
        "test_separate_identity_denies_provider_and_key_access",
        "test_attacker_cannot_restore_trusted_state"))
    result = runner.run(suite)
    print(json.dumps({"schema": "aml-sef-two-uid-lab/1", "assertions": RESULTS,
          "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
          "skipped": len(result.skipped), "trust_boundary": "separate unprivileged OS UIDs, trusted root/kernel"},
          indent=2))
    sys.exit(0 if result.wasSuccessful() and not result.skipped else 1)
