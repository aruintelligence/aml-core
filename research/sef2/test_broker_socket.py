"""Actual broker subprocess tests over Unix-domain sockets (synthetic)."""
import json
import multiprocessing
import os
import pathlib
import sqlite3
import socket
import tempfile
import time
import unittest
import test_gated_action_broker as fixtures
from broker_socket import BrokerServer,request_action

def serve(socket_path,broker):
    with BrokerServer(socket_path,broker) as server:
        server.serve_forever(poll_interval=0.05)

class BrokerProcessTests(unittest.TestCase):
    def setUp(self):
        # Reuse the exact signed test fixture without inheriting its test methods.
        self.fixture=fixtures.CapabilityBoundaryTests(methodName="test_capability_required")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root=pathlib.Path(self.fixture.broker.path).parent
        self.socket_path=self.root/"broker.sock"
        self.process=multiprocessing.Process(target=serve,args=(str(self.socket_path),self.fixture.broker))
        self.process.start()
        self.addCleanup(self.stop)
        for _ in range(100):
            if self.socket_path.exists():
                break
            time.sleep(0.02)
        self.assertTrue(self.socket_path.exists())
    def stop(self):
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=5)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=5)
    def envelope(self):
        return {"request":self.fixture.request,"attestations":self.fixture.signed(),
                "capability":self.fixture.token()}
    def test_signed_action_via_separate_process(self):
        env=self.envelope()
        self.assertEqual(request_action(self.socket_path,env),"APPLIED")
        self.assertEqual(request_action(self.socket_path,env),"ALREADY_APPLIED")
        self.assertEqual(self.fixture.count(),1)
    def test_unauthorized_action_denied_over_socket(self):
        env=self.envelope()
        env["capability"]=None
        self.assertEqual(request_action(self.socket_path,env),"DENIED")
        self.assertEqual(self.fixture.count(),0)
    def test_malformed_and_oversized_messages_fail_closed(self):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(str(self.socket_path))
            client.sendall(b'{"malformed":true}\n')
            self.assertEqual(json.loads(client.recv(1024))["status"],"DENIED")
        self.assertEqual(request_action(self.socket_path,{"junk":"x"*70000}),"DENIED")
        self.assertEqual(self.fixture.count(),0)
    def test_duplicate_json_keys_fail_closed(self):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(str(self.socket_path))
            client.sendall(b'{"request":{},"request":{},"attestations":[],"capability":null}\\n')
            self.assertEqual(json.loads(client.recv(1024))["status"],"DENIED")
        self.assertEqual(self.fixture.count(),0)
    def test_same_uid_direct_storage_bypass_is_demonstrated(self):
        # Red-team negative control: the test client runs under the broker's
        # OS UID and can mutate its DB without any capability. This MUST be
        # eliminated by an actual separate-UID deployment before security claims.
        self.assertEqual(request_action(self.socket_path,{"request":self.fixture.request,
            "attestations":[],"capability":None}),"DENIED")
        with sqlite3.connect(self.fixture.broker.path) as db:
            db.execute("INSERT INTO effects VALUES (?,?)",("unauthorized-direct-write","0"*64))
        self.assertEqual(self.fixture.count(),1)
    def test_killed_broker_fails_closed_and_restarts_idempotently(self):
        env=self.envelope()
        self.assertEqual(request_action(self.socket_path,env),"APPLIED")
        self.stop()
        self.assertEqual(request_action(self.socket_path,env,timeout=0.2),"DENIED")
        self.socket_path.unlink(missing_ok=True)
        restarted=multiprocessing.Process(target=serve,args=(str(self.socket_path),self.fixture.broker))
        restarted.start()
        try:
            for _ in range(100):
                if self.socket_path.exists():
                    break
                time.sleep(0.02)
            self.assertEqual(request_action(self.socket_path,env),"ALREADY_APPLIED")
            self.assertEqual(self.fixture.count(),1)
        finally:
            restarted.terminate()
            restarted.join(timeout=5)
