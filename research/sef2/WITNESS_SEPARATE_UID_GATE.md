# SEF2 Witness Separate-UID Test Gate

Research only. Not a production security certification.

Run `python3 research/sef2/test_witness_separate_uid.py` as root **only in an isolated disposable Linux test runner**. The test skips when not root or not Linux.

## Verified by this test when executed successfully
- The witness process uses the privileged test runner's UID and owns a mode-0600 SQLite file.
- A different unprivileged UID (65533) cannot advance the witness through the Unix socket.
- The explicitly allowed UID (65534) can advance exactly once using a valid chain extension; replay is rejected.
- The allowed UID cannot directly modify the witness SQLite file.

## Assumptions and limitations
- This test creates synthetic credentials and a temporary witness database, not a production authority.
- Both UIDs must be unused and available in the isolated environment. Never run in a shared or production host.
- The test does **not** establish that an authorized record was independently committed by the reservation authority.
- The socket server runs as a thread in the root test process; a real deployment requires a separately administered service and protected socket directory.
- A privileged host administrator can modify the witness database, socket, code, or process; no rollback-resistance claim is made against that adversary.
- No cryptographic mutual authentication, remote witness, or cross-host replication is provided.

Do not advertise the witness as independently enforceable until the deployment, identity, recovery, and rollback tests are performed under the stated threat model.
