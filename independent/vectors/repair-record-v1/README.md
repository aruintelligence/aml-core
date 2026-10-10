# Frozen repair record v1

`record.json` binds share 0 and share 2 from [`shards-v1`](../shards-v1/README.md) to the regenerated share 1 under the external [`trusted-policy.json`](../archive-v1/trusted-policy.json). It is one exact canonical wire example. The policy must be obtained independently during actual recovery; this repository fixture is test data.

The JavaScript test compares exact bytes. The Python cross-runtime check independently regenerates a matching record for each missing index and rejects tampering and overwrite.
