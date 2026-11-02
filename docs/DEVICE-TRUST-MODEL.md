# Stage 2: executable membership policy laboratory

The stage-1 [requirements](DEVICE-TRUST-DESIGN.md) now have an isolated C++17
policy model in `src/device_trust.h` and `src/device_trust.cpp`. It is built only
when `BUILD_TESTING` is enabled and is **not linked into the shipping plugin**.
No existing profile, tab, vault, transport, runtime version or encryption setting
is modified by this work. The [protocol design](DEVICE-TRUST-PROTOCOL.md) records
the concrete pairing direction and remaining integration requirements.

## Implemented boundary

The model validates typed membership proposals and certificates with fixed-width,
domain-separated encodings. It derives state/intent digests using the existing
platform SHA-256 backend and delegates approval signature verification to an
explicit `SignatureVerifier` implementation. No permissive production verifier,
private-key signer or key-release function is supplied.

Membership starts from a locally pinned, explicitly supplied genesis. Constructing
a new `Membership` from arbitrary remote data is not a trust decision. Future
integration must reconstruct and validate a pinned chain and protected local
approval witnesses; missing/corrupt saved state cannot create a replacement group.
The in-memory fork latch records conflicting child-state digests. The future
archive/journal adapter must additionally preserve the exact authenticated
certificate bytes for both branches; digests alone are not durable proof storage.

The model covers:

- one-signature bootstrap to the second device, then two distinct admitted
  signing identities, including after removal of the founder;
- exclusion of applicants and removal targets from voting;
- duplicate/colliding identities and retired identity reuse;
- exact group, root, parent, epoch, key-generation, public key-commitment and request binding;
- bounded certificate decoding and validation of every supplied approval;
- local sign-once reservations, with no timeout/cancel reset API;
- valid conflicting certificates at retained ancestors, with a sticky fork
  condition rather than automatic branch selection;
- idempotent accepted intents and separate handling of new expired requests
  versus delayed historical evidence.

Two identities do not prove independent physical hosts. An existing compromised
reader can still leak its plaintext or group key. Fixed two-approval membership
does not guarantee distributed consensus; a fork can remain hidden by transport.
See the full threat boundary rather than treating a passing model as a security
certification.

## Persistence and user verification are not simulated security

`reserve()` is an **in-memory** policy operation. Before a real client signs, the
vault-backed coordinator must durably commit the exact reservation, then use the
matching human-verification receipt. Copying a model object in a test demonstrates
state-machine behavior, not disk durability, protection from backup rollback,
process exclusion or power-loss guarantees. There is deliberately no production
key delivery until that adapter and the versioned signed event path are qualified.

Similarly, computing `verificationDigest()` is not proof that a user compared it.
Only a trusted-screen/out-of-band comparison in the reviewed pairing flow may
authorize `reserve()`. Neither a received QR image nor an approval-file boolean
is an acceptable substitute for that local decision.

## Test evidence and reproducibility

Build and run the focused offline test on Linux with a C++17 compiler, OpenSSL
development files and zlib:

```sh
bash tests/run-device-trust.sh
```

Or use CMake/CTest; a native plugin build also includes this test automatically
through the existing `BUILD_TESTING` configuration:

```sh
cmake -S . -B build-model -DCQS_BUILD_NATIVE_PLUGIN=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build-model --parallel 2
ctest --test-dir build-model --output-on-failure
```

These commands never start CopyQ or inspect a user profile. The focused test
uses a clearly marked deterministic public **test verifier**, not real signatures.
Its positive policy cases cannot establish the correctness of a future Ed25519
adapter. Real cryptographic vectors, invalid-key checks and end-to-end peer
verification remain independent requirements.

`tests/fixtures/device_trust_vectors.h` freezes independent canonical bytes and
SHA-256 values produced by Python `struct`/`hashlib`. Signature-shaped fixture
bytes are public placeholders. To compare deliberate regeneration:

```sh
python3 tests/generate-device-trust-vectors.py > /tmp/cqs-device-trust-vectors.h
diff -u tests/fixtures/device_trust_vectors.h /tmp/cqs-device-trust-vectors.h
```

The [acceptance matrix](DEVICE-TRUST-ACCEPTANCE.md) remains the product-level gate
register. Do not mark physical-device delivery, durable recovery, real signing,
CopyQ encryption coexistence or an automatic installer as passed by these tests.
Exact test counts/results belong to the implementing PR and its current CI run.
