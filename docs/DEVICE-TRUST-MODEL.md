# Stage 2: executable membership policy laboratory

The stage-1 [requirements](DEVICE-TRUST-DESIGN.md) now have an isolated C++17
policy model in `src/device_trust.h` and `src/device_trust.cpp`. It is built with
`BUILD_TESTING`; the default native plugin does not link it. A separate opt-in
[native Signed Join experiment](DEVICE-TRUST-COORDINATOR.md#experimental-native-signed-join)
uses it for verified enrollment and a new local tab. The
[protocol design](DEVICE-TRUST-PROTOCOL.md) records the concrete pairing
direction and remaining integration requirements.

## Implemented boundary

The model validates typed membership proposals and certificates with fixed-width,
domain-separated encodings. It derives state/intent digests using the existing
platform SHA-256 backend and delegates approval signature verification to an
explicit `SignatureVerifier` implementation. The optional
[control-plane laboratory](DEVICE-TRUST-COORDINATOR.md) supplies a real libsodium
verifier, private-key signer, durable approval coordinator and per-recipient
key delivery for isolated tests. The base model keeps its dependency-free
verifier boundary.

Membership starts from a locally pinned, explicitly supplied genesis. Constructing
a new `Membership` from arbitrary remote data is not a trust decision. The
optional `TrustJournal` reconstructs the chain and local approval witnesses from
an encrypted dedicated record, validates externally supplied genesis/local pins,
and retains complete authenticated accepted and conflicting certificates.
Missing/corrupt saved state cannot create a replacement group. The base model's
in-memory fork digests alone remain insufficient durable proof storage.

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

`reserve()` is an **in-memory** policy operation. `TrustJournal::approve()` now
holds a Store lease, replays authenticated history, checks the exact confirmed
digest, durably commits the reservation, and only then calls the real signer.
Its tests separately exercise failed/ambiguous commits and disk reopening.
Copying the base model still demonstrates only state-machine behavior. Complete
disk/key backup rollback across restart, platform power-loss behavior and the
versioned signed event path remain qualification gates. The opt-in coordinator
exercises encrypted identity storage and per-recipient key delivery in isolation.

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

These commands never start CopyQ or inspect a user profile. The base policy test
uses a clearly marked deterministic public **test verifier**, not real signatures.
Its positive policy cases cannot establish cryptographic adapter correctness.
The separate opt-in identity/journal tests use real signatures, RFC 8032 vectors,
invalid-key checks and fault injection; see the
[build and validation instructions](DEVICE-TRUST-COORDINATOR.md#build-and-validation).
The separate [experimental native workflow](DEVICE-TRUST-COORDINATOR.md#experimental-native-signed-join)
prompts for full peer comparison and can open a reviewed checkpoint as a local
tab. Running the policy tests does not exercise that workflow or establish
physical-device verification.

`tests/fixtures/device_trust_vectors.h` freezes independent canonical bytes and
SHA-256 values produced by Python `struct`/`hashlib`. Signature-shaped fixture
bytes are public placeholders. To compare deliberate regeneration:

```sh
python3 tests/generate-device-trust-vectors.py > /tmp/cqs-device-trust-vectors.h
diff -u tests/fixtures/device_trust_vectors.h /tmp/cqs-device-trust-vectors.h
```

The [acceptance matrix](DEVICE-TRUST-ACCEPTANCE.md) remains the product-level gate
register. Real signing and durable approval reservations now have isolated test
coverage. Do not mark physical-device delivery, durable recovery, CopyQ encryption
coexistence or an automatic installer as passed by these tests.
Exact test counts/results belong to the implementing PR and its current CI run.
