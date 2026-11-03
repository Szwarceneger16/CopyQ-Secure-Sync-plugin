# Device identities, durable approvals and key delivery

The isolated control-plane tests extend the [membership model](DEVICE-TRUST-MODEL.md)
with real signatures, a local identity vault, durable approvals and signed key
envelopes. Build them with `BUILD_TESTING` and `CQS_TEST_DEVICE_CRYPTO` enabled.
The tests use disposable directories and synthetic keys. Product integration
requires peer verification, transport publication, installation of the received
key, acknowledged Join and recovery. The [protocol design](DEVICE-TRUST-PROTOCOL.md)
and [acceptance gates](DEVICE-TRUST-ACCEPTANCE.md#implementation-gates) define
the product contract.

## Identity and signature boundary

`Identity::generate()` obtains a random device ID, an Ed25519 seed and an
independent X25519 secret through separate cryptographic RNG calls. Signing and
encryption keys are neither converted from each other nor derived from an unlock
password. Long-lived secret material uses guarded libsodium allocation and an
explicit memory lock; allocation/locking failures refuse operation. Copying and
moving identities are disabled, and destruction wipes/frees their storage.

`SodiumVerifier` validates Ed25519 prime-subgroup point encodings, validates the
signature's R encoding, and invokes single-part detached verification over the
exact message. It also validates canonical X25519 public encodings and uses the
library scalar multiplication check to reject low-order inputs. These checks
apply to pinned and proposed members, including journal replay. Message size is
bounded at 64 KiB. The inherited model encodings retain their `model-v1` domains;
this increment does not silently assign a final production wire version.

`Identity::sign()` is a low-level primitive and does not itself authorize an
admission. `TrustJournal::approve()` supplies that policy and durability ordering.
Calling the raw signer directly would bypass the coordinator's protections and
must not become an application pairing path.

`exportPrivate()` returns sensitive plaintext containing a domain/version
marker, device ID, Ed25519 seed and X25519 secret. `IdentityVault` stores this
record in a dedicated local `state::FileStore` with either a protected 32-byte
wrapping key or password protection. The binding commits to externally pinned
group, root and full member keys. Explicit create-only provisioning takes the
record lease. Reopen authenticates the record, validates its shape and re-derives
the public keys before matching the complete local member. Use a separate private
directory outside the synchronization folder.

The vault wipes exported and returned private record buffers it owns. The shared
FileStore codec can allocate transient plaintext buffers during serialization or
failed parsing. Secret memory locking applies to the live `Identity`. The
approval journal stores public membership data and sealed key envelopes.

## Pinned encrypted journal

Setup supplies a trusted `Genesis` and complete local public `Member`. These
values must come from local creation or the independently verified pairing flow,
never be inferred from the cloud data being accepted. The journal binding commits
to the group, genesis root/state and local ID/signing/encryption keys.

The coordinator uses a **dedicated** `state::FileStore` outside the transport.
Its existing whole-record AEAD, strict private-directory checks, exclusive lease
and compare-and-swap commit are reused. The record is schema 2 with exactly one
local item and one `application/x-copyq-secure-sync-trust-journal-lab-v1` field.
No clipboard head, pending import, publication, archive or history witness field
is permitted. In this dedicated record, `keyIdentity` stores the public journal
pin digest; it is not a replacement K-SYNC identity for a normal clipboard record.
Never point this coordinator at an existing clipboard state directory.

`initialize()` performs explicit create-only provisioning. Construction/opening
loads and validates an existing record; missing files, authentication failures,
foreign bindings and corrupt/unsupported contents never trigger initialization.

The bounded journal contains the exact canonical reservation proposals and full
authenticated accepted/conflicting certificates in their original event order.
Each event retains its original policy time. Replay starts from the externally
pinned genesis, validates suite keys and signatures again, and restores local
sign-once reservations before later certificates. Replaying all certificates
before reservations would lose the historical parent against which a vote was
reserved and is deliberately avoided.

| Limit | Value |
| --- | --- |
| Active members | 32 |
| Retained membership states | 256 |
| Journal operations | 512 |
| Individual event payload | 4,096 bytes |
| Complete journal payload | 2 MiB |

Reaching a limit refuses growth; no witness or reservation is silently pruned.
Known certificate retries do not append duplicate evidence. Exact approval retries
retain one reservation while performing another durable commit before signing.

## Approval and observation ordering

One Store lease covers each complete operation, including signature creation:

1. Load/authenticate the dedicated record and check external pins.
2. Replay its ordered log using real signature verification.
3. Match the unlocked identity to the complete pinned local member and check time.
4. Match the supplied confirmation to the full `verificationDigest(proposal, local)`.
5. Reserve that exact proposal against the current parent and local signer.
6. Durably commit the complete replacement record with an incremented generation.
7. Sign the exact `approvalBytes()` and return the approval.

No approval is returned on a commit error. Every exception from the Store commit,
including an ambiguous acknowledgement after a possible successful write, marks
the coordinator uncertain. Further operations on that instance refuse. Reopening
authenticates the actual persisted result; it does not erase an already recorded
vote. If the subsequent cryptographic signing call fails, the durable reservation
still prevents a different vote. Expiry, cancellation, restart and retry provide
no reservation-reset operation.

The confirmation argument must originate from a trusted local UI action after
out-of-band peer comparison. Its existence cannot prove that a person actually
compared screens. Copying a digest or QR file from the same untrusted transport
is not peer verification; implementing and reviewing that UI remains required.

Certificate observation validates the complete quorum before saving any change.
An authenticated historical conflict is saved with both complete branch
certificates, then remains latched on reopen. A duplicate accepted certificate
is idempotent. Once forked, fresh membership and signing operations refuse;
there is no automatic branch winner or quorum downgrade.

## Key delivery at the accepted head

`prepareDelivery()` holds the journal lease through replay, authorization,
encryption and commit. An Add authorizes delivery from an existing member to the
new member. A Remove authorizes delivery between two distinct survivors. Both
operations use the exact current successor and proposal digests. Peers with
different valid quorum subsets for the same proposal can therefore interoperate.
The sender proves possession of the accepted generation key by matching its
commitment. Both sides recompute candidate commitments for retained earlier
generations and reject known raw-key reuse.

One envelope per recipient is staged in the encrypted journal. Version 1 records
remain readable. Version 2 appends a nonempty, recipient-sorted table of at most
32 entries. Each entry is `recipient32 || length-u32BE || envelope`, following a
`count-u32BE`. Entries use the existing 4,096-byte field and 2 MiB journal limits.
Reopen verifies each saved envelope's exact context and sender signature. An
exact retry returns the same ciphertext. A commit error suppresses the result
and requires reopening. Advancing the head or observing a fork clears the old
outbox while retaining the membership evidence.

`receiveDelivery()` verifies local pins, current authorization and the signature
before opening the sealed payload. It compares the inner and outer context and
the key commitment before returning a guarded key. An accepted envelope grants
access to records encrypted with that generation, including its existing
history. A newer accepted head invalidates packages tied to the older head.
Production needs an authorized catch-up or a rule that coordinates head changes
with delivery completion. Publication must recheck the head under a live guard
because prepared bytes can outlive the journal lease. A peer can enforce only
the revocations and forks it has already observed.

## Clock and rollback limits

The encrypted record retains a high-watermark policy time. Fresh signing and
admission refuse a lower caller time. Authenticated late historical conflict
evidence remains actionable even after expiry or a local clock reversal and
does not lower the watermark. The caller still supplies the clock: this is not
a secure time source or a future-date plausibility check.

A live coordinator remembers the record generation and payload digest. It
rejects a lower generation or different payload under the same generation.
FileStore's whole-record compare-and-swap protects ordinary concurrent updates;
the lease remains held through signing. This does **not** prevent an attacker or
backup process from restoring all older valid ciphertext and keys across a
process restart. Production needs an external monotonic anchor or an explicit
recovery policy before claiming that broader rollback guarantee. Copying one
identity to two machines likewise does not create two independent approvers.

## Build and validation

Supply a separately obtained, trusted libsodium 1.0.22-or-newer development
installation. Configuration performs no dependency download or system package
installation. Both headers and the runtime library are checked; an older system
library is refused rather than used as a fallback.

```sh
cmake -S . -B build-control -DCQS_BUILD_NATIVE_PLUGIN=OFF \
  -DCQS_TEST_DEVICE_CRYPTO=ON -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/your/trusted/libsodium-prefix
cmake --build build-control --parallel 2
ctest --test-dir build-control --output-on-failure \
  -R '^(device-trust|device_identity|device_identity_vault|device_trust_journal|device_key_envelope|device_key_delivery)$'
```

The optional identity suite uses RFC 8032 vectors, real approval signatures,
malformed keys, scalar malleability, altered signature bits and strict resource
bounds. The journal suite exercises two-signature admission, exact confirmation,
reservation/observation replay order, stale/expired requests, fork persistence,
clock rollback, wrong pins, malformed records and failures before/after the
commit acknowledgement. Its Linux disk case uses disposable private directories
to test encrypted FileStore creation and reopen. No user keys or profiles are
loaded. The vault, envelope and delivery suites cover authenticated reopen,
recipient and context substitution, key commitment checks and durable ciphertext
retry. Exact results belong to the implementing PR and current test run.

Qualification still requires Windows/NTFS and Flatpak, physical power-loss
behavior, human peer verification and production transport. Enable the optional
build flag to include these suites in CI.

## Dependency qualification

The local validation baseline is upstream libsodium **1.0.22**, tag
[`1.0.22-RELEASE`](https://github.com/jedisct1/libsodium/tree/1.0.22-RELEASE),
commit `77e1ce5d6dee871c49ef211222ba18ef0c486bda`, annotated tag object
`bc5892beb87c388e123baa7c8f4862f30d9206a7`. Required upstream text files were
retrieved and each Git blob hash checked before a local static build. No source
or binary dependency is vendored by this increment. GitHub reported a valid PGP
signature for that tag; independent validation against the publisher's trusted
key has not been established. This evidence does not replace release provenance
verification or the upstream test suite.

The minimum version is intentional. Upstream documents that
`crypto_core_ed25519_is_valid_point()` in versions through 1.0.20 could accept
mixed-order points. The new adapter uses the corrected upstream validation path
and does not add a custom compatibility workaround for the older system library.
Publisher provenance, reproducible/pinned distribution, license/package metadata
and Windows/MSVC/Flatpak qualification remain release gates.

Primary references:

- [Libsodium public-key signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
- [Ed25519 point validation and historical issue](https://doc.libsodium.org/advanced/point-arithmetic)
- [Scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)
- [Guarded allocation and memory locking](https://doc.libsodium.org/memory_management)
- [RFC 8032 test vectors](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1)
- [Upstream release directory](https://download.libsodium.org/libsodium/releases/)
