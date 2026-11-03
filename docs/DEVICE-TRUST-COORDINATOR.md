# Device identities, durable approvals and key delivery

The isolated control-plane tests extend the [membership model](DEVICE-TRUST-MODEL.md)
with real signatures, a local identity vault, durable approvals, signed key
envelopes, durable recipient storage and file transport. Build them with
`BUILD_TESTING` and `CQS_TEST_DEVICE_CRYPTO` enabled.
The tests use disposable directories and synthetic keys. Product integration
requires peer verification, cloud delivery, CopyQ profile activation,
authenticated Join and recovery. The [protocol design](DEVICE-TRUST-PROTOCOL.md)
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
new member. A Remove authorizes delivery between two distinct survivors.
`prepareCatchUp()` is a separate local operation for an earlier member who is
still active at a later Add. It creates a fresh envelope for the current head.
The Add newcomer and Remove survivors use the ordinary delivery scope. All
packages bind the exact current successor and proposal digests. Peers with
different valid quorum subsets for the same proposal can interoperate.
The sender must match the accepted generation commitment. Both sides recompute
candidate commitments for retained earlier generations to detect raw-key reuse.

The sender stages one envelope per recipient. Reopening verifies every staged
envelope against current membership and the sender's pinned identity. A retry
commits the same bytes again before returning them, including when the prior
commit reported an uncertain result. Advancing the head or observing a fork
clears staged envelopes and their receipts while retaining membership evidence.
`publishDelivery()` rechecks the head under a live lease because a prepared
package can outlive the lease that staged it. A peer can enforce the revocations
and forks it observes.

## Recipient installation and receipts

`installDelivery()` authenticates a current envelope and checks its opened key
before committing the exact sealed package into the recipient journal. It signs
the storage receipt only after that commit returns successfully. Retrying after
an uncertain write requires a fresh open and successful durability barrier. A
different valid envelope for the same head may replace the installed package
only through the same checks and commit. The generation commitment binds both
packages to the same key.

`loadInstalledKey()` verifies the saved envelope against the historical accepted
state in which it arrived and checks the current recipient, generation and
commitment before opening it. This preserves the installed key across an Add
with the same generation and commitment. Rotation or a detected fork discards
the installed package. The journal stores the sealed package, and opening it
requires the local identity. Originating genesis and rotation keys require their
own durable preparation path.

`recordReceipt()` verifies the recipient signature against the exact package
already staged for it. The signed receipt commits to the envelope digest, both
endpoints, the membership transition, generation, commitment and scope. The
sender persists that receipt alongside the package until the head advances.
Repeating a valid receipt for the same package is idempotent. A receipt is the
authenticated recipient's assertion of storage. The honest implementation signs
it after persistence. Authenticated CopyQ Join is a separate product milestone.

Version 1 and 2 journal records remain readable. When delivery fields exist,
version 3 writes the usual event log followed by an outbound count (`u32BE`),
then recipient-sorted entries `recipient32 || envelopeField || receiptField`,
then `installedEnvelopeField`. A field is its length (`u32BE`) and exact bytes.
Zero length represents an absent receipt or installed package. Outbound
entries require nonempty envelopes and at most 32 recipients. A version 3
record requires at least one outbound envelope or an installed package. Each
field is bounded to 4,096 bytes and the entire journal to 2 MiB.

## Bounded file transport

Provision a dedicated `control/` child alongside `events/` under the existing
transport root. Control addresses are 64 lowercase hexadecimal characters, the
SHA-256 digest of the exact packet. The transport stores `<address>.cqc` files
and caps each packet at 4,096 bytes. The caller supplies the address for a
targeted read. The native backends open and recheck pinned paths, enforce the
file bounds before allocating and verify the address before returning bytes.
An absent control directory requires explicit provisioning. An address check
establishes byte integrity. Journal verification establishes authorization.

`publishDelivery()` selects its envelope from the verified current outbox.
`publishReceipt()` reopens the installed package against the exact current head
before signing its receipt. Both hold the journal lease through a successful
local commit and the transport publication barrier. This prevents a local
membership update from slipping between authorization and publication. The
recipient calls `installDelivery()` with the retrieved envelope. The sender
calls `recordReceipt()` with the retrieved receipt. Both validate the signed
context against local history after the transport read.

Publication stages the packet privately, then exposes its final name without
replacement. Retrying an existing name requires exact bytes and a fresh native
durability barrier. A durability error can leave the final name visible. Retry
under current authorization using the same packet address. Linux uses an
anonymous staged inode and mount identity checks. Windows uses an explicit
private staging directory on the same fixed NTFS volume. Keep that directory
outside the transport.

The file transport exercises the control exchange in isolated directories.
Address discovery, cloud-client delivery, profile activation and signed event
publication remain product integration work. A file sync service can withhold packets
or membership changes, and control headers and receipts expose public protocol
metadata to observers of the transport.

## Signed clipboard history

The [signed event format](DEVICE-TRUST-PROTOCOL.md#signed-clipboard-event-format)
authenticates the full author ID, accepted membership head, key generation,
revision identity, exact parent packet digests and ciphertext. The signature is
verified before AES-GCM decryption. Packed items remain subject to CopyQ's
semantic import checks when a runtime adapter consumes them.

The journal encodes under its current authorized state and checks the key
commitment and reuse policy. Batch reads verify under one journal lease and
accept only the current generation. An earlier accepted head within that
generation is eligible when the signer was a member at that head and is still
active. The graph checks exact parent packet bytes, parent membership epochs,
unique revision IDs and monotonic author sequences along every ancestor path.
The input order is independent of graph order. Both wire and plaintext budgets
apply to the entire batch.

The isolated encoder and reader form a pre-publication boundary. Runtime use
requires durable sequence and exact wire reservation, immutable publication,
history witnesses across scans, generation-specific storage and explicit legacy
archive migration. An empty or incomplete batch grants no authority to seed a
history. A reader can enforce membership history and events it has observed.

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
  -R '^(device-trust|device_identity|device_identity_vault|device_trust_journal|device_key_envelope|device_key_delivery|device_key_receipt|device_key_lifecycle|device_control_transport|device_signed_event|device_signed_history)$'
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
retry. The receipt and lifecycle suites cover commit-before-sign, receipt
substitution, catch-up, rotation, historical replay and encrypted disk reopen.
Exact results belong to the implementing PR and current test run.

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
