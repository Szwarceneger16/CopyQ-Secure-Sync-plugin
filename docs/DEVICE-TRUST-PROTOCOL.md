# Device trust protocol decisions

Status: engineering baseline for the isolated policy model, not a deployed wire
protocol or audited cryptographic implementation. The [stage-1 requirements](DEVICE-TRUST-DESIGN.md)
remain authoritative. The [acceptance gates](DEVICE-TRUST-ACCEPTANCE.md#implementation-gates)
are not all closed by this change. The optional native signed build can activate
an editable signed tab with separate keys; the default plugin path is unchanged.
These implementations remain opt-in pending distribution qualification.

## Implemented boundary

`src/device_trust.h` and `src/device_trust.cpp` implement bounded, deterministic
membership policy, canonical model encodings, complete-intent digests, independent
approval identities, retained ancestor witnesses and local signing reservations.
`SignatureVerifier` is an explicit injected boundary: the model asks it to verify
each signature against exact bytes and the parent's signing public key.

The optional [control-plane laboratory](DEVICE-TRUST-COORDINATOR.md) adds real
libsodium signatures, an encrypted identity vault, durable approval coordination
and signed key envelopes and storage receipts. It replays pinned history,
commits reservations before signing and durably stages the exact ciphertext
for each authorized recipient.
The optional native integration adds guided local provisioning, authenticated
checkpoint activation and explicit synchronization in a running CopyQ profile.
The acceptance gates still cover installed-platform and production delivery
qualification.

## Cryptographic suite selected for integration

The opt-in adapter uses libsodium single-part **Ed25519 detached signatures**,
independently generated **X25519 encryption keys**, and `crypto_box_seal()` /
`crypto_box_seal_open()` for recipient envelopes. Device signing and encryption
keypairs use separate randomness. Group and request identifiers, public recovery
bindings and nonce fields use a cryptographic RNG. The separate offline recovery
credential and package format described below remain unimplemented.

This is an explicit alternative to the earlier HPKE candidate, not HPKE or MLS
conformance. The sealed-box construction is library-provided; do not reproduce
its internals or create a custom X25519/AEAD composition. Sealed boxes do not
authenticate the sender, so sender authority comes from the separate verified
membership certificate and a signed envelope context. Signing does not conceal
the signed public metadata.

The laboratory requires libsodium **1.0.22 or newer** at configure time and
runtime. Its local validation baseline is the pinned 1.0.22 release documented in
[dependency qualification](DEVICE-TRUST-COORDINATOR.md#dependency-qualification).
The adapter validates Ed25519 point encodings and rejects noncanonical/low-order
X25519 public inputs before they enter the journal. A nonzero 32-byte token passing
only the base model's structural checks remains insufficient. Independent
publisher-key verification and Windows/MSVC/Flatpak qualification still gate
distribution. Neither the base policy model nor the shipping plugin gains a
libsodium runtime dependency by default.

The existing AES-GCM clipboard-event and private-vault backends are unchanged.
Adding control-plane signatures does not upgrade old shared-key events into
individual sender authentication. A versioned signed-event format, mixed-writer
rejection and explicit archive migration remain prerequisites for production.

## Exact model bytes

Names ending in `model-v1` deliberately prevent accidental use as a final release
protocol. Model version is the integer 1. Tokens, keys and digests are exactly
32 bytes; signatures are exactly 64 bytes. Unsigned integers use big-endian
fixed widths. Domains below include one final zero byte; there is no implicit
text encoding, JSON normalization, optional field or algorithm negotiation.

`Member96` is `id32 || signingKey32 || encryptionKey32`. An intent contains:

| Order | Field / representation |
| --- | --- |
| 1 | `CopyQ-Secure-Sync-membership-intent-model-v1` plus NUL |
| 2 | `version` as u32 |
| 3 | `group32 || root32 || parent32` |
| 4 | `parentEpoch` as u64, then target `keyGeneration` as u64 |
| 5 | target `keyCommitment` as 32 bytes |
| 6 | operation u8: Add = 1, Remove = 2 |
| 7 | subject `Member96` |
| 8 | `request32 || nonce32` |
| 9 | `created` and `expires`, each u64 |

`encodeProposal()` produces those exact bytes, denoted `P`. A model certificate
is `certificate-domain || P || approvalCount-u32 || approvals`; its domain is
`CopyQ-Secure-Sync-membership-certificate-model-v1` plus NUL. Each approval is
`signer32 || signature64`, ordered by signer ID. Decoders reject unknown version
or operation, malformed intrinsic values, duplicate approvals, noncanonical order,
truncation, trailing bytes and bounds violations before unbounded allocation.

For parent member `A`, `verificationDigest(P,A)` is SHA-256 of:

```text
"CopyQ-Secure-Sync-membership-verification-model-v1" || NUL || P || Member96(A)
```

The exact message passed to `SignatureVerifier` is `approvalBytes(P,A)`:

```text
"CopyQ-Secure-Sync-membership-approval-model-v1" || NUL || P || Member96(A) || verificationDigest(P,A)
```

An implementation must not substitute `SHA256(P)` or a library's multipart
Ed25519ph mode for that single-part message. Each vote binds its approver and the
same proposed operation; votes on another parent or different applicant cannot
be combined. The successor state also commits to the intent, so changing a
request does not produce the same operation merely because member lists match.

Genesis, state and proposal digests use the model's separate domains. The source
and independent fixtures define their exact encodings. Production formats need
their own reviewed version assignment and complete frozen cross-platform vectors;
renaming these domains in a release without updating vectors is not migration.

## Peer verification without a custom short code

Use the **entire 256-bit verification digest**, rendered as 64 hex digits grouped
for comparison, or a QR representation of the same reviewed public context.
Do not compare only a suffix, truncate to six digits or claim a short-code security
level without a separately reviewed authenticated pairing construction.

For each required approver, both the applicant and that approver compute the
digest locally using their own intended keys, the exact proposed request and the
existing group's pinned root. Compare on the actual trusted device screens or
over an independent authenticated channel. The applicant verifies each approver
and root, not only the other way around. A QR file obtained through the same
untrusted Nextcloud folder, a self-signature, or a familiar label is insufficient.

Fresh request and nonce fields are part of `P`; the verified request must be the
one later reserved and signed. The selected approver's full member keys are also
bound. A changed parent, recipient key, request, lifetime or local intended group
invalidates verification and requires a new comparison. Never build the displayed
digest exclusively from attacker-supplied keys while ignoring the local identity.

Record the local confirmation for this exact digest and then reserve the signing
intent. `TrustJournal::approve()` enforces this order in the optional laboratory:
only after a durable Store commit may the signer receive the exact approval bytes.
Its confirmed-digest parameter is a trusted local caller boundary. The optional
terminal setup adapter displays the full comparison and requires local input
from each peer's trusted screen. Transport data supplies no confirmation.
Two cloned signing identities count once. Separate keys enrolled on one
physical host do not prove independent computers or protect against that OS's
compromise; explain this boundary when presenting two-device protection.

## Membership and time behavior

The model admits at most 32 active members and retains at most 256 states; limits
cause refusal, never silent pruning of trust witnesses. Signing keys and IDs must
be unique, including retired identities, and the applicant cannot vote. The sole
genesis member may add the second device once. Thereafter two distinct current
identities approve additions. Removal needs two survivors, excludes the target,
and increases future-key generation with a new nonzero key commitment. Additions
retain the parent's generation and commitment. There is no permanent founder privilege.

Proposal validity is `created <= now < expires`, with a positive lifetime of at
most 86,400 seconds. The model receives `now` from its caller; it is not a trusted
clock service. The optional journal persists a monotonic watermark and refuses
backwards time for fresh signatures or admissions while allowing authenticated
historical fork evidence. Production still needs a qualified clock source and a
policy for implausible future dates or uncertain restored time. Correcting the
clock does not erase a signing reservation.

Already accepted exact intents remain idempotent after their deadline. A delayed
cryptographically valid conflicting certificate is still fork evidence, even
after expiry: a deadline is not proof that signatures or a remote acceptance
were withdrawn. Retain earlier accepted ancestors to detect deep conflicts.

Fixed two-of-N approval is not global consensus. Disjoint pairs, or an equivocating
member, can certify competing branches before either side observes the other.
On observing a valid conflict, halt membership, key delivery and automatic sync;
continue protected local saves. Honest split partial votes can also block a
parent without completing a certificate. Keep reservations and show the blocked
state; do not unlock them on timeout, cancel, restart or retry. Deliberate new-group
recovery is the baseline escape path, not automatic selection of a winner.

## Key delivery and acknowledgement contract

The 32-byte data key commitment uses SHA-256 of
`CopyQ-Secure-Sync-data-key-commitment-control-v1` including NUL, followed by
`group32 || keyGeneration-u64BE || key32`. The group ID precedes the genesis root
and initial key commitment in setup. `SyncKey` holds the key and uses guarded
memory for commitment calculation and sealed payloads. The journal compares the
candidate key with the commitments for prior generations using their original
generation numbers. This detects reuse even when the current commitment differs.

The isolated envelope codec has a fixed 832-byte encoding. Its public header is
`CopyQ-Secure-Sync-key-envelope-lab-v1` including NUL, followed by the context.
The context is 301 bytes in this order.

| Field | Encoding |
| --- | --- |
| Version | u32BE, value 1 |
| Group and pinned root | `group32 || root32` |
| Accepted successor and proposal digest | `successor32 || proposal32` |
| Recipient identity | `Member96` |
| Sender | member ID, 32 bytes |
| Key generation | u64BE |
| Key commitment | 32 bytes |
| Scope | u8, 1 for ordinary delivery or 2 for catch-up after a later Add |

The sealed payload is `CopyQ-Secure-Sync-key-envelope-plaintext-lab-v1` including
NUL, the identical context and `key32`. Its sealed-box encoding adds 48 bytes to
the 381-byte plaintext. The 64-byte detached signature covers the exact public
header and sealed bytes. The receiver checks its pinned current head, sender,
recipient, signature and ephemeral X25519 key before opening. It compares the
inner context and recomputes the commitment before returning the guarded key.
Independent fixtures exercise the byte layout and detached signature.

The [coordinator](DEVICE-TRUST-COORDINATOR.md#key-delivery-at-the-accepted-head)
stages one exact ciphertext per recipient and discards its outbox on a head
change or fork. Both scopes deliver the current generation key, with access to
records encrypted under it. Membership is authorized by the accepted intent,
so different valid certificate signature sets can yield the same envelope context.
Scope 2 permits an explicit catch-up at a later Add for a recipient admitted
before that Add. The new member and Remove survivors use scope 1.

A storage receipt is 442 bytes. Its signed prefix is the domain
`CopyQ-Secure-Sync-key-storage-receipt-lab-v1` including NUL, version `u32BE` value
1, `group32 || root32 || successor32 || proposal32 || sender32 || Member96`
for the recipient, `generation-u64BE || commitment32 || envelopeDigest32 || scope-u8`.
The digest is SHA-256 of the exact full envelope. The final 64 bytes are the
recipient's detached Ed25519 signature over the 378-byte prefix. The recipient
signs after its sealed package is durably stored. The sender verifies the receipt
against the staged package and current head before saving it. Historical
validated packages can supply the installed key only while the recipient,
generation and commitment remain current and the journal is free of forks.

The isolated [file transport](DEVICE-TRUST-COORDINATOR.md#bounded-file-transport)
publishes the envelope and storage receipt under the current journal lease.
Each packet has a targeted SHA-256 address and immutable file name. Recipients
still validate the signed context against their accepted history. Product
integration must durably prepare the rotation secret before soliciting approvals
and use the installed key only after signed clipboard events and profile activation
are qualified. Publish a separate completion acknowledgement after authenticated
CopyQ Join has succeeded.
A removed member keeps any earlier key it obtained. A later generation uses a
fresh key and survivor-specific delivery.

## Signed clipboard event format

The laboratory packet starts with the fixed domain
`CopyQ-Secure-Sync-signed-event-lab-v1` including NUL, followed by the
version as `u32BE`. New packets use version `2`. Its header contains, in order,
`group32 || root32 || head32 || commitment32 || author32`, generation and
sequence as `u64BE`, the 45-byte ASCII revision ID and parent count as `u8`.
Zero to two parents follow in sorted revision-ID order. Each consists of its
45-byte revision ID and SHA-256 of the full parent packet. The file identity
must independently match the signed revision ID. The device component starts
with `d` followed by the first 31 lowercase base32 characters of the full
author ID's SHA-256 digest. The journal refuses collisions among active devices.

The remaining header is a random 12-byte nonce and the ciphertext-with-tag
length as `u32BE`. AES-256-GCM authenticates the exact header as AAD. Version 2
derives a separate AES key for each full author ID using HMAC-SHA256 keyed by
the generation secret. Its input is the domain
`CopyQ-Secure-Sync-signed-event-aes-gcm-author-key-lab-v2` including NUL, then
`group32 || root32 || generation-u64BE || author32`. The encrypted payload has
domain `CopyQ-Secure-Sync-signed-event-payload-lab-v1` including NUL, item count
as `u32BE` and canonical base64 packed items with `u32BE` byte lengths.

The journal durably charges an attempt before invoking the encoder, including
attempts that fail or are discarded. Each author may reserve up to 65,536
attempts per generation. An Add preserves the count, while a key rotation
starts a fresh count. Retrying publication reuses the stored ciphertext. With
one intact journal per identity and uniform independent 96-bit nonces, the
probability of a nonce collision under one derived key is below 2⁻⁶⁵ by the
union bound. Separating keys by author keeps the per-key bound independent of
how many authors a membership fork admits before discovery. The limit is
below the random-IV invocation limit in [NIST SP 800-38D, section 8.3](https://csrc.nist.gov/pubs/sp/800/38/d/final).
Cloning an identity, restoring older journal state, or bypassing the journal
can invalidate the attempt count.

Version 1 remains readable for local laboratory data. Its shared AES key
uses the earlier domain `CopyQ-Secure-Sync-signed-event-aes-gcm-key-lab-v1`
including NUL and the input fields `group32 || root32 || generation-u64BE`.
The publication and shared-folder history paths require version 2.

The final 64 bytes are the author's Ed25519 signature over the domain
`CopyQ-Secure-Sync-signed-event-signature-lab-v1` including NUL and SHA-256 of
the exact header and ciphertext-with-tag. The reader authenticates that
signature before opening the payload. Current-generation history rejects
packets from old generations and forks, while allowing verified ancestors from
earlier accepted heads in the same generation. Signed history uses a separate
format and derived key from the legacy archive. Product migration must preserve
that archive and establish an explicit successor history.

## Independent recovery credential

This format is not implemented. Guided setup currently stores a random public
recovery binding in the genesis, without exporting an independent recovery secret
or usable offline package. Its local setup password only unlocks that device's
encrypted profile; losing that profile and its password is not addressed by the
proposed format below.

The proposed first recovery format uses a generated 256-bit random recovery
secret, separate from ordinary local passwords and device signing keys. Its
public group binding is a domain-separated digest; the secret is exported only
through an explicit offline backup flow, never retained as founder authority,
automatically copied to the system clipboard, or stored beside the cloud archive.

Encrypt the recovery package with a library-provided AEAD and authenticate its
complete versioned metadata: original group/root, membership checkpoint, included
key generations, snapshot/archive digests and creation time. XChaCha20-Poly1305
with a fresh random 24-byte nonce is the selected libsodium candidate for this
new package, independent of existing vault formats. Exact header/domain, key
separation, renewal, rotation and restore semantics require adapter vectors and
failure tests before this format can be used. An optional passphrase wrapper
would require separately specified Argon2id parameters and resource bounds;
an ordinary unlock password is not a substitute recovery credential.

A recovery import must prove the package's declared coverage and credential
binding, then create a new independently verified group with new keys. It never
fabricates two approvals or resets bootstrap in the old group. Preserve old data,
identify omitted historical generations and unsent local edits, and require old
peers to verify/rejoin explicitly. Missing keys are not recoverable by an empty
replacement. A fresh-machine restore drill is a release requirement.

## User control and remaining work

Before effectful actions show the affected group/device/tab, full-history access,
approval count and consequences of removal or recovery. Require user confirmation
for verification, granting access, changing launch/permissions, migration and
destructive actions. Automatic discovery, validation and safe retry need no repeated
prompt; they must not silently weaken the trust policy or CopyQ encryption.

G1-G4 have concrete choices and isolated implementations for membership,
identity storage, signing, approvals, key envelopes and locally verified
enrollment. Activation preflight verifies the installed sealed package and the
current signed history before producing readiness metadata. The
[experimental native Signed Join](DEVICE-TRUST-COORDINATOR.md#experimental-native-signed-join)
can open a reviewed checkpoint as an editable local `signed_sync` tab after
separate confirmation. The explicit synchronization action can publish local
edits or pull a verified successor while the tab is unloaded. A separate
confirmation authorizes background synchronization for the running CopyQ
session. Conflict resolution requires a decision over one or two exact signed
tips and preserves the prior encrypted local copy when adopting a remote
selection. An authorized device can retire its matching pending publication
locally after key rotation. The old checkpoint remains bound to its generation.
The earlier sealed-key storage receipt acknowledges only the sealed key write.

Guided native provisioning now creates a private encrypted setup manifest with
independent device, group and wrapping keys. Applicant setup requires the full
genesis fingerprint from a separately trusted device. Founder setup creates one
durable empty signed root and retains its initial group key locally in the
encrypted manifest. Founder activation uses that independently pinned key only
while current membership and key commitment authorize it; this creates no extra
approval vote or permanent founder privilege. Advanced manually provisioned
vault/journal/credential paths remain supported.

An authorized surviving device with the accepted newer key installed may review
and activate a separate encrypted successor checkpoint. A single authenticated
new-generation tip is adopted, or the explicitly designated first device may
confirm seeding an empty provisioned scope from its current local copy. The
coordinator rechecks the exact old cursor, local content, new target and current
authority, retains the old checkpoint and an encrypted local backup, and supports
exact retry through durable seed and successor receipts. This is local adoption;
events do not assert ancestry across key generations. Background synchronization
remains a separate in-memory opt-in for each CopyQ session.

Product work still includes cloud discovery, acknowledged Join, offline recovery
package export/import, native legacy archive migration and platform qualification.
Hosted signed-suite and real CopyQ two-device results, Windows/MSVC/NTFS and
Flatpak package qualification, production cloud delivery and a fresh-machine
recovery drill remain release gates. Full disk/key rollback across
restarts requires an external monotonic anchor or explicit recovery policy.
G5's product migration and G6-G7's installer/platform qualification still gate
distribution. Advanced settings remain ordinary UI.

## Primary references

- [Libsodium signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures):
  detached verification and the distinction between Ed25519 and multipart Ed25519ph.
- [Libsodium sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes):
  recipient encryption without sender identity; no homemade implementation.
- [Distinct signing and encryption keys](https://doc.libsodium.org/advanced/ed25519-curve25519):
  upstream guidance supporting separate key roles.
- [XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
  and [password key derivation](https://doc.libsodium.org/password_hashing/default_phf):
  candidate recovery primitives, not qualification of our package format.
