# Device trust and guided setup: stage 1

Status: design baseline, revision 1. This document specifies future behavior; it
does not enable pairing, change the current protocol, or certify a new release.
The current RC still uses [manual setup](DEVICE-SETUP.md). Requirements marked
MUST are constraints on the implementation proposed here, not existing features.

Companion documents: [delivery and installer contract](GUIDED-SETUP-DELIVERY.md)
and [acceptance matrix and implementation gates](DEVICE-TRUST-ACCEPTANCE.md).

## Scope and existing foundation

The product goal is terminal-free installation on Windows 11 x86_64 and Mint
with CopyQ Flatpak, followed by **Create synchronization** or **Join
synchronization**. Nextcloud's desktop client transports local files; Secure
Sync does not need Nextcloud credentials or a new network service.

Today, `src/events.cpp` authenticates v1 events using a shared K-SYNC. Separate
device-local keys protect private data and vaults. `native/key_vault.cpp`,
`native/unified_state.cpp` and `native/history_transition.cpp` provide foundations
for guarded key setup and resumable transitions. They do not implement signed
device membership or public-key pairing. A v1 device ID is not proof of the
individual sender: every holder of K-SYNC can authenticate v1 events.

This work MUST preserve current state and history. New membership, approval and
event formats need explicit version admission. No in-place reinterpretation of
v1 bytes or silent compatibility claim is allowed.

## Trust boundary and guarantees

Assume the transport can read, modify, omit, duplicate, reorder and replay files,
present different views to different devices, and replace paths during access.
Local storage can fail or become unavailable. A previously trusted device may
be lost or compromised. Device labels, paths, timestamps and discovery files
are untrusted input; a public-key signature alone does not establish ownership.

The design MUST authenticate the intended peer before key delivery, validate
membership authorization, retain encrypted local data on refusal, and remember
accepted membership/history witnesses to detect observed rollback and forks.

Two approvals authorize an operation in conforming clients. They do NOT prevent
a compromised reader from leaking plaintext or K-SYNC it already possesses.
Splitting only an approval signing key does not change this boundary. No promise
of remote erasure, global transport consistency, availability against omission,
or forward secrecy for the retained shared-key history is made.

## Identity and membership state

A group has a random group ID, a pinned genesis/root digest, a versioned policy,
and a hash-linked history of membership states. Membership epoch and data-key
generation are separate fields; neither is inferred from file modification time.
Each member has an application-generated random ID, a signing identity and
separate encryption key material. The chosen suite MUST prevent inappropriate
cross-use of keys and provide domain separation.

Real hostnames MUST NOT be published automatically. A random label is the
default; a user may deliberately choose a display alias. Labels are not identity
or authority. Renaming does not create a new member or add an approval vote.

An accepted state commits to the parent digest, group/root, epoch, active member
IDs and keys, policy, data-key generation, bootstrap history, and removed-member
history needed for validation. Public control data may expose pseudonymous
membership, timing and file sizes. Private keys, passwords, decrypted clipboard
data and unwrapped group keys MUST stay outside transport. Local approval intent,
accepted state and signing material MUST be protected against accidental rollback
and ordinary concurrent processes; restoring an old backup requires recovery.

## Authorization policy

There is no permanent owner, coordinator or privileged founding host.
Approval authority belongs to distinct active device identities in the exact
parent membership state, not to accounts, labels or application instances.
Require unique member IDs and signing public keys: reject collisions or enrolling
the same signing key under another ID. A clone of an identity counts once.
Two enrolled identities are not proof of two physical computers; two different
keys on one compromised OS do not constitute independent security boundaries.
The verification UI must explain this when claiming two-device protection.

| Operation | Required authority |
| --- | --- |
| Create a new group | Explicit local Create action; a new independent root and keys. |
| Add the second device | The sole genesis member verifies and signs; this one-time bootstrap is then durably consumed. |
| Add any later device | Two distinct active members of the parent state, neither the applicant. |
| Remove a member | Two distinct active members of the parent state, excluding the removal target. |
| Change trust policy or recovery authority | At least the same two-member authority; never a local settings toggle. |
| Recover when authority is unavailable | Independent offline recovery credential and explicit creation of a new group; see Recovery. |

The bootstrap exception MUST be recorded as consumed in the authenticated
membership history and local durable state. It MUST NOT be re-enabled because
only one device is visible, online or left in a restored snapshot. The initial
second device becomes a full approver when that membership state is accepted.
Its encrypted-data Join and acknowledgement are tracked separately; a client
MUST require local onboarding to finish before offering approval actions.

In a two-device group, both approve the third. In a larger group, any two approve
the next. An offline device does not lose membership. Removing the founder uses
the same policy as removing any other member. Ordinary removal requires at least
three members and leaves at least two. With only two, an unavailable or unwanted
member requires deliberate recovery; there is no hidden one-vote fallback.
No ordinary operation may delete the last usable member or weaken the threshold.

## Pairing and signed intent

1. The applicant selects the local transport and creates a private identity. It
   publishes a bounded, versioned, signed request with fresh randomness. The
   request is discovery input, not proof of trust or authority.
2. Each approver verifies the intended applicant through a reviewed comparison
   or QR protocol. The applicant also authenticates the existing group and peer;
   both endpoints need a trusted root binding. The comparison MUST bind the
   group/root, exact request, both endpoints' keys and fresh protocol transcript.
   A code or fingerprint copied only from the same untrusted folder is insufficient.
3. Each approval covers the same admission intent: version and operation domain,
   group/root, exact parent membership digest and epoch, candidate ID and full
   keys, request ID and nonce, expiry, policy, proposed successor and data-key
   generation. The human-verified bytes and the subsequently signed bytes MUST
   agree. Each approver's transcript binding accompanies its approval.
4. Before signing, persist a local reservation for that exact membership intent.
   After signing, retries reuse it; a crash cannot cause signing a different
   child of the same parent. Duplicated signatures from one identity count once.
5. Verify the required distinct signatures and parent authority before accepting
   the proposed successor or creating a key-delivery package. Any parent change
   makes an unfinished request stale: require a fresh request and verification.
6. Encrypt authorized key material for the verified applicant. Authenticate and
   bind the package to the exact certificate, recipient keys, request, group/root
   and key generation. Correct clients never release a partial admission after
   one of two approvals, or treat a bare encrypted key as membership authority.
7. The receiver verifies the chain/root and certificate, decrypts the package,
   initializes create-only local storage, and performs authenticated history
   Join. It returns an authenticated acknowledgement of the exact operation and
   successful stage. Retrying never creates a different identity or fresh history.

The precise pairing/SAS construction, signature encoding, cryptographic suite,
serialization, expiry behavior under clock skew and key-package library are
implementation gates, not invented in this document. In particular, a short
numeric code is not assumed secure against grinding or unlimited retries.
HPKE is a candidate key-envelope mechanism, not a complete pairing protocol.
Independent verification of each approver is required in the two-approval flow.

The UI distinguishes requested, awaiting verification, approvals 0/2 or 1/2,
authorized, awaiting key delivery, local Join, and receiver-confirmed. A local
file write is not proof of receipt. Rejection/cancellation is terminal locally;
delayed signatures cannot revive a cancelled request. Timely global cancellation
cannot be guaranteed when a peer or transport withholds updates.

## Concurrent operations and transport forks

Two signatures do not provide global consensus. With four members, disjoint
pairs can sign competing children of one parent. With three, one compromised
signer can equivocate. Even durable sign-once intent on honest clients cannot
prevent every fork. Nextcloud is neither a lock nor a trusted membership server.

The chosen baseline is detection and explicit recovery, not an unsupported claim
of global finality. On observing different valid successors of the same accepted
parent, including any retained ancestor even after several later epochs, enter
**membership conflict**, preserve both, and stop membership changes,
key delivery and automatic synchronization. Continue protected local saves and
allow encrypted backup. Do not select by timestamp, filename, delivery order,
lexicographic hash or majority of files. Ordinary resume is forbidden; recovery
creates a new explicitly verified group. A revision seeking global finality must
replace this baseline with a reviewed stronger protocol before promising it.

Before such a conflict is observable, partitioned clients may have accepted
different valid branches and released keys. Detection cannot undo that disclosure.
Remember accepted parents and known siblings locally; missing transport files
must not reset these witnesses. A fully hidden branch cannot be detected until
evidence arrives. Wrong-parent approvals cannot be combined across branches.

Even without a completed conflicting certificate, split partial votes can block
progress: in a two-member group, one signs request X and the other signs Y.
Surface **membership approval blocked**, keep both intents and offer explicit
new-group recovery if no valid successor can be completed. Expiry, cancellation,
restart or a user retry MUST NOT clear signing reservations or authorize signing
a different child of that parent. Do not claim that local serialization prevents
this distributed deadlock. A future abort/unlock protocol needs separate review;
it is not an implicit timeout fallback in this baseline.

## Removal and future-key rotation

Two surviving members approve a specific removal intent. The successor excludes
the target and binds a freshly generated future-data key. Deliver it separately
to each remaining member's authenticated encryption identity, never solely
encrypted with the old group key known to the removed member. The founder is
eligible for removal and has no residual ordinary authority.

Once a client learns a valid removal, it MUST stop old-generation publication
before resuming with the successor. New-version event verification must bind
sender signatures, authorized membership and key generation. Offline old-key
edits remain preserved for explicit reconciliation, not silently accepted as
new-generation writes. A device hidden from the removal cannot be promised
instant revocation; the UI reports last confirmed membership, not global reach.

Members retain previously received plaintext and keys. Joining a group with an
existing archive requires an explicit history-access policy. The guided default
is full existing-history access after authorization, matching clipboard-history
sync expectations; state this before approval. Any future-only option requires
a separate tested key/history design. Re-encryption cannot recall old copies.

## Recovery and loss of authority

Create and verify an encrypted offline recovery package during initial setup.
Its credential is independent of a surviving device's ordinary unlock password,
is not retained as an extra founder privilege, and is never written to the sync
folder. Record only the public recovery binding in the group. Without an
independently available credential, do not offer a misleading recovery bypass.

When two approvers are unavailable, ordinary admission/removal remains blocked.
Explicit recovery uses that credential plus the required encrypted archive/key
material to create a new group ID/root, fresh identities as needed and new keys.
Preserve the old group/archive; do not forge a two-member certificate or reset
bootstrap inside the old group. Old peers must deliberately verify and join the
new group. They do not automatically follow a recovery announcement in Nextcloud.
Recoverable current state, historical generations and unsynced per-device edits
are different assets: the package format must specify its scope and freshness.

Recovery authority is intentionally a separate trust path and must be explained
as such. Test restoration on a fresh machine. A compromised recovery credential
does not permit remote erasure, and recovery does not repair a compromised local
OS. With no usable credential, keys or decryptable backup, lost data is not
recoverable by adding an empty replacement. Design gates cover package renewal,
passphrase protection and invalidation/rotation of recovery authority.

## Storage, versions and implementation boundaries

All new control-file readers MUST enforce bounded size/count/depth, strict schema
and version admission, duplicate-field rejection and canonical signing inputs.
Never execute filenames/labels or use untrusted JSON paths. Use handle-bound,
no-follow access and create-only immutable publication with private durable
journals. Partial writes, conflict copies, resource exhaustion and unavailable
folders must defer/refuse, never seed a replacement group.

Membership operations use a serial local coordinator with durable intent and
idempotent retries, integrated with vault/state epochs and existing editor/save
guards. An installer restart, password prompt or failed package must not race
another key operation. Keep key material out of logs, diagnostics, shell arguments
and the system clipboard. Public discovery uses pseudonyms; any further metadata
encryption needs a protocol design, not a promise that metadata is absent.

Old manual key transfer remains a legacy v1 workflow, not a bypass for admission
to the new group. Downgrade or mixed writers cannot circumvent signed membership.
Migration retains the original v1 transport/state and starts a versioned successor
only after explicit authorization. The complete membership chain, genesis and
policy remain verifiable after data-history compaction or backup restore.

## References and review boundary

- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html): key envelopes, context
  binding and security limitations; it supplies neither peer identity selection
  nor the application's replay, membership or pairing protocol.
- [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html): separation of identity,
  membership and delivery. This design does not claim MLS conformance.
- Current implementation: [event contract](EVENTS.md), [key lifecycle](KEY-LIFECYCLE.md),
  [history transitions](HISTORY-TRANSITIONS.md), [state](STATE.md).

The stage-1 outcome is reviewable requirements and explicit non-goals. It is not
a cryptographic audit. The [gate register](DEVICE-TRUST-ACCEPTANCE.md#implementation-gates)
must be resolved with concrete designs and test evidence before production pairing.
