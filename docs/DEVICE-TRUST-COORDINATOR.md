# Device identities, durable approvals and key delivery

The isolated control-plane tests extend the [membership model](DEVICE-TRUST-MODEL.md)
with real signatures, a local identity vault, durable approvals, signed key
envelopes, durable recipient storage, file transport, signed clipboard event
publication, read-only legacy archive migration, and authenticated Join with
activation preflight. Build them with
`BUILD_TESTING` and `CQS_TEST_DEVICE_CRYPTO` enabled.
The tests use disposable directories and synthetic keys. The separate
[native experiment](#experimental-native-signed-join) can open a verified Join
checkpoint in an editable CopyQ tab and
[synchronize it on demand](#manual-signed-tab-synchronization) or
[during an explicitly enabled CopyQ session](#signed-background-synchronization)
while it is unloaded. It includes guided local provisioning, founder activation,
explicit signed conflict decisions, local retirement of pending publications and
reviewed activation of an accepted newer key generation. Cloud discovery and
offline recovery packages remain unimplemented; installed-platform qualification
is still required.
The [protocol design](DEVICE-TRUST-PROTOCOL.md)
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
Ordinary clipboard transaction fields are prohibited. The journal keeps its own
publication and witness state inside the dedicated MIME payload. In this record,
`keyIdentity` stores the public journal pin digest.
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
| Individual control entry payload | 4,096 bytes |
| Control section | 2 MiB |
| Reserved clipboard event packet | 2 MiB |
| Encryption attempts | 65,536 per author and key generation |
| Current-generation clipboard witnesses | 1,000, 77 bytes each |

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
authenticated recipient's assertion of storage. The implementation signs it
after persistence. A live CopyQ Join acknowledgement requires the profile
integration to apply the accepted snapshot.

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
Address discovery and cloud-client delivery remain product integration work.
A file sync service can withhold packets or membership changes.
Control headers and receipts expose public protocol metadata to observers of
the transport.

## Signed clipboard history

The [signed event format](DEVICE-TRUST-PROTOCOL.md#signed-clipboard-event-format)
authenticates the full author ID, accepted membership head, key generation,
revision identity, exact parent packet digests and ciphertext. The signature is
verified before AES-GCM decryption. Packed items remain subject to CopyQ's
semantic import checks when a runtime adapter consumes them.

Batch reads verify under one journal lease and accept only the current
generation. An earlier accepted head within that generation is eligible when
the signer was a member at that head and is still active. The graph checks
exact parent packet bytes, parent membership epochs, unique revision IDs and
monotonic author sequences along every ancestor path. Both wire and plaintext
budgets apply to the entire batch. The caller-supplied laboratory validator
`readSignedHistory()` can still read version 1. Shared publication and scans
require version 2 with its separate per-author AES-GCM keys. A staged version
1 packet can be resumed locally or discarded. Shared publication requires a
fresh version 2 reservation.

### Durable event reservation

`prepareClipboardEvent()` checks the pinned local author, current membership,
key commitment and reuse policy. Under one journal lease it commits the next
author sequence and increments the generation's attempt counter with an empty
reservation. It then seals the event and commits the exact signed ciphertext
before returning the sequence and packet. Failed or interrupted attempts still
count if the first commit persisted. Resume and publication reuse ciphertext.
An occupied reservation blocks new preparation. The journal retains ciphertext
and ciphertext digests.

Existing payload versions 1–5 remain readable. Version 4 added the sequence as
`u64BE`, a one-byte reservation flag, and a `u32BE` packet length followed by
the exact packet. A clear flag requires zero length. A set flag with zero length
marks an allocated sequence without a recoverable packet. Version 5 keeps that
section and appends the key generation as `u64BE`, the attempt count as
`u32BE`, a one-byte publication attempt flag, and a `u32BE` witness count.
Each witness is a 45-byte revision ID and its 32-byte packet digest, ordered
lexicographically by ID. Replay authenticates a staged packet against the
pinned author, reserved revision and its accepted membership head without
decrypting the clipboard payload. Use default FileStore limits or provision
capacity for the full journal and record framing so the packet and witnesses
cannot consume space needed by membership changes.

An unconfirmed commit poisons the live coordinator. After reopening,
`inspect()` reports the allocated sequence and whether a pending packet is
ready. `resumeClipboardEvent()` takes the matching sequence and recommits
the stored bytes before returning them. A reservation interrupted before the
packet was stored cannot be resumed or re-encrypted. A sealing error after
the first commit leaves the same empty reservation. Use
`discardClipboardEvent()` with the matching sequence to retire a reservation
before a publication attempt. The sequence and any counted attempt remain
allocated. Tagged replica reservations require the corresponding authenticated
checkpoint intent and are handled by the signed tab workflow below.

A same-generation Add permits resume for an author still active at the
current head and preserves the attempt counter and witnesses. An authenticated
rotation resets the counter and witness set for the new generation, keeps the
allocated sequence, and preserves the pending packet as stale. An observed
membership fork blocks both resume and publication.

### Scoped publication and durable scans

Setup explicitly provisions one `signed-<digest>` directory per group,
genesis root and key generation. The name commits to those three values in
`signedEventFolderName()`. Packets are flat
`<device>-<12 decimal digits>.cqe` files. Legacy and earlier-generation
packets have separate directories. The native backends pin and recheck the
directory and files, enforce scan budgets and publish without replacement.
Retry checks the exact bytes and repeats the native durability barrier.

`publishClipboardEvent()` holds the journal lease through validation and all
publication steps. It checks current authority, verifies the scoped history and
candidate, and durably records the visible witnesses and the publication attempt
before the native create-only write. After native confirmation it records the
candidate's witness and clears the reservation. An ambiguous native write keeps
the exact packet for retry and blocks discard in the current generation. An
ambiguous final journal commit can be retried using the same sequence after
reopening. When the staged packet is the only missing witness, an explicit
retry of that same attempted ID may restore it if its staged digest matches.
An ordinary scan still refuses that omission.

Append requires authenticated parents. The first parentless packet in a scope
requires an explicit `Seed` operation against an empty verified scope. An empty
or incomplete scan grants no Seed authority. Different clients can race to
publish the first packet, and the service can withhold an unseen root. A scan
refuses multiple roots when they become visible together. Append can reference
older authenticated parents and create another tip. The coordinator leaves
those branches for explicit resolution.

`scanClipboardEvents()` verifies the whole current-generation graph before
returning a snapshot. It refuses missing or changed witnessed IDs and unknown
local-author packets, with an exception for the exact pending packet after an
attempt. A successful nonempty scan commits the exact wire digests before
returning decoded items. The evidence survives restart and detects omissions
and substitutions that contradict earlier verified scans. A service can still
withhold events or membership changes that the client has never seen.

### Explicit legacy archive migration

`previewLegacyMigration()` computes a confirmation for a verified legacy
archive and a pinned successor. The source Store lease stays held while
reading the authenticated private record and scanning the legacy transport.
The source must have a schema 6 private record with the expected binding and
legacy key identity, one accepted tip and a complete witness map. The scan
must match every retained witness and the accepted head, with the head as its
sole tip. The source must have no pending import, publication or resolution.
The decoded MIME snapshot of the accepted tip must equal both the saved head
snapshot and the local checkpoint. The source is read-only throughout.

The confirmation uses a domain-separated HMAC key derived from the legacy
key. It binds the canonical logical source record and every authenticated
legacy event fingerprint, ordered by ID, to the successor group, genesis root,
key generation, key commitment and founder identity. The digest stays local
and requires explicit authorization from the trusted caller. It grants no
membership or Join authority. The successor starts with an unused founder
journal at epoch zero in generation zero, a separate synchronization key and
an empty, provisioned signed scope. A preexisting membership approval
reservation prevents migration from starting. Before reserving the first
sequence, the migration checks the Seed payload against the 2 MiB signed
packet limit.

`migrateLegacyArchive()` revalidates the source and confirmation while holding
both the source and successor leases. It durably binds the migration intent
to a reserved sequence, seals the accepted tip as one parentless v2 packet,
and commits the exact ciphertext. It then records the publication attempt
before the immutable write. Finalization retains the packet witness and marks
the migration complete in the same journal commit. The original encrypted
archive and private state stay in place. The signed successor starts with a
snapshot of the verified tip. Its remote readers authenticate that new packet
under the successor membership rules.

Journal payload version 6 appends a 32-byte confirmation MAC, the migration
sequence as `u64BE` and a one-byte completion flag to the version 5 payload.
`inspect()` reports the sequence and completion status. A retry checks the
same source proof again. If the reservation commit persisted without a packet,
the retry burns a fresh sequence and encryption attempt. Once the packet is
durably staged, the retry uses its exact bytes. An ambiguous final commit can
be reconciled against the retained witness. While migration is pending,
ordinary preparation, resume, scan, publication and discard cannot bypass
the intent.

An incomplete migration requires the founder-only genesis state at every
attempt. Local membership approval and outbound key delivery remain blocked
until finalization. The journal can still observe valid external membership
evidence, and an Add, rotation or detected fork blocks the pending migration.
After finalization, ordinary enrollment can proceed. The source lease
serializes local access to the private record. Legacy peers can still change
files they control, and subsequent source changes can block a retry. This archive
migration is a separate control-plane operation; the guided native setup creates
an empty signed group and does not import an existing legacy tab. Native archive
migration and cloud-client qualification remain distribution work.

## Authenticated Join and activation preflight

The applicant journal uses independently trusted genesis pins and the
applicant's full local vault identity. `beginJoin()` checks that the identity
is eligible and persists a random 32-byte request before returning it. A
reopened journal repeats the durability barrier before returning the same
pending request. `proposeJoin()` binds that request to a fresh nonce and the
approver's current parent. The applicant's previously accepted certificate
chain supplies its view of the parent. Fresh admission uses a trusted clock and a live
proposal deadline. Historical import with backdated acceptance is outside
this flow.

The optional terminal adapter uses trusted local input and output streams.
It shows the group, genesis root, applicant, expiry and access consequences.
`showJoinApplicantReview()` displays the intended approvers' comparison
values on the applicant's screen before votes are signed.
Each participant derives the full 256-bit comparison digest locally for the
exact Add proposal and selected approver. The applicant enters the full
comparison from each actual certificate signer after checking it against
that signer's trusted screen or independent authenticated channel. The
approver uses the same process before signing. Both accept 64 hex digits
with optional fixed grouping. The adapter reads the clock again after the
prompts. A cancelled or mismatched comparison submits no approval or Join.

`acceptJoin()` rechecks the local request, current parent, exact signer set
and quorum, full comparisons and certificate signatures. The accepted Add
and its verified enrollment marker commit together under one journal lease.
The journal can confirm the same accepted certificate after reopening
without another Add. Ordinary certificate observation can retain valid fork
evidence. An applicant with a pending request must use the verified path to
accept its own Add. Low-level Add observations provide no verified Join
marker for activation. The marker records the admission and current membership
still governs access.

Version 7 appends the 32-byte request and 32-byte accepted intent digest to
the version 5 payload. An all-zero intent represents a request still
awaiting admission. Version 6 remains the separate founder migration format.
Replay checks the admission marker against the accepted Add in the log.

Journal version 10 permits optional migration and replica publication evidence
without fabricating a Join enrollment for the founder. Version 11 adds a scoped
generation-Seed marker with pending, published or retired phase. Retirement
retains a digest commitment to the old scope, head, generation, sequence and exact
staged wire digest, and records when the publication outcome may be ambiguous.
A later Seed retains that retirement lineage for interrupted retries.

`preflightJoinActivation()` requires verified admission for an applicant and
reopens the sealed key package from the private journal for the current member
and key generation. The independently pinned founder may instead supply the
guarded key retained by its local setup. This key must match the accepted
generation commitment, and the founder must still be an active member of an
unforked membership state. This is no additional admission vote or exemption
from membership policy. The operation authenticates the signed generation scope and its retained
witnesses, requires exactly one tip, and validates that tip's packed CopyQ
MIME data. The journal commits the observed packet digests before returning
the profile binding, group, root, membership head, member ID, generation and
exact tip ID and digest. The profile binding is a caller-selected label. The
preflight does not open the native profile or inspect its local tab. The
terminal adapter is separate from CopyQ's settings UI. The native experiment
below can mount the reviewed checkpoint locally. The key storage receipt
still acknowledges only storage of the sealed key package.

## Experimental native Signed Join

Build the native module with `CQS_BUILD_NATIVE_PLUGIN=ON`, `BUILD_TESTING=ON`,
`CQS_TEST_DEVICE_CRYPTO=ON` and `CQS_BUILD_SIGNED_JOIN=ON`. Use the Qt SDK and
pinned CopyQ source checkout required by the native build. Link a trusted
libsodium 1.0.22-or-newer development installation using its shared library
or a static library built with position-independent code where the module
linker requires it. The experimental option defaults to off.

Use a disposable CopyQ 17 profile. Enable **Encrypt Tabs**, put **Secure Sync**
first in CopyQ's plugin priority list (including disabled entries), and enable
only plugins supported by the experiment: Secure Sync and any of Text, Image,
Notes, FakeVim, Pinned Items and Tags (`securesync`, `itemtext`, `itemimage`,
`itemnotes`, `itemfakevim`, `itempinned`, `itemtags`). The guard checks the actual
CopyQ plugin inventory and priority. Other enabled plugins can affect how CopyQ
stores, renders or handles tab items.

Open **Preferences → Devices and recovery → Set up signed synchronization…**.
Choose one of these actions:

1. **Create a new group** selects an empty synchronization folder and a private
   local parent outside it. Setup creates a dedicated private profile, generates
   an independent device identity, group key and separate random vault, journal
   and checkpoint wrapping credentials, and publishes one empty signed Seed.
   It then opens the existing verified checkpoint and activation workflow.
2. **Join an existing group** selects the delivered signed transport and a
   private parent. Obtain the public invitation and full group fingerprint from
   a trusted device. Compare the complete fingerprint on an independent trusted
   screen before entering it. The invitation pins the genesis; it grants no
   membership or key access. Continue with the peer-verified Join steps below.
3. **Open an existing signed profile** selects the private profile created
   earlier and unlocks it with its setup password. Use this action after an
   interruption, for later Join actions or for synchronization.

Keep the private profile and its password. Setup requires at least 12 UTF-8
password bytes and stores the generated credentials in a password-protected
encrypted manifest. It writes no raw credential files to the transport. Public
invitations contain the 192-byte genesis, encoded as lowercase hex after
`cqs-signed-group-v1/`. The full fingerprint hashes a separate domain and all
genesis fields. A random public recovery binding in this format is not an offline
recovery credential. Recovery-package export and restore are not implemented.

The manifest records a provisioning phase before initializing the vault and
journal. An interrupted operation reuses those exact saved identities and
credentials. Founder publication retries the exact staged empty Seed; burned
reservations remain gaps. Only the provisional phase may create the initial
Seed. Opening a ready profile never treats missing history as permission to
reseed. Private directories are created with protected local permissions and
validated pinned paths. Windows requires private storage and staging on the
same fixed NTFS volume as transport. Initial provisioning holds a setup session
lease, then releases it; live secrets remain guarded in memory. Journal and
checkpoint operations retain their own exclusive leases.

**Advanced signed setup…** opens a previously provisioned identity vault and
trust journal. It remains available for controlled manual provisioning. Supply
these pins from trusted local setup, encoded as contiguous hex in field order.

| Field | Bytes in order | Hex digits |
| --- | --- | --- |
| Genesis pins | Group ID, founder device ID, founder Ed25519 public key, founder X25519 public key, public recovery binding, initial key commitment | 384 |
| Local identity pins | Local device ID, local Ed25519 public key, local X25519 public key | 192 |

Select existing, separate private directories for the identity vault, trust
journal and signed checkpoint. Keep the private directories and key files
outside the synchronization root. Supply independent raw 32-byte credential
files for the vault, journal and checkpoint. A publisher can optionally
supply a separately provisioned group key file when its journal has no
installed key. Windows publication uses a separate private staging
directory on the same NTFS volume as the transport. The shared root needs
its `events/` directory for the transport layout, a provisioned `control/`
directory and the current signed generation directory. Checkpoint creation
requires an available signed history.

1. The applicant creates or reopens a request. An existing device prepares
   an Add proposal for that request. Exchange these public messages.
2. The applicant previews the proposal and intended approvers. Each approver
   checks the full comparison value on an independent trusted screen or
   authenticated channel before signing. The applicant assembles the public
   approvals and verifies the full value for each actual signer.
3. Existing devices verify the resulting membership certificate. A current
   member publishes a sealed key for the intended recipient, who installs
   it using the immutable packet address. The storage receipt acknowledges
   the sealed key write.
4. The applicant selects **Review and write signed checkpoint**, reviews the
   verified signed tip and confirms the encrypted checkpoint. The journal
   rechecks the accepted membership, installed key, history and exact reviewed
   tip under its trust lease.
   The destination FileStore uses an exclusive session lease and a record
   lease to create the encrypted checkpoint and verify readback. An
   interrupted write can be retried with the same profile binding, signed
   provenance and snapshot. A conflicting existing destination is refused.
5. After the durable write is verified, separately confirm **Activate signed
   tab**. Confirming repeats the signed-history and checkpoint checks against
   the reviewed tip. If you decline, the encrypted checkpoint is retained
   without enabling the tab. First activation requires that the name
   `signed_sync` and its mnemonic aliases are unused and that the CopyQ `.dat`
   cache for that tab is absent. After activation, create a tab named exactly
   `signed_sync` and open it. On later starts, reopen the same tab with the
   private checkpoint available. Guided profiles prompt for their local setup
   password; advanced profiles require the private checkpoint credential file.

### Local tab storage boundary

The checkpoint holds the signed provenance and the verified MIME snapshot as an
immutable baseline. It also stores the editable local copy. Opening the tab
authenticates this private encrypted record and acquires an exclusive session
lease for the lifetime of the saver. Updates to the working copy are committed
and checked by reading the encrypted record back. CopyQ's tab file contains a
routing marker with a binding digest and checkpoint record generation. Opening
requires the same binding and a checkpoint at least as recent as that marker.
A checkpoint may be ahead of the marker after synchronization while the tab
is unloaded or after an interrupted tab file update. The marker contains no
clipboard items or credential bytes. Settings remember the checkpoint and
reviewed binding and provenance. Guided configurations identify the encrypted
setup profile and prompt for its password on unlock; settings contain no setup
password or raw wrapping credential. Advanced configurations retain a private
credential-file path. Keep every private profile and raw credential file outside
the shared root.

An incompatible live plugin configuration, a missing or invalid checkpoint or
credential, or a conflicting tab or cache on first activation causes refusal.
There is no automatic conversion of an existing tab. Signed verification
refuses legacy packets and uses the signed generation scope throughout. The
existing legacy storage and synchronization paths remain separate.

The local tab opens without the signed transport, trust journal or identity
vault. Guided unlock authenticates only the ready setup manifest and its
immutable group, genesis-root and member pins against the active checkpoint
configuration; it performs no provisioning. It then opens the encrypted
checkpoint using the recovered wrapping credential. Local data remains readable
offline even if remote membership has subsequently changed; publication still
requires current journal authority. Opening or editing the tab does not start
replication. Like other
CopyQ tabs, its open contents are available as plaintext to CopyQ commands.
Copying items to the system clipboard or exporting them can put plaintext
outside the checkpoint. Treat that data as you would data in any other CopyQ
tab.

### Manual signed tab synchronization

1. Activate `signed_sync` through Signed Join. Finish editing, let CopyQ save
   normally, and resolve any save error before unloading. Close any editor and
   switch to a different tab. If the signed tab is still loaded, close CopyQ
   normally and reopen the profile with another tab selected. Keep
   `signed_sync` unloaded until synchronization completes.
2. Reopen the guided signed profile with its password, or use **Advanced signed
   setup…** with the trusted local pins and credential paths. Select
   **Synchronize signed_sync**. Review the displayed
   transport folder and confirm that this device may publish local edits there
   as an encrypted signed packet. New activations pin the canonical transport
   and private journal paths to the local profile. An older activation binds
   them after the user confirms the source and the journal authenticates the
   expected history. Changing either path is refused after pinning.
3. Reopen `signed_sync` after the operation. Repeat on a separately admitted
   and activated device to receive the update once its synchronization client
   has delivered the packet. Opening the tab or saving a local edit alone
   leaves replication idle.

The operation holds the exclusive checkpoint session and authenticates the
signed history against the last locally accepted membership and installed
key in the private trust journal. The journal retains exact packet witnesses.
The checkpoint separately remembers its last synchronized revision and
packet digest alongside the immutable Join proof and baseline. A clean copy
can move to a single authenticated descendant. A dirty copy can publish only
from its sole authenticated base tip. If local edits and the signed tip have
both advanced, or if multiple signed tips are visible, synchronization
reports a conflict and preserves the local copy and signed branches. Peers
may publish concurrently, so a new branch can still appear after a device's
last scan. An incoming snapshot that exceeds CopyQ's item limit or would
change a pinned or locked row is deferred.

Publication saves its intent before the journal reserves and seals the
packet. If publication is interrupted, retry the same action with the same
profile and transport. Recovery checks the reserved packet against the
intent and can confirm an earlier write using the same ciphertext. If newer
local edits exist when an earlier publication is confirmed, the encrypted
checkpoint retains those edits. An unattempted reservation for content edited
since staging is retired before evaluating the current local copy.

Synchronization uses the last locally accepted trust state. Membership
certificates and key packages are exchanged and installed through the
separate explicit workflow. An observed membership fork, removal of the
local device or change in key generation stops the current profile from
synchronizing. An eligible device can explicitly retire a matching
old-generation reservation locally after key rotation.

### Review and resolve signed conflicts

1. Leave the activated tab unloaded. Open Signed Join and select **Resolve
   signed conflict**. The wizard presents one or two authenticated signed
   versions and shows their full revision IDs and packet digests. Conflicts
   with more than two signed tips are refused by this wire version.
2. Choose **Keep this device's encrypted local copy** or select an exact
   signed revision. Confirm the displayed versions. The journal revalidates
   the reviewed local copy and exact signed tip set before publication.
3. The resolution is a signed update referencing every reviewed tip. The
   existing signed packets remain in history. A remote selection archives the
   prior local copy inside the encrypted checkpoint before publication. If
   another signed branch appears, review the current state before attempting
   another resolution. For a pending publication, use **Synchronize signed_sync**
   with the same profile and transport to reconcile the existing intent.

The checkpoint supports up to three encrypted conflict backups, subject to
private-record capacity. A remote selection is refused if the backup cannot be
retained. Use **Manage encrypted conflict backups** to review their item
counts. **Restore** swaps the selected backup with the current working copy
and leaves the signed cursor in place. Restoring a copy is a local edit.
**Remove backup** requires confirmation and removes only the selected backup
from the active checkpoint. Older filesystem blocks, storage snapshots or
independent copies may still contain it. Both actions require the checkpoint
generation to match the reviewed list and are refused during a pending
publication. CopyQ item limits and protected rows also apply to restored or
selected remote content.

### Signed background synchronization

Activate and unload `signed_sync`, and use manual synchronization to verify
the source if it has no pin yet. In Signed Join, select **Start signed
background synchronization**, review the source and confirm that the current
CopyQ session may send encrypted signed updates and fetch verified changes.
The wizard closes and the background action checks again at 30-second intervals.
It uses the same authenticated history and checkpoint rules as the manual
action. The tab must remain activated in the current profile, and background
work runs only while it is unloaded.

Opening the tab cancels or waits for the active operation to release the
checkpoint and defers further work while the tab is loaded. Applying or
reloading settings, disabling the plugin, opening Signed Join again or exiting
CopyQ stops the background session. Use **Stop signed background
synchronization** in Preferences to stop it explicitly. Stopping waits for an
already-started publication to finish or return an error. Any durable pending
intent remains available for manual review. Conflicts, pending work and
synchronization errors stop the session, with status shown in Preferences.
The user must review and reconcile pending work manually.

Authorization and the unlocked backend are held in memory for this CopyQ
process. Stopping releases the background backend and its credentials. Each
new CopyQ process requires a fresh opt-in.

### Recover pending publication after key rotation

After the private journal accepts a newer key generation, a device that
remains an authorized member can select **Recover pending publication after
key rotation** in Signed Join with the same activated profile and source.
Review the prompt and confirm local retirement. The operation matches the
old reservation to the encrypted checkpoint intent, keeps the working copy
and its old cursor, and does no transport I/O. The result distinguishes
an unattempted publication, a confirmed earlier transport write, and an
earlier publication that may have reached transport when the journal cannot
confirm its outcome. Existing transport history remains available.

The checkpoint remains bound to the original key generation. Use the separate
reviewed generation activation below to adopt the current generation. A membership
fork, removed device or mismatched reservation blocks this recovery.
Current readers can open earlier private records. Older builds can refuse
records written with conflict backups, merge intents or rotation evidence.

### Activate an accepted newer key generation

1. Exchange and accept the membership certificate and install the current sealed
   key through the verified device workflow. Leave `signed_sync` unloaded. Retire
   any matching old pending publication with the action above first.
2. Select **Activate accepted key generation**. Choose a new private destination
   for the successor checkpoint. The source remains intact. Review the old and
   new generations, local item count, selected version and confirmation digest.
3. If the new signed scope has one verified tip, adopt that exact version. If the
   explicitly provisioned scope is empty, the designated first device may confirm
   publishing its current local copy as the first signed snapshot. Check delivery
   before doing so; simultaneous first devices can create branches. Other devices
   should receive and authenticate that snapshot before activating.
4. Confirm the review. The operation rechecks active membership, the installed
   key, source cursor, exact local copy and target history under the journal and
   old checkpoint leases. It writes and reads back a separate encrypted successor,
   including a backup of the prior local copy, before updating the active profile.
   Retry the retained destination after an interrupted write or activation.

This is an explicit local adoption. Signed histories in different key generations
do not claim cross-generation cryptographic ancestry. An old CopyQ routing marker
is accepted only through the recorded predecessor binding and reviewed maximum
checkpoint generation. Forks, removal, missing keys, changed local data, another
target tip or unrelated pending work require a new review. The native row/item
limits and protected-row checks also apply. Background synchronization does not
activate a new generation automatically.

A staged Seed that differs from the current local copy is refused by default.
An explicit pending-content review can bind both the actual staged snapshot and
the changed local copy; the successor uses the reviewed staged content and backs
up the current local copy. If another accepted rotation makes an interrupted Seed
stale, an explicit review may retire only that exact scoped intent locally. It
does no old-scope transport I/O and does not claim the packet was never published.
Unsealed reserved sequences are burned, and retirement evidence survives the
next Seed and its retries.

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
recovery policy before claiming that broader rollback guarantee. Restoring a
prior journal or running the same identity with independent journals can reuse
a clipboard event sequence or exceed the per-author encryption budget. Cloned
identities count as a single membership approver.

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
  -R '^(device-trust|device_identity|device_identity_vault|device_trust_journal|device_key_envelope|device_key_delivery|device_key_receipt|device_key_lifecycle|device_control_transport|device_signed_event|device_signed_history|device_archive_migration|device_join|signed_join_checkpoint|signed-setup)$'
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
The Join suite covers request durability, full peer comparisons, exact
certificate retry and signed-history preflight with synthetic clipboard
data. The signed checkpoint suite exercises encrypted reopen, exact retry,
immutable baseline retention and refusal of changed or stale data. Native
builds with testing enabled include the Qt comparison dialog test. The opt-in
native build also includes `native-signed-setup`, `native-signed-generation`,
`native-signed-tab-storage`, `native-signed-tab-activation`,
`native-signed-replica-background` and marker
handling in `native-loader`. `signed-setup` covers encrypted provisioning,
independent credentials, verified invitations, exact reopen, immutable offline
credential unlock, missing-history non-reseeding and Linux durable interruption
cuts. The Qt setup suite drives
cancel, founder creation, fingerprint refusal, password reopen and source checks.
`device_join` also covers founder authority and reviewed generation adoption,
successor backup retention, exact retry and interruption recovery.
The `native-signed-two-device` CTest uses the `cqs-signed-two-device-test` fixture executable;
`tests/run-copyq-signed-two-device.py` exercises two disposable CopyQ processes,
encrypted cache markers, signed two-way updates, restart, conflicts and incomplete
or altered delivery. The fixture uses the production detached coordinator after
tab unload; it does not qualify human setup or actual cloud delivery.
These focused tests do not qualify the installed CopyQ GUI or sandboxed
packages.
Exact results belong to the implementing PR and current test run.

Release gates remain successful hosted Linux and Windows/MSVC runs of the signed
suites and real CopyQ two-device qualification, Windows/NTFS and Flatpak package
qualification, physical power-loss behavior, human peer-verification trials and
production cloud-client delivery. The offline recovery format, credential-bound
package export/import and fresh-machine restore drill are not implemented.
Dependency publisher provenance and distribution metadata remain required below.
Enable the optional build flag to include the signed suites in CI; adding the
jobs does not itself close their qualification gates.

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
