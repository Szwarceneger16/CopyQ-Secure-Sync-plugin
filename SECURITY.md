# Security policy and threat model

CopyQ Secure Sync handles private clipboard contents, which may include passwords,
access tokens, personal records, images and arbitrary binary data. Confidentiality,
integrity and preservation of those contents take priority over automatic setup,
availability or convenience. Encryption is only one part of that responsibility.

This document describes the current native plugin, its trust boundaries, operating
requirements and known limitations. Requirements below govern future changes;
they are not evidence that an unfinished feature already provides protection.

## Current status and maintenance scope

At the introduction of this policy, [VERSION](VERSION) is **0.2.0-rc.1**. The native
plugin integrates encrypted local storage, synchronization and recovery, but remains
an experimental release candidate. It has no independent security-audit or
cryptographic-certification claim. Do not make it the only copy of sensitive data.

[Release qualification](release/qualification.json) still lists pending physical
two-device Nextcloud acceptance, fault/historical-upgrade acceptance and performance
at production limits. Consult the current file, [release readiness](docs/RELEASE-READINESS.md)
and CI for the exact commit/platform being installed; historical green runs and
planned acceptance cases do not qualify a different build.

Report affected versions, identifying the exact version/commit. When possible,
also reproduce on current `main` or the latest native candidate. This policy does
not establish a long-term-support or backport commitment for older candidates,
the Python 0.1.1 predecessor, experimental modules or third-party builds. It does
not establish a response-time guarantee or bounty program.

## What is trusted

The plugin runs native code inside CopyQ. It must trust the installed CopyQ process,
the selected module and its dependencies, the operating system and the device while
unlocked. Every recipient of the shared synchronization key must also be trusted
with all data protected by that key.

The synchronization folder and cloud service are untrusted delivery mechanisms.
Inputs may be malformed, duplicated, modified, reordered, withheld or replayed;
different devices may receive different views. Filenames, directory entries and
timestamps are not authorization or freshness evidence.

| Threat | Current protection | Limit |
| --- | --- | --- |
| Cloud operator or folder reader without keys | Clipboard payloads are encrypted before publication; event metadata is authenticated. | Metadata remains visible; delivery and availability are outside the cryptographic guarantee. |
| Modification without K-SYNC | AES-GCM verification rejects altered authenticated data before payload decoding. | Valid old ciphertext can still be replayed or withheld. |
| Remote history rollback or equivocation | Encrypted local state retains accepted history and fingerprints of observed events. | Protection is relative to retained observations, not proof of a globally complete history. |
| Theft of private encrypted files | Local contents use an independent random key in a password-protected vault. | Copied password envelopes permit offline guessing; an unlocked or compromised endpoint is outside this protection. |
| Concurrent edits or interrupted operations | Explicit conflicts, encrypted backups and durable journals protect guarded transitions. | They cannot guarantee cloud delivery, arbitrary hardware durability or recovery after loss of all usable keys/backups. |
| Malicious or compromised admitted device | Previously observed history changes can be detected. | Possession of K-SYNC permits reading and creating authenticated events; v1 has no individual cryptographic authorship. |

Same-user malware, an administrator, a debugger, an injected CopyQ plugin, a
compromised cloud client on the endpoint or a malicious application reading the OS
clipboard can obtain plaintext or keys. A cloud service compromised only remotely
has a different boundary from its client compromised on an unlocked device.

## Data and metadata boundaries

- Only the configured `synced_tray` tab participates in this protocol. This does
  not encrypt the entire clipboard environment, other tabs or arbitrary files in
  the transport. Secrets copied into this tab are eligible for synchronization;
  there is no guarantee that passwords or personal records are detected/excluded.
- With independent storage enabled, the authoritative local snapshot, accepted
  history, pending operations and protected backups are stored in an authenticated,
  encrypted private record. Ordinary/preserved CopyQ tabs retain CopyQ's own
  storage rules; selecting a transport does not migrate or encrypt them.
- The transport holds encrypted event payloads. Its public headers and paths
  expose device labels, sequence numbers, parent relationships and protocol
  version. The provider can also observe file counts, sizes, modification times
  and traffic patterns. Encryption provides neither anonymity nor traffic padding.
- Profile settings, including paths and labels, are not a secret-storage mechanism.
  Use neutral device labels and paths when disclosure would otherwise reveal identity.
- Clipboard contents and usable keys necessarily exist in process memory while
  loaded/unlocked. Display, editing, copying, clipboard managers, screenshots,
  accessibility tools, swap, hibernation and crash dumps create further exposure.
  Best-effort buffer wiping does not cover every Qt/STL or application copy.
- Removing an item creates a new snapshot; earlier encrypted events and backups
  may still contain it. Cloud versioning, recycle bins, endpoint backups, SSD
  behavior and copied archives prevent a secure-erasure guarantee. Compaction,
  uninstall and key rotation do not remotely erase existing copies.

The synchronization module exchanges files through the local folder; the cloud
desktop client handles network delivery. Configure that client/account securely,
including transport TLS, account authentication, sharing and retention. Do not
confuse TLS to the provider with the plugin's payload encryption. See
[Nextcloud acceptance and boundaries](docs/NEXTCLOUD.md).

## Cryptography and key handling

The current backends use AES-256-GCM with 32-byte keys, random 12-byte nonces and
16-byte tags: OpenSSL on Linux and Windows CNG on Windows. Randomness comes from
the platform cryptographic generator. Event headers are authenticated as additional
data; authentication succeeds before decompression or item decoding. Random nonce
generation is not a nonce-misuse-resistant construction or a promise of unlimited
safe key lifetime. Retry reuses the durably reserved exact ciphertext rather than
creating a different encryption for the same publication intent.

| Credential/key | Purpose | What changing it does |
| --- | --- | --- |
| CopyQ password and DEK | Core Encrypt Tabs and ordinary CopyQ storage | Does not change the Secure Sync password or keys. |
| Secure Sync password | Protects this device's key vault | Rewraps the vault; neither the local key nor K-SYNC is rotated. |
| Random device-local key | Encrypts authoritative private data | Local rotation rekeys local data; K-SYNC is unchanged. |
| Shared K-SYNC | Encrypts/authenticates synchronization events | The supported shared-key transition creates a new key, transport and private profile; peers explicitly join it. |
| Transfer/backup/journal password | Protects the corresponding exported or recovery envelope | Changing a live vault password does not re-encrypt earlier copies. |

Vault, transfer and key-backup envelopes currently use PBKDF2-HMAC-SHA256 with
600,000 iterations and a random 16-byte salt, followed by authenticated AES-GCM
encryption. This is not a memory-hard password KDF. New passwords have a floor of
12 UTF-8 bytes, which is not an entropy guarantee. Use long, unique passwords;
an attacker holding an envelope can guess passwords offline without UI rate limits.

The vault holds both the local key and K-SYNC. Encrypted key transfer exports only
K-SYNC; the receiving device generates its own local key and vault. Verify the
recipient and deliver the transfer password separately through trusted channels.
The current transfer is a bearer-secret exchange, not authenticated public-key
pairing. Never put a password or raw key in a command-line argument, saved script,
shell history, repository, diagnostic report or synchronized folder.

An explicitly imported raw 32-byte K-SYNC file remains an additional sensitive copy.
It is not deleted by the plugin, and editing/deleting it does not rotate the key
already imported into a vault. Manage that copy deliberately outside the transport.

### Shared-key and revocation limits

Protocol v1 authenticates possession of K-SYNC, not a particular device or person.
A holder can decrypt all obtainable events under that key and construct valid
events using another device label. There is no cryptographic read-only member role,
per-event forward secrecy or signed device-membership enforcement in this runtime.

Removing cloud access does not revoke a copied K-SYNC. Changing the vault password
or rotating only the local key does not repair a shared-key compromise. Use the
[shared-key/history transition](docs/HISTORY-TRANSITIONS.md) from a clean device,
provision the new key only to trusted peers and revoke old cloud access separately.
Never distribute a replacement secret protected solely by the compromised old key.

Full-history rotation re-encrypts the old graph, including old contents; compact
rollover starts from the deliberately selected local snapshot. Both retain old
archives. Neither retracts plaintext, keys or archives already copied. An offline
device is not remotely wiped or automatically moved into the successor group.

### Locking and backups

Loaded models and automatic synchronization can retain unlocked keys. Hiding
CopyQ is not proof of locking, and stopping automatic synchronization alone does
not unload a tab. Stop automatic work, close editors, switch away from the tab and
use **Secure Sync: lock**; verify completion and resolve any unload refusal.
The Preferences lock control clears keys only after owned models are unloaded.
CopyQ's core lock and the plugin vault remain independent protection mechanisms.

Keep private encrypted backups of the data record, vault and applied profile,
plus the credentials needed to open them. A key backup is not a clipboard-data
backup, and synchronization is not an independent backup. Stop automatic work,
checkpoint/unload the tab and copy a consistent set of encrypted files. Refresh
backups after rotation and verify restore using an isolated profile. An older
key backup may not decrypt newer local data. Respect the authenticated profile/path
binding when restoring; changing settings is not a data-relocation procedure.
An interrupted, unsealed history-transition journal contains encrypted keys under its original
password; protect it and finish sealing through the documented action.

If usable keys, credentials and backups are all lost after keys leave memory,
there is no password-reset backdoor to recover the ciphertext. See
[key lifecycle](docs/KEY-LIFECYCLE.md) for exact recovery conditions.

## Filesystem and endpoint requirements

- Keep dedicated private data, vault, transfer, backup and transition-journal
  directories outside the synchronized transport, with the separation required
  by each action. Linux private state requires user-owned `0700` directories and
  single-link `0600` files.
  Supported Windows storage uses fixed local NTFS and protected private DACLs;
  publication staging must meet the transport-volume requirement.
- Hardened readers/writers pin handles, validate file identity/ownership and reject
  unsafe links, reparse points, special files and unsupported locations. Windows
  checks are not a promise of support for arbitrary network/removable filesystems.
  Linux also requires trusted procfs and filesystem support for `O_TMPFILE`, hard
  links, atomic rename and `fsync`; unsupported environments must refuse rather
  than use a weaker fallback.
  Do not relax permissions or substitute generic path reads to bypass refusal.
- Permission and path checks cannot stop a process acting as the same user or an
  administrator, and cannot discover every unrelated backup/synchronization tool.
  Explicitly exclude private directories from unwanted cloud backup and indexing.
  Use endpoint protections such as full-disk encryption and a locked OS session.
- Do not clone an active device's whole profile to another writer, reuse its device
  ID or reset sequence/state files. Join with a new device identity and fresh private
  storage. One local process lease is not a distributed lock across devices.
- Keep CopyQ, Qt, crypto/compression libraries, the OS and the cloud client updated
  within the tested compatibility matrix. Use only trusted compatible plugins.

Core **Encrypt Tabs** is distinct from CopyQ's GPG `itemencrypted` plugin. Current
integration rejects incompatible storage such as `itemsync`, GPG `itemencrypted`
and unknown third-party loaders/savers. Do not disable core encryption or weaken
these checks as a workaround. Use [installation](docs/INSTALLATION.md) and
[native data/protection](docs/NATIVE-DATA-AND-PROTECTION.md) for qualified combinations.

## Integrity, freshness and safe failure

Successful AEAD verification does not establish that a clipboard item's content is
safe. Received MIME, text, HTML, images and file-related data remain untrusted.
Do not enable automatic commands or external actions on received contents without
separately assessing them. Authentication must precede decompression; parsers must
retain strict schemas, canonical encodings and resource limits.

Current limits include 1,000 events/witnesses, 25 MiB per wire envelope, 32 MiB per
decompressed event, 256 MiB aggregate encrypted/decompressed history each, 10,000
local items, 32 MiB per local snapshot, 128 MiB aggregate record plaintext and four
protected conflict/recovery backups. These are byte/count budgets, not a process
memory ceiling or immunity to denial of service. Capacity exhaustion must refuse
further unsafe work without silently pruning history or overwriting local edits.
See [event limits](docs/EVENTS.md) and [conflicts/history](docs/CONFLICTS-AND-HISTORY.md).

Local-save status, publication to the local transport and receipt by another device
are different facts. Local checkpoint scheduling is not a durability deadline;
termination before a confirmed save can lose recent edits, and editor buffers are
not committed tab contents. A successful local flush does not certify physical
power-loss behavior or honest hardware. Local publication does not prove delivery
to the server or any peer. See [automatic synchronization](docs/AUTOMATIC-SYNC.md).

Retained witnesses detect changed or missing previously observed events. They
cannot detect an event never delivered, establish a globally current view, or
detect rollback of the entire local record and its backups together. Initial
joining depends on the history supplied to the device. Two isolated devices can
both observe an empty cloud folder and independently Seed; only the first device
should Seed, and others must wait for delivery before Join.

Authentication failure, incomplete history, ambiguous tips, unsafe paths, missing
established state, exhausted capacity or unresolved recovery must stop the affected
operation. Preserve encrypted state, journals and later edits; never interpret a
missing mount or corrupt record as permission to initialize an empty replacement.
Protected local saves should remain available when the synchronization failure
allows them. Use explicit retry/restore/conflict actions rather than deleting event
ancestors, resetting counters or manually rewriting journals.

## User control, migration and removal

Automatic synchronization is opt-in. Before operations that export keys, replace
populated local contents, adopt a tab, rotate keys, discard backups, change history
or leave private storage, the user must understand the scope and make a deliberate
choice. Routine safe validation/retry should not require repeated approvals.
Future setup must also disclose changes to autostart, launch settings or sandbox
permissions and obtain deliberate consent. It must not silently broaden access
or weaken encryption to make installation succeed.

Preserved-tab adoption retains the source and an encrypted archive, validates
supported data and avoids plaintext intermediate exports. This does not erase
copies the source storage already held. Stop the old Python agent on every migrating
device and follow [device setup](docs/DEVICE-SETUP.md); automatic conversion of its
state is not implemented. Never run both writers on the same profile.

Back up before upgrading private-state formats. Older modules may refuse newer
schemas; do not downgrade an active profile in place or repoint it at older state
to bypass that refusal. Follow the supported migration/handoff for that version.

Before disabling or deleting the module, complete **finish encrypted removal** to
stock CopyQ with **Encrypt Tabs** enabled, verify the `Detached` result and verify
the data after restart. Removing the DLL/SO first bypasses the guarded handoff and
can make the private snapshot unavailable. Retained encrypted state/vaults are not
automatically deleted; uninstall is not secure erasure.

## Device-trust work is not a shipped guarantee

[Stage 1 (#3)](https://github.com/Szwarceneger16/CopyQ-Secure-Sync-plugin/pull/3)
defines future pairing/membership and guided-setup requirements.
[Stage 2 (#4)](https://github.com/Szwarceneger16/CopyQ-Secure-Sync-plugin/pull/4)
adds an isolated test-only policy model with a deterministic test verifier. At the
introduction of this policy, neither provides production peer verification,
signature enforcement, durable signing reservations, device-key delivery, recovery
packages or a guided automatic installer in the running plugin.

Before such features can be advertised, they require real cryptographic adapters,
verified peer identities, durable authorization state, migration of authenticated
events and platform qualification. The design's one-time bootstrap and subsequent
two-distinct-identity approvals must not become a silent quorum downgrade on loss
of devices. Conflicting membership evidence must halt authorization/key release
and affected automatic work while preserving recoverable local data. Removal must
exclude the target and deliver fresh future-data keys only to survivors.

Even a correct implementation cannot make an existing reader forget plaintext or
guarantee global consensus over asynchronous cloud delivery. Model tests, comparison
digests and planned acceptance cases are not proof of real peer verification or
durable production security.

## Development and distribution requirements

Changes touching parsers, keys, storage, imports, recovery, installation or
permissions require review of the affected trust boundary and failure paths.
Preserve authentication-before-use, bounded decoding, independent key roles,
authenticated profile binding, no-overwrite publication and durable reservation
of exact ciphertext. Retries must not reuse an ID for changed contents or discard
the evidence needed for recovery. Do not invent cryptographic constructions or
silently change formats, parameters or compatibility behavior.

Tests must use synthetic clipboard contents, public fixture keys and disposable
profiles. Include malformed/oversized input, wrong-key/tamper cases, interruption,
stale decisions, filesystem races, rollback/conflicts and migration/restore where
relevant. Tests and fuzzing reduce risk; they are not a security proof. Require
current-commit native/installed-platform evidence and the outstanding release
qualification before stronger product claims.

Native modules execute with CopyQ's authority. Obtain artifacts from a trusted
repository/release, verify version/commit and package integrity, and enforce the
actual CopyQ/Qt/OS/architecture/compiler compatibility checks before loading.
Checksums shipped beside an artifact detect corruption but do not independently
authenticate a publisher if the same source is compromised. Current manifests and
CI promotion are not cryptographic attestation or reproducible-build proof. Review
dependency/pin changes and follow the [release procedure](docs/RELEASING.md).

Logs, telemetry, exceptions, CI artifacts and support reports must not include
clipboard payloads, passwords, raw keys or decrypted records. Current explicitly
copied diagnostics use a fixed redacted field allowlist; this is not a guarantee
that every CopyQ/plugin/OS log or crash dump is safe. Review any attachment before
sharing. Copying diagnostics also places them on the OS clipboard, where clipboard
history may retain them. New diagnostics/telemetry require privacy review and must
not silently upload private material.

## Suspected compromise or data loss

1. Pause automatic synchronization. Isolate a suspected endpoint and revoke its
   cloud/account access from a clean device; do not trust it to rotate or deliver
   replacement secrets.
2. Preserve private encrypted data, vaults, transition/import journals and complete
   transport history before repair. Keep them outside public issues and shared
   logs. Avoid resetting, reseeding or deleting files to make an error disappear.
3. Assess exposure. If plaintext, an unlocked endpoint or K-SYNC may have leaked,
   treat obtainable data under that key as exposed. Revoke/replace any copied
   application passwords, tokens or other credentials in their originating systems.
4. Recover from verified backups or use the supported shared-key/successor procedure
   on a clean device. Share the fresh key only with trusted devices; verify data
   and each successor profile before resuming automatic work. Password rewrapping
   alone does not contain a leaked key, and rotation cannot undo past disclosure.

## Reporting a vulnerability privately

Do not publish exploit details or real private data in a public issue or PR.
Use GitHub's private **Report a vulnerability** flow under the repository's
**Security** tab **if available**:
[private advisory](https://github.com/Szwarceneger16/CopyQ-Secure-Sync-plugin/security/advisories/new).
If that flow is unavailable, ask the maintainer for a private reporting channel
without disclosing the vulnerability publicly. No separate security email or
encrypted-contact key is established by this document.

Include the affected version/commit, OS/filesystem, CopyQ/Qt/package versions,
expected versus actual behavior, impact and a minimal reproduction using only
synthetic data. Describe any relevant interruption, permissions, history or
migration conditions. Do not attach real clipboard exports, passwords, keys,
private vault/state files, raw crash dumps or identifying paths. Replace sensitive
values and reproduce in a disposable profile. Coordinate disclosure and remediation
privately; publication of this policy is not authorization to access anyone else's
devices, cloud folders or private data.
