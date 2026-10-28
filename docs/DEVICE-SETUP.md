# First device, another device and preserved-data transition

The commands below run inside an existing, unmodified CopyQ 17. No Python
service or rebuilt CopyQ is required. Complete this setup before enabling
automatic synchronization or resolving conflicts. Install the matching DLL/SO, restart
CopyQ, and use its Secure Sync command menu. Close editors first. The commands
checkpoint and ordinarily unload the bound tab; unload refusal stops the action.
Stock text/image/notes/FakeVim plugins can remain enabled for guarded state
actions. Disable incompatible storage and unknown third-party
loaders; a refusal identifies the active loader. See [automatic sync](AUTOMATIC-SYNC.md).

## First device: Seed

1. Choose a new, unused device ID and an existing dedicated transport with an
   existing `events/` directory. Seed requires the entire authenticated history
   to be empty, including other devices. A missing mount/folder refuses setup.
2. Choose separate existing private data and password-vault directories outside
   the transport. Linux directories need owner-only permissions. Windows needs
   protected private DACLs on fixed local NTFS. On Windows, choose an existing
   **Private publication staging folder** on the transport's volume if the data
   directory is on another drive. It must be private, outside the synchronized
   folder and separate from the vault. Leaving this option empty uses the data
   directory. Data and vault can stay on a different NTFS volume; Linux uses
   anonymous staging and does not use this option.
3. Apply the profile with independent storage enabled. Initialize empty storage
   with a separate Secure Sync password. K-SYNC is generated or explicitly
   imported from an existing private 32-byte file. This is create-only setup.
4. Put the desired items into `synced_tray`, or adopt a preserved ordinary tab
   using the procedure below. Run **Seed first history from local data**.
5. A successful Seed writes one protocol-v1 encrypted root event at sequence 1
   and records it as the accepted head. Empty tabs and empty items are distinct.
   Local checkpoint generations are never used as event sequences.

Seed, adoption and preserved Join upgrade private state to schema 3. Older
plugin builds cannot read that schema; keep an encrypted data/vault backup and
do not downgrade an active profile without its documented handoff.

Before any transport write, schema 3 durably reserves the sequence, exact
encrypted envelope and corresponding snapshot in the one private AEAD record.
If publication/confirmation or the final state commit is interrupted, use
**retry reserved Seed**. It reuses those exact bytes and that ID; existing event
files are never overwritten. Reconciliation checks exact ciphertext and applies
a fresh native durability barrier before accepting the head. A completed retry
is idempotent. It does not allocate sequence 2 or generate another nonce.

Changed ciphertext, conflicts, missing/corrupt state and unavailable transport
stop recovery and retain the journal and local data. Later local edits are kept
when retry publishes the reserved snapshot; they become local changes relative
to the accepted Seed. Retry never replaces them or publishes those newer edits. Do not
reset the profile, delete its journal or use Seed on an existing history. If two
devices independently Seed while cloud delivery hides the other root, both roots
can later appear: v1 cannot globally lock an eventually consistent cloud folder.
Seed only the first device; wait for that event to arrive before joining others.

## Another device: Join

1. On the first device use **Share encrypted synchronization key**. Transfer the
   protected key package privately and communicate its transfer password
   separately. The package carries K-SYNC, never the device-local data key.
2. Configure a different, unused device ID and the same synchronized transport
   on the second device. Use new private data/vault directories. Import the
   shared key package using **Set up from a shared encrypted key** and choose
   this device's own Secure Sync password. Its local data key is independent.
3. Wait until the complete authenticated history has arrived, then run **Join
   authenticated history (empty tab)**. Reusing an ID already in history refuses
   Join. Missing parents, multiple tips or an authentication error do not select
   a winner or produce a partial import.
4. Subsequent manual **import next history tip** uses the existing guarded
   FastForward path and refuses local changes.

If the new private tab already has items, choose **Join history and keep a local
backup** instead. This explicitly archives its exact pre-Join ordered MIME
snapshot inside the same encrypted record before replacing local contents.
The backup survives successful Join, crashes, local saves and local-key rotation.
Interrupted import uses the existing accept/retry/restore commands; restoring
original data retains the archive and leaves the profile unjoined.

After successful Join, **restore preserved pre-Join data** restores that archive
only from a clean accepted snapshot. It retains the accepted head, making the
restored contents local changes. Later local edits and pending operations refuse
this command so it cannot silently overwrite new work. The archive is not cleared
by restoration. It is a single protected pre-Join archive, not a merge feature.
Before Join the same command can restore an adopted archive into an empty
unjoined tab; it refuses a different nonempty local snapshot. A completed retry
that already contains the archived contents is idempotent.

## Move an ordinary CopyQ tab into private plugin storage

1. Back up the existing CopyQ profile, including external item files and its
   encryption key files, into a private encrypted backup. Enable CopyQ **Encrypt
   Tabs**, unlock it normally, and keep independent plugin storage off.
2. Run **preserve ordinary CopyQ tab before setup**. It ordinarily unloads and
   renames `synced_tray` to `synced_tray-before-secure-sync` using public CopyQ
   APIs. An existing backup name is never overwritten. A retry after a completed
   rename reports `AlreadyPreserved`.
3. Apply the new standalone profile and explicitly initialize its empty private
   storage, or initialize from the shared encrypted synchronization key.
4. Run **import preserved CopyQ tab (keeps source)**. The source must unlock and
   ordinarily unload. Its supported packed items are validated in memory before
   a whole-record encrypted copy/readback. The destination must be empty and
   unjoined; matching completed retries are idempotent. An existing different
   destination or archive refuses adoption.
5. Compare the restored destination with the source, restart CopyQ and verify
   again. Keep the original native tab and encrypted profile backup. Then Seed
   an empty transport or Join existing history with the protected local backup.

No plaintext intermediate export is written. The native source tab remains
served by CopyQ, and a private archive of adopted contents remains in the plugin
record. Native `DataFile` values now use [bounded materialization](NATIVE-DATA-AND-PROTECTION.md).
Missing/corrupt/changed files, arbitrary custom converter values, malformed
packs or exceeded limits refuse instead of being dropped/stringified. The
preserved-tab command scopes a public saver `copyItem()` audit before the host
serializer can turn a failed file read into empty bytes. It verifies the full
materialized source and its model epoch before adoption, and restores ordinary
copying after failure/cancellation. An empty/unavailable source refuses this
command; an intentionally empty first device can use Seed directly.
The local ceiling is 10,000 items and 32 MiB; packed/event and aggregate-record limits
can refuse a smaller source. Never delete the source to bypass a refusal.

## Explicit transition from Python 0.1.1

This is a fresh-profile transition, not automatic conversion of Python's
`state.json` or `pending-import.json`.

1. Finish any interrupted import/recovery with the old agent first. If its
   pending state is unresolved, stop here and preserve its files and tab; the
   native plugin must not guess whether a partially imported tab is authoritative.
2. Stop the old agent and disable its scheduled/service startup on **every
   migrating device**. Keep the previous private state, configuration, key and
   complete CopyQ profile in a private encrypted backup outside transport. Do
   not delete files or leave both implementations writing the same profile.
3. Preserve the existing ordinary `synced_tray` as above. Configure a **new unused
   device ID** and new empty native private folders. Do not reuse Python's state
   folder or reset its sequence counter. Explicitly import the existing K-SYNC
   (or a protected transfer carrying that same key).
4. Keep the existing transport history unchanged. Initialize native storage and
   adopt supported preserved tab contents. Use Join, with the protected local
   backup if the tab is populated. Existing history is authenticated and reused;
   Python metadata is neither trusted nor copied into native generation counters.
5. Restart CopyQ, compare exact items/formats and retain both backups. If history
   is incomplete/conflicting or data formats are unsupported, stop migration and
   keep the old tab/state intact. Do not Seed over that history.

If no usable history exists, keep the original transport and backups untouched;
create a different empty transport and new device profile, adopt supported data
and Seed there. This creates a new history deliberately. It does not repair,
truncate or reinterpret the previous history. A return to ordinary native CopyQ
storage uses the existing guarded encrypted handoff/removal procedure, not a
directly disabled plugin with an unreadable cache marker.

## Validation boundaries

The native suites cover independent local keys, exact envelope reconciliation,
ten state-commit and three transport-publication subprocess exits, nonempty Join
backup/recovery, changed ciphertext, unavailable transport, later-edit retention
and local-key rotation with a reserved Seed. A Python encoder/AES-GCM oracle
checks the new schema-3 vector while the old vectors stay unchanged.

An official unmodified CopyQ 17 AppImage test passed the native source-preservation
and adoption commands, Seed/retry, protected key transfer into a second separately
configured CopyQ server, Join of exact binary data and both servers' restart.
These two servers share a local test transport; delivery through real cloud
clients between physical devices is not certified by this test. Windows/NTFS
uses native CI rather than Linux filesystem emulation. Full Windows GUI and
Flatpak installation/lifecycle still require their own validation.
