# Secure Sync local encryption and keys

The main `securesync` module uses the standard CopyQ 17 plugin API. It does not
patch CopyQ, obtain its password/DEK, or require a service. CopyQ discovers a new
DLL/SO at startup, so installation requires a restart. This milestone implements
local key management; the native synchronization runtime is still unfinished.

## Three independent credentials

| Credential | Purpose | Shared between devices? |
| --- | --- | --- |
| CopyQ password and DEK | CopyQ's Encrypt Tabs, unlocking and ordinary tab storage | Managed by CopyQ |
| Secure Sync password | Encrypt the private local key vault | No; choose a password per device |
| Random local key, 32 bytes | Encrypt this device's authoritative local snapshot | Never exported to another device |
| K-SYNC, 32 bytes | Authenticate/encrypt protocol v1 synchronization events | Yes, only with trusted devices |

The vault holds the random local key and K-SYNC. Creating the first vault either
generates K-SYNC or explicitly imports an existing strict 32-byte key file.
The imported file is not consulted on subsequent local saves. The plugin does
not delete that user-owned file; store or remove it according to your backup
policy. Changing its contents does not change the already imported identity.

The separate password is necessary because the public CopyQ API does not expose
its password or encryption key. Changing either password does not change the
other. A Secure Sync password change rewraps the vault, preserving both keys and
the existing local ciphertext. New passwords must contain 12–1,024 UTF-8 bytes;
length is a floor, not a strength guarantee. Use a long, unique password.

## Setup and transfer

Choose separate existing private directories for data and the vault, outside
the synchronized transport. On Linux use owner-only directories (0700); on
Windows use a protected private DACL on local NTFS. The transport needs `events/`.
The application checks both UI path relationships and handles at actual I/O.

For a new profile enable independent storage, choose the vault directory, and
use **Initialize empty standalone storage** with the new password. Initialization
is create-only: existing data, a vault, Python state, unknown files or orphan
staging files are refused. Apply the profile and use a new empty `synced_tray`.
An ordinary populated CopyQ tab is not silently migrated.

For another device, **Share encrypted synchronization key** writes a create-only
password-encrypted transfer into a dedicated private directory outside transport,
data and the vault; overlapping paths are refused for transfers and backups.
Use a separate transfer password and communicate it separately. The transfer contains only
K-SYNC, never the source device's local key. On the other device configure a
new empty profile, then **Set up from a shared encrypted key**. It creates a new
local key and vault under that device's own password. This transfers a key;
Manual Seed, Join and protected adoption use [unified state](UNIFIED-STATE.md).
See [device setup](DEVICE-SETUP.md) for both devices and the explicit Python
transition. [Opt-in automatic synchronization and subsequent publication](AUTOMATIC-SYNC.md)
are available; its action retains unlocked keys in memory until stopped.

After a partial initial setup where the vault was committed but data was not,
**Finish interrupted initial setup** authenticates that vault and performs
create-only data initialization. It never generates replacement keys.
The vault authenticates an `initializing` intent until data setup is confirmed;
an established vault refuses this action even when its data file has disappeared.
Interrupted setup with an already committed data record verifies and retains it.
Earlier schema-2 experimental storage encrypted with raw K-SYNC needs the explicit
**Migrate earlier experimental local storage** action and its original key. The
new vault is committed before an atomic data rekey; retry resumes after a crash.
Migration from Python state is not implemented by this action.

## Locking and password changes

CopyQ retains control of its native tab lock and password dialogs. With Encrypt
Tabs enabled it checks its own password before asking the plugin to load the
tab. Secure Sync then authenticates its independent vault if needed. The module
advertises encryption support because its private ciphertext remains protected
when CopyQ enables/disables encryption or changes its own password.

Unlocked keys remain in memory while an owned tab model is loaded. Destroying
the last owned model wipes the cached keys; an unlock without a model expires
after 60 seconds. CopyQ's ordinary encrypted-tab expiry unloads eligible models
and therefore clears these keys. CopyQ intentionally keeps active models and
open editors loaded; hiding a window alone is not proof that it is locked.

Use **Secure Sync: lock** from CopyQ's command menu after switching away from
`synced_tray` and closing editors. It checkpoints committed model contents and
uses public `unload()` without forcing. If CopyQ refuses unload, the operation
reports refusal and preserves the model. It does not discard editor buffers.
The Preferences **Lock Secure Sync** control only clears keys after models have
already been unloaded. Preferences key actions operate on the applied profile;
save changes before using them.

Use **Change Secure Sync password** to rewrap the vault atomically. After any
unconfirmed commit, try the old and new credentials without resetting files.
The record is entirely protected by one credential set or the other. No password
or raw key is written to QSettings or logs. Public scripting supports prompts;
advanced `callPlugin` credentials must be QByteArray values. Do not put actual
passwords in command-line arguments, shell history or saved scripts. The process
test's embedded credentials are public synthetic fixtures only.

## Rotation, backups and loss

**Rotate local data key / finish interrupted rotation** first checkpoints owned
models, durably journals both old and new local keys in the vault, atomically
rekeys the data, verifies it, and finally retires the old key. Interrupted
rotation retains the key needed for either complete data record. Unlock selects
the key that authenticates current data; repeat rotation to finish the journal.
K-SYNC remains unchanged. Refresh the encrypted vault backup after rotation.

**Back up encrypted keys** authenticates the vault and writes an encrypted,
create-only backup to another private directory. It is a key backup, not a copy
of clipboard data. Preserve the data directory, applied profile and password
too. A pre-password-change backup uses its original password; a backup predating
local-key rotation cannot decrypt the latest data and is refused on restore.

**Restore missing key vault** accepts only a missing target, authenticates the
backup and verifies its keys against current private data before creating the
vault. It never overwrites an existing/corrupt vault. If the vault disappears
while keys are still unlocked, **Rebuild a missing vault from currently unlocked
keys** verifies those keys against the data before create-only recovery. This
option cannot recover keys after process shutdown or their eviction from memory.

Wrong/missing credentials, corruption, unsafe permissions and busy leases refuse
the operation. Opening/saving never silently creates an empty replacement. If
both the vault/password and usable backup are lost after keys leave memory,
the encrypted data cannot be recovered; there is no backdoor or reset recovery.

Protocol v1 does not replace a key in an existing transport. The integrated
[history transition](HISTORY-TRANSITIONS.md) instead re-encrypts the full graph
under a new K-SYNC in a new transport, preserving IDs, parents and contents.
Compact rollover starts a new root while retaining the old encrypted archive.
A durable private journal and suspended source vault allow crash recovery;
other devices explicitly Join using an independently shared new key.

## Safe disabling and removal

Unchecking/removing the plugin first cannot convert its private snapshot. A
direct disable while independent storage is active is deferred by the module.
Changing its profile or opting out while it owns a model is also refused. CopyQ
configuration, deletion of a DLL/SO outside the process and other plugins cannot
be fully controlled by this module: complete the handoff before uninstalling.

1. Enable CopyQ **Encrypt Tabs** and establish its password.
2. Disable incompatible storage and unknown third-party plugins
   (ordinary text/image/notes/FakeVim and Pinned/Tags may remain enabled), close editors and select another
   tab. This ensures CopyQ's standard saver receives the handoff.
3. Run **Secure Sync: finish encrypted removal** in CopyQ's command menu and
   authenticate Secure Sync. This verifies the current public plugin inventory,
   checkpoints data and records an authenticated pending removal intent.
4. Ordinary unload/reload restores the exact snapshot and lets CopyQ commit its
   standard encrypted tab file. The public saver callback confirms the commit
   before Secure Sync persists opt-out. A settings change invalidates the
   authorization; a refused unload leaves the operation pending. Finish removal
   again after resolving it. **Cancel pending removal** is allowed before a
   confirmed native commit.
5. Only after `Detached` disable/delete the module and restart CopyQ. Restore
   other item plugins afterward. Keep the vault and encrypted private data until
   you have verified your recovery/backups; they are not automatically deleted.

After interruption, rerun the command. If CopyQ already committed its encrypted
file, the plugin compares its loaded MIME snapshot with private data before
finalizing. Empty tabs and supported byte-array MIME data are covered. Default
CopyQ may materialize large values as `DataFile`; recovery verification uses
[bounded native materialization](NATIVE-DATA-AND-PROTECTION.md). Unsafe, missing,
corrupt or over-limit files refuse while retaining the encrypted private backup. A denied/unconfirmed handoff never authorizes
plaintext export or deletion of the backup.

## Format and verification boundary

Vault/transfer/backup envelopes use `CQSVLT01`, random 16-byte salt,
big-endian 600,000 PBKDF2-HMAC-SHA256 iterations, random 12-byte nonce, and
AES-256-GCM ciphertext with 16-byte tag. The complete header and profile binding
are authenticated. Unknown modes/parameters and oversized inputs are rejected
before derivation. Linux uses OpenSSL and Windows uses CNG; no new crypto library
is bundled. Vault plaintext is limited to 64 KiB, with 4 KiB of snapshot content.

Key buffers are wiped on release, but this is not a guarantee against access by
the same OS user, process memory inspection, swap, crash dumps, rollback of all
files or a compromised application. Paths stored in settings are nonsecret.

Linux validation includes actual process termination during record transition
and both phases of local-key rotation, module key eviction/recovery tests, and
the official unmodified CopyQ 17.0.0 AppImage with separate external modules.
The GUI helper uses only public Qt APIs, is restricted to disposable fixture
sessions and is excluded from installation/packages. Windows tests are included
in CI, together with actual official Windows GUI and installed Flatpak package
replacement/encrypted removal. See the current-SHA results and the explicit
[installation matrix](INSTALLATION.md); historical local-only results do not
certify other platforms. Passing local encryption tests does not complete
synchronization.
