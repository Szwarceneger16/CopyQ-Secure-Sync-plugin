# Native file migration and Pinned/Tags

Secure Sync remains an external CopyQ 17 module. Install it into the plugin
folder for the matching ABI; no patched executable, private host class layout,
Python service or additional CopyQ storage plugin is required.

## Migrating native files

Use the preserved-tab adoption procedure in [DEVICE-SETUP.md](DEVICE-SETUP.md).
CopyQ unlocks its own encrypted source; Secure Sync uses its independent password
for its destination vault. The original tab and adopted encrypted backup remain.

The capture accepts QByteArrays and the exact registered CopyQ `DataFile`
metatype. It bounds the metatype's stream output before reading the documented
CopyQ 17 path/key envelope. Public `info("data")` is normalized for native
separators/trailing separators before comparison. The path must belong to it, with
CopyQ's four SHA-256 path components. Files are read through pinned handles,
with size/EOF/identity checks and verification of `SHA256("copyq_salt" + bytes)`.
Missing, corrupt, changed, linked, unsafe or over-limit files abort adoption
before committing the destination. Arbitrary QVariant converters and `FILE:`
MIME names remain unsupported.

Plain native files are read directly within the remaining snapshot budget.
Encrypted files are bounded to that budget plus 256 bytes of native framing.
The native Qt metatype decrypts a clone whose path refers only to a frozen copy
of the checked ciphertext: a sealed anonymous memfd on Linux/Flatpak, or an
owner-only temporary ciphertext file held without write/delete sharing on
Windows. Windows explicitly provisions the new temporary directory and file with the
current user as owner and a protected DACL; inherited temporary-directory
permissions are not relied on. Native source ownership by Administrators/SYSTEM
is allowed only with the audited writer ACL and successful kernel read access;
private ciphertext requires the exact user owner. Windows pins every ancestor
without delete sharing and opens the
frozen file by volume GUID, preventing path redirection during conversion.
The host receives the equivalent Win32 device namespace form that Qt preserves
without rewriting it into a UNC path.
The latter is removed on ordinary completion or exception. A process
termination can leave ciphertext only in the temporary directory. No plaintext
intermediate export is written.

The plugin forwards the native stream's opaque DEK field in transient memory
and wipes its stream buffers. It does not ask for CopyQ's password, read its key
files, link QCA, persist the native key, or substitute it for K-LOCAL/K-SYNC.
A native encrypted DataFile that decrypts to empty is refused because CopyQ's
converter reports both failures and empty plaintext identically. Plain empty
files are accepted and verified normally.

The final source capture checks all materialized bytes and the model epoch
again. The same bounded reader verifies an already committed native DataFile
snapshot when recovering encrypted removal. Plugin-owned snapshots still store
byte values, not local file paths. Limits remain 10,000 items, 256 formats/item,
1,024 ASCII bytes/MIME name and 32 MiB names/data; packed events and the aggregate
128 MiB record can impose a smaller effective migration limit.

## Protected rows

Audited CopyQ 17 Pinned and Tags plugins may remain enabled. Secure Sync reads
pin/tag MIME bytes and the public ordered tag definitions. Locked tags use the
same exact-name/anchored-regex first-match rules as CopyQ; tags are not trimmed.

An incoming replacement must retain each existing pinned item at its fixed row
position, and every locked tagged item with identical MIME content and relative
order. Tagged anchors above the final existing pin also keep their row position
so the stock Pinned wrapper cannot move them during structural edits.

Imports retain persistent model indexes for protected rows. Unprotected data
above the final pin are changed in place; gaps below it can change row counts.
New pin metadata is attached after all structural edits, so even new pins in
the middle of the incoming list cannot trigger stock Pinned row moves during
an earlier gap edit. Keep Both preserves the local order when appending remote
items and checks the result against the existing protection.

Removing, changing or reordering a protected item refuses before preparing the
import journal or accepting its history head. This applies to visible imports,
unloaded imports, Join with preserved local data, recovery and restoration.
Conflict/backup choices are checked before reserving a published decision, and
confirmed resolution projection is checked again before preparing its journal.
A waiting receiving device keeps its accepted revision and contents. Release
pins or blocking tags deliberately through CopyQ, then review the resulting
local changes/conflict; the plugin never silently overrides protection.

`itemsync`, GPG `itemencrypted`, and unknown third-party storage/saver plugins
remain incompatible. Core Encrypt Tabs is distinct from that GPG plugin.

## Verification

Native tests cover bounded native DataFile reading, missing/corrupt files,
non-execution of arbitrary converters, protected identity and matching rules,
and refusal without changing encrypted state or accepted head. The actual
CopyQ GUI scenarios exercise stock Pinned/Tags with bidirectional publication,
visible import, restart and protected deletion refusal. Preserved-tab tests
exercise real core-encrypted file-backed data and a missing-file retry. The
POSIX lifecycle driver also creates native DataFiles on encrypted removal and
recovers after termination between native commit and final opt-out.
