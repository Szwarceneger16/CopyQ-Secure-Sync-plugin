# Native CopyQ settings and inspection

The loadable `securesync` DLL/SO targets the unchanged CopyQ 17 plugin interface.
Preferences → Items → Secure Sync configures read-only transport inspection and
opt-in independent local storage. The panel's **Devices and recovery** page and CopyQ's command menu offer explicit
unloaded-tab Seed/Join/import, preserved-tab adoption and offline recovery through
a [unified record](UNIFIED-STATE.md). [Subsequent publication and opt-in automatic sync](AUTOMATIC-SYNC.md)
include live visible-tab updates, persisted scheduling and explicit conflict resolution. The explicit
[fresh-profile Python 0.1.1 transition](DEVICE-SETUP.md) preserves old data/state.

## Profile and controls

The page provides device ID, fixed protocol-v1 tab `synced_tray`, existing transport
with `events/`, private data directory, private password-vault directory, optional
existing K-SYNC import file, optional Windows publication-staging directory,
and the independent-storage checkbox. Folder/file
chooser Cancel preserves the field. Editing changes no files. Apply/OK saves eight
schema-3 fields under `Plugins/securesync`; no password/key material enters settings.
The nonsecret `host_cache_file` is observed separately from public loader/saver
QFileDevice callbacks for interrupted-removal verification.

Schema 1 stays inspection-only on read; inspection-only schema 2 can upgrade
settings. A schema-2 standalone profile needs explicit migration with its original
key and a newly selected vault directory. Unknown schemas are preserved/refused.
Changing a profile while a model is owned is deferred. Selecting another path
does not copy/rebind files or retarget an active inspection.

On Windows, publication staging must be private and on the same fixed NTFS
volume as transport, outside its tree and separate from the vault. An empty
field uses the private data directory, preserving existing configuration.
Selecting private staging on the transport drive supports data/vault on another
drive. This auxiliary path is excluded from record binding so it can be corrected
before retrying a reserved event; normal stop/unload guards still apply. Linux
keeps anonymous staging and does not use the setting.

**Initialize empty standalone storage** acts on the selected draft, asks for a
new independent password and performs create-only provisioning. It does not
save the draft or migrate a populated ordinary tab. Apply the draft afterward.
Vault actions otherwise use the applied profile. They expose unlock/release,
password change, local-key rotation/resume, encrypted key backup/recovery,
encrypted K-SYNC transfer, partial-setup resume and earlier-experiment migration.
See [full key and removal procedure](KEY-LIFECYCLE.md).

Preferences actions launch a short-lived CopyQ command client in the same session;
there is no shell, daemon or password in its arguments. Only fixed action identifiers
are accepted. These are the same public-script operations used by menu commands:
checkpoint, ordinary unload, active-plugin inventory and editor/protection checks
remain mandatory. Profile drafts cannot run these actions until applied. Busy
operations disable competing controls; stopping automatic synchronization requests
safe cancellation rather than terminating the durable worker. Closing Preferences
does not kill an admitted operation, and Cancel does not undo completed actions.

Actual lock/removal coordination uses the generated CopyQ commands **Secure
Sync: lock** and **Secure Sync: finish encrypted removal**. They can call public
`unload()` and `stats()` in the host script context. A direct Preferences prepare
callback without current inventory reports this instruction; the corresponding
Devices and recovery action runs the full command and does not approve
a guessed set of active plugins. Preferences can cancel a pending removal or
confirm a completed native handoff. Unload never forces an editor closed.

## Read-only transport inspection

Inspection captures the chosen draft and disables fields/actions during its
owned worker. Repeated requests do not queue workers. A vault-backed profile
must first be applied and unlocked; the worker receives only K-SYNC, never the
local key/password. A raw-key inspection-only profile uses the strict platform
reader. Inspection neither reads nor changes the private data record and writes
nothing to transport or clipboard models. Results contain fixed diagnostics,
counts, never device/revision IDs, paths, key bytes or malformed payloads.

## Status, errors and safe diagnostics

The live status separates **Ready**, **Synchronizing**, **Waiting for files/tab**,
**Conflict**, **Locked**, **Recovery required**, **Error** and configuration/disabled
states. Each presentation includes local-save evidence and a next action. The
last successful operation does not mask newer unsaved committed edits or a local
save failure. A verified save covers committed model data; editor text is excluded.
After restart, loading a verified record also restores guidance for a pending
import, publication or conflict decision, or for explicit Seed/Join. A successful
local load/save does not clear a still-pending synchronization operation. These
phase hints come from already authenticated records, without additional polling I/O.
An unconfirmed commit means either an older or newer complete record may be
durable: retain the record/vault, reload and use explicit recovery rather than reset.
Publication into a local transport folder never promises delivery to another device.

**Copy safe diagnostics** is explicit and copies JSON format 1 with only:
`format`, fixed `component`, allowlisted `state`, boolean `automatic`, `locked`,
`operation_active`, and `local_save` (`unchecked`, `pending`, `verified`, or
`unconfirmed`). It excludes paths, device/event identifiers, counts, MIME names,
contents, key identities, keys, passwords and raw exception/process output.
`plugins.securesync.diagnostics()` returns the same redacted report; the menu's
**Secure Sync: status and next step** displays the human-readable status.
Read-only inspection is displayed separately and never changes trust or clears a
synchronization failure. The panel refreshes from in-memory state, without polling
encrypted files on the GUI thread. It is not a claim that external files cannot
change after the last verification.

Missing parents defer acceptance; multiple authenticated tips remain conflicts.
Automatic synchronization is off by default. A persisted opt-in preference
resumes only in the GUI server and waits for unlock; CopyQ CLI processes never
start a scheduling client. Worker ownership and shutdown are bounded by
local I/O. Automatic sync uses a separate worker and stops scheduling without
terminating an in-flight durable operation; synchronous saver callbacks still wait.

## Paths and platform build

Preflight rejects relative/unsafe paths, traversal, symbolic links and overlapping
transport/data/vault directories. Actual disk operations use handle-pinned
platform readers/stores. Linux requires private owner/mode checks; Windows uses
local NTFS, protected ACLs and Win32 sharing/lease checks. Choosing a folder does
not guarantee that unrelated software does not synchronize it.

Build from a clean CopyQ v17.0.0 checkout at
`d0c179f75c04974bfe801289ea6e58a1a49535fc`. CMake verifies source cleanliness and
the exact plugin IID; it compiles interface support, not the CopyQ application
or Synchronize plugin. Qt 6.10+ Core/Gui/Widgets, C++17, CMake 3.24+, zlib and
Linux OpenSSL 3 / Windows CNG are required. Default builds neither link nor
prepare the historical host extension or require its test-only QCA dependency.

```sh
cmake -S . -B build -DCOPYQ_SOURCE_DIR=/absolute/path/to/clean/CopyQ \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The Qt ABI/architecture must match the installed CopyQ. Installing requires a
restart for module discovery. Flatpak needs a matching SDK build and paths
visible in its sandbox; a native host `.so` is not a universal Flatpak module.
The plugin advertises `supportsEncryption() == true`: its own password vault
is independent of CopyQ's Encrypt Tabs and no CopyQ DEK is obtained.

## Evidence and limits

Required native suites exercise real settings, actual QPluginLoader modules,
strict key/transport workers, bounded models, vault lifecycle and local storage.
Process tests in the official unmodified CopyQ 17 AppImage also exercise native
password dialogs, expiry/editor guards and removal/restart. Test-only Qt widget
automation is an external disposable module excluded from installation/packages.
See [storage evidence](STANDALONE-STORAGE.md) and [release gates](RELEASE-READINESS.md).
Windows CI and matching-SDK Flatpak GUI checks must pass for each new commit;
consult that commit's reports rather than inferring success from this document. All tests use public synthetic keys and disposable profiles.

Shared-key rotation, compact rollover, explicit successor Join and journal recovery/sealing are available in Devices and recovery; see [history transitions](HISTORY-TRANSITIONS.md).
