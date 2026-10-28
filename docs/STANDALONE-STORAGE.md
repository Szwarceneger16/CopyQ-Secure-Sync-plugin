# Standalone local storage in securesync

The ordinary `securesync` DLL/SO now owns an opt-in local encrypted checkpoint
through unmodified CopyQ 17 loader/saver callbacks. It does not require `host/`,
Synchronize, a service, Python at runtime, or a rebuilt CopyQ executable.
Installing the module requires restarting CopyQ to discover it.

This is still an experimental development build, not full synchronization.
Local encryption now has a separate password vault, key sharing, rotation,
backup/recovery and an explicit encrypted return to standard CopyQ storage.
See [key lifecycle and removal instructions](KEY-LIFECYCLE.md). Platform release
verification and synchronization remain separate gates.

## Explicit setup

1. Install the compatible `securesync` module and restart CopyQ.
2. In Preferences → Items → Secure Sync, choose a device ID, an existing transport
   with `events/`, and separate **dedicated empty private state and vault
   directories outside the transport**. An existing strict 32-byte K-SYNC file
   is optional: setup otherwise generates the shared key. Directories must
   already exist; permission and handle checks remain required.
3. Select **Use independent encrypted storage for synced_tray (experimental)**.
4. Click **Initialize empty standalone storage…** and confirm the displayed
   create-only operation and set a separate Secure Sync password. This operates
   on the selected draft; it does not save
   settings, migrate an existing tab, or start synchronization.
5. Apply the profile, then create a new empty `synced_tray` tab. Existing nonempty
   models are refused, so an existing ordinary tab is not silently migrated.

An advanced fixture may instead call `plugins.securesync.initializeStorage()`
after the profile is saved. The public script object forwards to CopyQ's standard
`callPlugin` server callback. `Initialized` means create-only provisioning succeeded;
a repeated call is refused. Loading/saving never invokes provisioning.
Opening the plugin/settings starts no background synchronization or state writes.

Settings schema 3 adds `vault_directory`. Schemas 1 and inspection-only 2 can
upgrade their settings; standalone schema 2 requires explicit local migration
with its original key. Unknown schemas are preserved/refused. Neither passwords
nor key bytes enter QSettings. The nonsecret `host_cache_file` setting records
the actual public QFileDevice path for interrupted handoff verification.

## Persistence contract

A binding hashes length-framed device, fixed tab, transport, key-file and private-
directory identities, plus the vault directory for schema 3. Its domain is
`CqsStandaloneStorageV2-<SHA256>`. A random device-local key authenticates the
ciphertext; K-SYNC is independent. Changes while the plugin owns a model are
deferred. Other profile changes invalidate existing savers rather than silently
retargeting them. Changing paths does not move/rebind encrypted files.

The handle-based `state::FileStore` supplies leases, atomic AEAD replacement and
readback on Linux and Windows/NTFS. The public saver and boundary checkpoints
remain synchronous durability barriers. Import/recovery transactions use a
worker and cancellable GUI dispatch; authorized manual state actions return an
operation token. See [runtime and cancellation](AUTOMATIC-SYNC.md).

The main record now uses schema 2: authoritative `local`, accepted remote `head`,
pending import/recovery and K-SYNC identity in one bounded encrypted record.
Ordinary saves retain history/journal metadata and require the loaded generation.
Earlier local-only `cqs-storage` heads require explicit migration; they are never
treated as remote revisions. See [shared state and manual operations](UNIFIED-STATE.md).

Only after private commit, authenticated readback and full model/epoch comparison
does the saver write CopyQ's 80-byte cache marker: `CQSLOC01`, 64 ASCII binding-hash
characters and an 8-byte big-endian generation. CopyQ owns the borrowed QIODevice
and its later commit. The plugin never commits a borrowed QSaveFile.

Loading restores the newest private snapshot, including with an older cache.
An absent cache can be reconstructed from existing private state. A cache newer
than private state, wrong binding/key, corrupt/missing record or insufficient tab
capacity is refused without resetting the private record. Unchanged snapshots do
not create another generation. No plaintext snapshot is exported to disk.
The configured tab stays claimed with invalid/unknown opt-in settings, so a failed
initializer cannot fall back to the default saver. Owned markers remain recognized
with opt-out/invalid settings, preventing an
ordinary loader from treating that marker as plain clipboard data. Direct disable
is deferred until explicit encrypted handoff. External deletion/configuration
cannot be fully controlled by the module; follow the removal procedure first.

## Data policy and guards

- Up to 10,000 ordered items; empty tabs, empty items and zero-byte fields differ.
- Up to 256 formats per item and 1,024 ASCII bytes per MIME name.
- At most 32 MiB of MIME names plus effective value bytes. Retained remote event
  packs have a separate 32 MiB ceiling and complete plaintext records are capped
  at 128 MiB, including journal/checkpoint copies. An import can be refused below
  the local ceiling when their combined record exceeds its budget. Local-only
  data no longer need a duplicated Base64 laboratory event.
- Text, HTML, URI lists, images, audio, other custom MIME and binary data are
  preserved as exact QByteArrays. MIME bytes are not normalized or interpreted.
- Normal plugin-owned saves remain byte-only and refuse `FILE:` names or custom
  QVariant values. Explicit native adoption and encrypted handoff recovery now
  use [bounded DataFile materialization](NATIVE-DATA-AND-PROTECTION.md), including
  content-address verification and frozen ciphertext decryption by CopyQ.
- Standard callbacks supply the exact tab identity/model, with GUI-thread/lifetime
  checks. A saver cannot write another model/tab or use a changed/disabled profile.
- Automatic cropping is refused. Over-limit saves retain prior private data.
- Initial restore requires an empty model and verifies its resulting full contents.

Visible remote import requires a verified bound public Qt view without an open
editor. Pinned and locked Tags rows are retained as exact protected anchors;
changes that would remove or modify them refuse before journaling or accepting
history. Unloaded imports apply the same protection policy.

## Verification

`native-standalone-storage` loads the actual main module through QPluginLoader and
exercises real private files, binary reload, hard interruption after private commit,
stale/missing cache, wrong keys, corruption, capacity, create-only setup, profile
changes, opt-out, nonempty models, larger-than-lab data, bounded DataFile migration/refusal, no arbitrary custom
converter execution and busy leases. It is mandatory on both CI platforms.

The full local Linux build includes 21 suites, including unified state, password-envelope and
key-vault tests and the historical host regression;
the main module no longer links that historical adapter. Default builds disable
that optional regression and do not prepare a patched host or require QCA for it.

The actual unmodified official CopyQ 17.0.0 AppImage (Qt 6.11.1) passed 17 session
checks for the **main** `securesync`: ordinary setup, encrypted binary checkpoint,
normal restart, SIGKILL/stale cache, missing cache, unrelated tab, Encrypt Tabs
enable/disable/re-enable and refusal of unencrypted handoff,
separate password change, local-key rotation, native CopyQ password change,
password expiry and both unlock dialogs, editor-safe unload refusal, other-plugin
refusal during handoff, interrupted native handoff, encrypted handoff and restart
with the plugin removed. All inputs were public disposable fixtures. The module
was built with Qt 6.10.3; CopyQ was never rebuilt.

```sh
python3 tests/run-standalone-copyq.py --storage main \
  --copyq /path/to/existing/copyq --plugin /path/to/libsecuresync.so \
  --out work/standalone-main-session
```

Use `--storage lab` with `libsecuresynclab.so` for the older isolated experiment.
For GUI lifecycle tests configure `CQS_BUILD_UI_TEST_PLUGIN=ON`, supply its
separate `libcqs-ui-driver.so` using `--ui-driver`, and add `--lifecycle` in a
disposable desktop session. The helper is excluded from install/packages.
Flatpak has a separate matching-SDK build and real installed-sandbox tests.
Neither the historical native results here nor a green model test certify it or
a Windows CopyQ process: consult the current [installation matrix](INSTALLATION.md)
and corresponding CI reports.

## First/next device and existing data

Manual Seed, Join with a protected local archive, and guarded adoption from a
preserved ordinary CopyQ tab are integrated. See [device setup](DEVICE-SETUP.md)
for step-by-step setup and the explicit Python 0.1.1 fresh-profile transition.
These setup commands do not merge data. Subsequent edits use the separate
[publication and automatic synchronization commands](AUTOMATIC-SYNC.md).
