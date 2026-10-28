# Verified CopyQ host persistence

Historical experiment: the production requirement is an installable module
for unmodified CopyQ 17. This patched-host design is superseded as a product
direction. The current main module uses [independent storage](STANDALONE-STORAGE.md)
and [the native release contract](RELEASING.md). All host-specific requirements
and configuration-only limitations below describe the historical test adapter,
not the installed product.

`host/` implements an optional CopyQ 17 host extension and
`native/host_clipboard.cpp` connects it to the transaction Clipboard port.
The plugin's `transformSaver()` binds only the exact `synced_tray` model received
from CopyQ and returns the original saver unchanged. This does not change the
item-loader ABI/IID or replace Encrypt Tabs. Vanilla CopyQ remains usable for
configuration/inspection, but does not expose this persistence capability.

## Host integration

`host/prepare.py` exports the pinned clean CopyQ source into a separate disposable
directory, applies `copyq-17.patch` and copies the extension sources. It never
patches the dependency checkout or a running user installation. See
[host build instructions](../host/README.md).

ClipboardBrowser creates a GUI-thread `PersistentTab` before the actual factory
loads/initializes its saver. The model carries a QPointer to a versioned Qt
interface; binding checks the full tab ID, exact model and endpoint lifetime.
Rename, capacity change, unload/destruction, disabled storage, locked encryption
or an active internal/external editor refuse replacement. Disabling the sync
plugin retires its adapters. An unknown saver/wrapper also refuses replacement
before the first row is removed.

The initial supported storage chain is CopyQ's native default saver with global
**Encrypt Tabs** enabled and its host DEK unlocked. GPG/itemencrypted and other
storage plugins are not silently decoded as native storage. The default saver
is factored into `NativeTabSaver` with identical normal serialization and a
separate quiet readback path. The DEK stays inside the host.

## Confirmation sequence

1. Check bounded effective MIME content, exact model revision and access guards.
   Host and plugin both reject ABA changes and structural transitions.
2. Save the bounded, normalized MIME snapshot with the actual native encrypted
   saver into a private temporary file in the authoritative tab directory,
   hashing all bytes actually written. Normalization avoids an unbounded lazy
   DataFile converter during serialization; the live model is rechecked.
3. Check serialization, flush and OS disk synchronization. Qt 6.10's own
   QSaveFile::commit() ignores the result of its internal syncToDisk call, so
   that call alone cannot supply this barrier.
4. Recheck model, saver and guards before the commit attempt. Linux uses the
   owning QSaveFile commit followed by directory fsync. Windows uses an owning
   QTemporaryFile, closes its checked/flushed handle and calls MoveFileExW with
   REPLACE_EXISTING and WRITE_THROUGH, then flushes the installed file handle.
   No borrowed saver callback device is committed by the plugin.
5. Reopen authoritative storage, bound its size and require its SHA256 to match
   exactly the ciphertext generated in this call **before** deserializing it.
6. Decode with the same native serializer and host key into a detached bounded
   model. This path cannot initialize a missing tab, crop items, transform a
   saver, migrate storage, ask about corruption or modify the live model.
7. Require complete ordered effective MIME equality, EOF, unchanged host
   revision/guards and unchanged plugin epoch/content. Only then may Importer
   retire the encrypted journal and advance the head.

Native external DataFile values are materialized by the host without arbitrary
QVariant converters. Reads bound the ciphertext/plaintext sizes and verify the
normal content-addressed path against its bytes. Import readback also confirms
blob flushes and, on Linux, all newly created blob-directory ancestors. Windows
blob publication uses the same write-through helper. Ordinary capture opens
blobs read only. Remote pack() FILE references remain rejected.

A precommit failure leaves the old authoritative tab file. Any failure after
an attempted commit is unconfirmed: the new file may already be installed and
the coordinator must retain its journal. There is no blind rollback or deletion
of the final file. Windows may retain an encrypted temporary orphan after a
failed native move. Missing or substituted authoritative storage is refused.

## Validation and boundaries

`native-host-persistence` uses the actual QCA-enabled CopyQ encryption and
serializer, real disk files, native OS flush/rename operations and encrypted
CQS FileStore. Configuration paths alone are redirected to disposable fixtures.
It also loads the actual plugin and tests its host binding. Failure hooks cover
write/flush/sync/commit/readback stages; a real rename failure and hard child
process exits before/after commit exercise failure and restart recovery.
Large encrypted blobs, binary/empty items, access/lifetime/capacity guards, ABA,
unsupported savers, missing/substituted files and preservation of manual edits
are required scenarios. Missing QCA/provider is a failure, never a skip.

Both CI platforms compile the modified browser, item factory and itemstore
sources in addition to running the bridge suite. This is not a full CopyQ GUI
end-to-end build/session or physical power-loss certification. Windows guarantees
are checked native file flushes and write-through moves on the tested local
NTFS; Linux additionally confirms directory fsync. Hardware/cloud-provider
durability promises are outside this test.

The UI remains configuration/inspection only. Native state provisioning,
migration and the runtime that coordinates worker I/O with GUI-thread imports,
publication and explicit recovery still need integration. The persistence port
and exact-model binding now exist for an adapted host; a standalone DLL/SO cannot
add the required host cooperation to an unmodified CopyQ process.
