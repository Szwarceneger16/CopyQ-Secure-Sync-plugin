# Transactional import and recovery coordinator

`src/import_transaction.{h,cpp}` implements the C++17 import/recovery state
machine over two explicit ports: `Store` and `Clipboard`. It is linked into
`cqs-core` and tested using the real authenticated event reader/history graph.
It adds no runtime library, worker process, Python dependency or system service.

**Status:** the main standalone plugin integrates the coordinator with the
[schema-2–6 unified record](UNIFIED-STATE.md). Manual Join/FastForward/recovery
uses a checkpointed, ordinarily unloaded tab and detached authoritative contents.
Automatic imports also use this coordinator on a worker, with cancellable
GUI dispatch for guarded live-model access. Seed/publication, protected adoption,
automatic scheduling and explicit conflict merges are integrated; see
[automatic sync](AUTOMATIC-SYNC.md) and [conflicts and history](CONFLICTS-AND-HISTORY.md).
The optional patched-host bridge is retained only for historical regression
coverage; the shipping module uses standard CopyQ callbacks and its own record.

The patched-host Clipboard port described below is retained only in historical
regression tests. The main module now uses [standalone local storage](STANDALONE-STORAGE.md)
and does not depend on that port. Schema 1 retains the historical independent
Clipboard persistence contract below. Schema 2 commits authoritative `local`
with the pending journal before its readback barrier, then atomically accepts
the head and retires the journal. Active-editor-safe live replacement remains
unimplemented; public unload provides the current manual integration guard.

## Import sequence

`importTip(authenticatedHistory, Join|FastForward)` acquires a private-state lease
and reads the authoritative record. A pending transaction blocks a new import.
Join requires an explicitly initialized, unjoined record and an empty local tab.
FastForward requires an existing head and unchanged local MIME data.

The authenticated history must have exactly one tip. The accepted head must
still be present, its event metadata/payload must be unchanged, and it must be
an ancestor of the incoming tip. Conflicting tips are not silently resolved;
an absent head is not interpreted as a new device. An unchanged tip returns
`UpToDate` without writes. Missing parents are already rejected by the reader.

For an incoming tip the coordinator performs these steps:

1. Decode packed items into detached effective MIME bytes, applying limits.
2. Prepare a private record containing the previous checkpoint, full original
   snapshot and target event/snapshot. Commit it durably BEFORE touching CopyQ.
3. Replace the bound tab only if both its contents and mutation epoch still
   match the captured view; active editors must cause refusal.
4. Persist through CopyQ's normal encrypted item store and reload actual durable
   MIME bytes. A successful in-memory edit alone does not satisfy this barrier.
5. In ONE private-record commit, advance the checkpoint and retire the journal.

Any exception stops the operation. There is deliberately no catch-all that
blindly rewrites the original tab: the user may have added data after the failure.
A store failure can happen before OR after a durable write. Recovery reloads
state rather than assuming which side of the write the exception represents.
An edit after the durable clipboard barrier remains a local edit against the
accepted checkpoint and blocks a later incoming import; it is not discarded.

## Explicit recovery

`recover()` reads only the local pending record and the bound tab. It needs no
online Nextcloud connection and does not rerun Join or Seed.

| Action | Required state and behavior |
| --- | --- |
| `AcceptTarget` | Import phase and the full target already visible; persist/reload/verify it, then commit the checkpoint without inserting items again. |
| `RetryImport` | Import phase and current contents equal the original or target; finish the guarded replacement and durable verification. |
| `RestoreOriginal` | Current contents equal original or target; first commit the Restore intent, then restore/verify the original and keep the prior checkpoint. |

Once Restore intent is committed, AcceptTarget/RetryImport cannot change that
decision after a restart. A repeated Restore finishes the same rollback.

If current data match NEITHER original nor target, all three modes refuse to
write and retain the journal. This includes manual post-failure edits and some
partially applied multi-item writes. Native authoritative storage now offers
explicit `PreserveAndRetry` and `PreserveAndRestore`: a bounded encrypted backup
is committed and all projected record sizes are checked before replacement.
See [conflicts and history](CONFLICTS-AND-HISTORY.md). Historical schema-1 ports
still refuse divergent data. Merely matching the number of items is never enough. Empty snapshots,
including rollback to an unjoined empty tab, are supported.

## MIME equality, not pack() equality

`Snapshot` is an ordered vector of maps from MIME name to binary bytes. Map
insertion order is irrelevant; item order, MIME presence, zero-length values,
NUL bytes, CRLF and all other bytes are significant. No text normalization or
lossy encoding conversion occurs in the coordinator.

The Clipboard adapter must decode full effective MIME data without writing a
tab and must reject unsupported QVariant representations, not stringify/drop
them. It must validate bounds DURING decode/capture before returning allocated
objects. The coordinator checks the returned values too. Its ceiling is 10,000
items, 256 formats per item, 1,024 ASCII bytes per MIME name and 32 MiB of MIME
names plus value bytes per snapshot. These are byte/count limits, not an RSS
cap; several original/target/checkpoint copies can coexist. Smaller budgets
are accepted. Returned snapshots are plaintext in memory and must not be logged.

Remote packed bytes are retained only to detect mutation of an already accepted
remote event. They are NEVER compared to locally repacked bytes. Changing a
remote payload under the same ID is rejected even if it decodes equivalently.
The accepted-head comparison also works in historical schema-1 ports. Native
schema-6 records additionally retain fingerprints of observed ancestors and
unaccepted branches. This
cannot establish global freshness against events never delivered to this device.

## Required production adapters

### Store

- Provision a private binding identity tied to device, tab, K-SYNC and selected
  transport. Never reuse it after changing any of those; validate it on load.
- Acquire a cross-process exclusive lease for the whole operation. Busy callers
  must fail/defer, not block the CopyQ GUI indefinitely.
- Authenticate/bound a single encrypted record containing head and optional
  pending transaction together. There is no window between updating a separate
  head file and removing a separate journal file.
- Compare-and-swap the complete expected record and monotonically increment its
  generation. Commit atomically and durably before returning; ambiguous failures
  may leave the old or new record, never an invented empty initial record.
- Keep records and keys outside the cloud folder. Do not serialize Snapshot
  plaintext to disk. Use a distinct AEAD domain/subkey for private records,
  nonce discipline and safe handle-based I/O. Migration from Python 0.1.1 state
  is NOT implicit and is not implemented here.

### Clipboard

- Bind to exactly one validated tab and marshal operations to the proper Qt
  thread. Maintain a non-reused epoch across mutations, including ABA edits.
- Compare epoch + full snapshot in the same guarded mutation operation. Refuse
  locked tabs, unresolved editors and any unsupported data rather than forcing
  an unload or silently flattening data.
- Implement a real persistence/reload barrier through the encrypted CopyQ store.
  Do not implement `persist()` as `capture()` or an arbitrary timer delay.
- Do not launch an independent Python agent or write plaintext exports.

The coordinator does not itself encrypt/serialize private records, generate a
key, reserve an event sequence, publish local changes, create merge events,
watch folders or retry in the background. It accepts a freshly authenticated
history snapshot; that is not a guarantee against remote replay/withholding or
changes after scanning. The future runtime must serialize scans and operations,
recheck history as needed and retain its own freshness/equivocation policy.

## Tests

```sh
./tests/run-transaction.sh
CXX=clang++ ./tests/run-transaction.sh
CXX=clang++ SANITIZE=1 ./tests/run-transaction.sh
```

The same suite is registered as `transaction` in CTest. The standalone script
uses a temporary executable and no user's CopyQ, keys, folders or state. Test
histories use real AES-GCM authentication/decompression/DAG construction with a
public test key. Test packed tokens are NOT real Qt serialized items. The MIME
adapter and durable store are explicit in-memory fault models, never production
fallbacks.

The suite covers 42 named scenarios, including empty Join/empty remote snapshots,
MIME preservation, dirty local state, accepted-head mutation, conflicts, epoch
races, active editors, wrong durable readback, explicit retry/restore and schema/
binding limits. It injects an interruption at each of 13 import boundaries and
12 restore boundaries, both retaining and discarding simulated volatile clipboard
state (50 combinations). It checks state after constructing a new Importer.

These tests validate state-machine ordering and decisions under the port
contracts. They do NOT validate Windows CNG/Win32, a Qt MIME adapter, real disk
fsync/AEAD record encoding, a live CopyQ restart or a complete native sync cycle.

Design background (not linked dependencies): SQLite's atomic-commit description
<https://sqlite.org/atomiccommit.html>, and Qt's QSaveFile atomicity/fallback
contract <https://doc.qt.io/qt-6/qsavefile.html>. A generic file-save API alone is
not a substitute for the required private-store and CopyQ durability adapters.
