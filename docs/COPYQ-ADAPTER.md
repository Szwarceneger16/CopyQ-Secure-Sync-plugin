# CopyQ packed MIME and model adapter

`src/packed_items.{h,cpp}` decodes remote packed items into the coordinator's
ordered MIME snapshots. `native/model_clipboard.{h,cpp}` implements its
`transaction::Clipboard` port for an explicitly supplied Qt list model.
Both are built and tested. `HostClipboard` is now a historical test-only adapter
for the [adapted host](COPYQ-PERSISTENCE.md); the main module does not link it.
[Standalone local storage](STANDALONE-STORAGE.md) instead binds through standard
loader/saver callbacks. The main runtime now uses `GuiClipboard` to dispatch only
model capture/preflight/replacement to the GUI while the import coordinator
performs its encrypted transaction/readback in a worker. Epoch, editor, profile
and cancellation checks span those calls. See [runtime](AUTOMATIC-SYNC.md).

## Packed items

CopyQ 17's `pack()` returns one `serializeData(QVariantMap)` stream, not the
whole-tab serialization. The event contains Base64 strings for these individual
streams. Our decoder reads big-endian Qt 4.7-compatible lengths, UTF-16 MIME
names and binary QByteArrays without invoking CopyQ's deserializer or QVariant
converters. It accepts the current `-2` stream and the deprecated nonnegative
format. DEK-encrypted `-3` streams and unknown versions are rejected.

The compressed MIME dictionary matches the pinned CopyQ source. `4`, `8plain`
and `0text/plain`, for example, all decode to `text/plain`. Prefix selection in
CopyQ uses an unordered map, so raw packed bytes are not an equality test for
local content. Duplicate **effective** MIME names are rejected even if their
wire abbreviations differ. Snapshot comparison uses item order, MIME presence
and exact value bytes; empty tabs, empty items and zero-byte fields are distinct.
Qt NULL QByteArrays are effective zero-byte fields.

The decoder rejects `FILE:` names in both formats before processing the field's
value. It never opens a remote-supplied local file, imports a DEK or instantiates
arbitrary QVariant types. Effective names must satisfy the existing ASCII MIME
policy. Canonical Base64, stream lengths, compression flags, format counts,
truncation and trailing bytes are checked. qCompress framing has an advertised
length and a bounded zlib stream; mismatches, empty compressed output and trailing
zlib bytes fail closed. Decoding does not normalize payload text or binary data.

The transaction limits apply during decoding: at most 10,000 items, 256 formats
per item, 1,024 bytes per MIME name and 32 MiB of names plus decoded values.
Callers may lower them. Packed Base64 input also has the v1 event plaintext
ceiling of 32 MiB across all items. These are logical byte/count budgets, not an
RSS promise; compressed input, detached output and transaction backups coexist.

## Model operations and guards

The constructor takes a specific `QAbstractListModel`, never a window title or
an implicit current tab. `QPointer` detects model destruction. Model operations
require the application's main Qt thread and refuse structural transitions or
reentrant adapter calls. Signal-driven process-wide epochs are never reused
across adapter instances. Data edits, resets, layout/row changes and ABA edits
invalidate earlier views. Signal callbacks do not throw on epoch exhaustion;
subsequent operations are refused permanently.

Capture reads `contentType::data` as an exact QVariantMap. Values must already
be QByteArrays: convertible strings, CopyQ DataFile objects and other custom
types are rejected **without calling their converters** in normal storage capture.
Explicit preserved-tab adoption supplies the audited bounded
[native reader](NATIVE-DATA-AND-PROTECTION.md) instead. MIME/count/byte limits
are applied before copying to the C++ snapshot. Returned snapshots are detached
plaintext in memory; they must not be printed or exported to disk.

The default model port still refuses custom QVariant values. The optional
`HostClipboard` installs a bounded `readSnapshot` port so the adapted host can
materialize its own native encrypted DataFile values. That host path checks
content-addressed bytes and size limits; the legacy host adapter never calls a converter or
opens a blob path. The standalone native reader is separate and uses only
registered Qt metatype callbacks on frozen checked ciphertext. Remote FILE references remain rejected during pack decoding.

`HostClipboard` installs `ModelAccess` callbacks bound to that same tab:

- `readable()` validates availability and access, including locked-tab state.
- `writable()` additionally rejects active editors and other unsafe writers.
- `persistAndReadback(view, limits)` performs the real encrypted CopyQ save and
  returns bounded, detached MIME data reread from its authoritative storage.

Missing access callbacks deny operations. Missing persistence denies replacement
**before the first row is removed**, even though replacement itself is volatile.
Callbacks may not mutate the view to authorize a stale operation; epoch checks
detect their side effects. All desired QVariant maps are validated and allocated
before deletion, and the original epoch plus complete snapshot must still match.
The adapter checks normal Qt model notifications, pinned row indexes, empty
inserted rows and the final exact snapshot. It stops on unexpected edits or
model failures rather than continuing to overwrite them.

Replacement failures can leave a partial model. It does not blindly restore
the original or erase intervening edits; the coordinator's durable prepare
record must precede replacement and retain recovery information on failure.
Model APIs cannot make a multi-row operation atomically durable by themselves.

Persistence checks the epoch/content before and after its callback and requires
the returned durable snapshot to match. `capture()`, a successful `unload()`,
`saveUnsavedItems()` without a reported outcome, an arbitrary delay or an in-
memory copy do not satisfy this contract. CopyQ's browser unload path does not
expose the required confirmed disk result, so no such fallback is installed.

## Executed tests and remaining integration

`packed-items` has 25 portable scenarios, including 10,000 deterministic input
mutations. `tests/run-packed-items.sh` also supports `SANITIZE=1` for ASan/UBSan.
`native-model-clipboard` has 26 Qt scenarios using the **actual pinned CopyQ**
ClipboardModel, ClipboardItem and serialization sources. It compares decoded
data against real unencrypted `pack()` output and real Qt QDataStream prefixes,
then tests guards, ABA, destruction, thread refusal, conversion refusal,
replacement, wrong readback, reentrancy and partial failure/edit preservation.

Upstream support is compiled into the test executable only, with QCA disabled;
the test's data-directory seam fails if ordinary fixture pack() tries to access
a filesystem path. Synthetic persistence callbacks and a fault model are
explicit test ports, not production durability implementations. They do not
test encrypted CopyQ disk save/reload, live profile restarts or power loss.

Both suites are required by the Linux and Windows native CI gate. Linux local
Qt 6.10.3 build/tests and decoder ASan/UBSan/LeakSanitizer passed during this
change. The hosted workflow result for the exact commit determines MSVC/NTFS
validation; test preparation alone is not a successful Windows run.

The historical host extension supplies exact-tab lifecycle/access binding and the
[encrypted CopyQ storage barrier](COPYQ-PERSISTENCE.md) for its regression tests.
That bridge remains test-only. The main external module uses public callbacks
and its own worker/GUI dispatch, authoritative record and cancellation path.
