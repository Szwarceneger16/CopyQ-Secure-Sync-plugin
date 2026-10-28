# One authoritative encrypted synchronization record

The main `securesync` module now uses record schemas 2/3/4/5/6 in the existing
`record-v1.cqr` AEAD container. CopyQ's 80-byte tab file remains a cache marker.
The plugin uses standard CopyQ 17 callbacks; it does not patch/rebuild CopyQ,
run a daemon. [Opt-in automatic synchronization](AUTOMATIC-SYNC.md) uses a standard CopyQ action.

## Fields and identity

One atomic record contains:

- `local`: the authoritative ordered MIME snapshot, including local edits.
- `head`: the last accepted, authenticated synchronization event and its decoded
  snapshot; absent until explicit Join. Local saves never advance this field.
- `pending`: an import target, the original snapshot and Import/Restore intent.
  Ordinary local saves retain this journal and backup, including divergent edits.
- `witnessed`: schema-6 semantic fingerprints of all observed history, including
  ancestors and unaccepted branches; retained across saves and recovery. See
  [conflicts and history](CONFLICTS-AND-HISTORY.md).
- `generation`: a local 64-bit CAS revision, independent of protocol-v1 device
  sequences. It is never turned into a synthetic synchronization event.
- `binding`: the existing hash of device, fixed `synced_tray`, selected transport,
  raw-import path, data directory and vault directory.
- `keyIdentity`: SHA256 of `CopyQ-Secure-Sync-key-identity-v1\0` followed by the
  actual 32-byte K-SYNC. This is authenticated inside the encrypted record and
  checked against the unlocked vault key on every native read/write.

The random local key encrypts the record; it stays distinct from K-SYNC. Changing
profile paths does not move/rebind data. Unsupported schemas, a wrong context,
missing/corrupt state or unsafe permissions refuse load instead of creating an
empty profile. Existing settings schema 3 and the key-vault wire format remain
unchanged. See [keys and recovery](KEY-LIFECYCLE.md).

The optional Windows publication-staging path is deliberately outside this
binding: it only controls where an already encrypted event is prepared for its
same-volume atomic move. Correcting it must not orphan the record, vault or a
reserved ID. It is checked before new reservations and again at publication;
changing it while a model/operation owns the profile requires the normal stop
and unload guards. Existing profiles keep using the private data directory.

Schema 1 remains supported by the generic codec for historical transaction tests
and key vaults/transfers, but main local storage requires schema 2. The new codec
adds the local snapshot and a bounded 64-byte lowercase hex key identity after
the existing head/journal fields. Schema 3 additionally retains an independent allocated sequence, exact encrypted
publication intent and optional preserved local snapshot. It is upgraded by an
explicit Seed, adoption or preserved Join; older schema-2 records remain readable.
The schema is inside the authenticated payload;
schema-1 frozen vectors remain byte-for-byte unchanged. Unknown/mixed schemas,
trailing data, malformed identity and oversized snapshots are rejected.

## Explicit migration

Earlier standalone snapshots used a reserved `cqs-storage` event for local
numbering. Use **Secure Sync: migrate local checkpoint to unified state** from
CopyQ's command menu, with other item plugins disabled and the tab unloaded.
It authenticates the vault and old record, preserves the exact snapshot in
`local`, clears that artificial head, attaches K-SYNC identity, and advances
the local generation once in a whole-record CAS. It never declares the old
local counter to be an accepted remote version.

Retry is idempotent if a complete schema-2 record already committed. Failure
does not reset data; process interruption leaves a complete old or new record.
Reload through CopyQ's normal load button or restart after migration if a
previous failed load left the tab locked. Keep a usable encrypted backup before
upgrading; older plugin versions cannot read record schema 2. Close other old
CopyQ/plugin instances before migrating. The older raw-K-SYNC experiment uses
its separate explicit migration and now writes schema 2 directly. Python-state
migration is a documented manual transition. Changing key/transport/private
paths together is now handled by the journaled [history transition](HISTORY-TRANSITIONS.md).

## Manual Join, import and offline recovery

Disable other item plugins temporarily. The generated CopyQ commands use public
`show()` to actually load the bound tab, switch to an existing other tab when
available, checkpoint committed contents, and call ordinary `unload()`.
`tab()` alone only sets script context. Unload refusal stops the operation;
no forced unload, editor closing or arbitrary timer implements this guard.
The callback independently refuses an owned model, checks current plugin
inventory, rejects a changed authorization/profile epoch, authenticates the
vault and claims the private profile before doing disk work.

**Join authenticated history (empty tab)** accepts one complete authenticated
tip only when no head exists and local contents are empty. Empty history does
not Seed a device. **Import next history tip** requires a clean joined snapshot,
the immutable old event still in history and one descendant tip. Conflicts,
withheld/changed heads, missing parents and dirty local data refuse the import.
Import never selects an automatic winner or merges branches; publication is a separate guarded operation.

The worker acts on detached contents of the authoritative record, never on a
loaded GUI model. Under one record lease it:

1. Durably commits the target/backup journal while retaining the previous head
   and local contents.
2. Commits target local contents in the same encrypted record, still retaining
   the old head and journal, then authenticates the durable readback.
3. Atomically accepts the new head and retires its journal. CopyQ reloads exact
   local bytes through its normal plugin loader afterward.

Each intermediate record is complete and can be restored without trusting a
newer GUI view or a CopyQ delayed-save timer. The final head/journal update is
one CAS commit, not separate files. If a post-publication flush/recheck fails,
the result is unconfirmed: either complete record may exist. Explicit reload
and recovery inspect it; no catch-and-rollback or automatic empty initialization
is used.

Recovery commands are **accept pending target**, **retry pending import** and
**restore pending original**. They need only the private record and keys, so
they work offline with transport unavailable. Accept requires target local
contents already present. Restore first commits its decision, which cannot be
switched into accepting the target after interruption. Divergent later edits
remain in `local` and block ordinary recovery. The explicit **preserve new edits
and retry/restore** commands retain an encrypted backup before replacement. Explicit conflict choices, encrypted backups and resolution recovery are
described in [automatic sync](AUTOMATIC-SYNC.md).

## Concurrent processes and local saving

The profile gate `.cqs-session.lock` uses the same handle, ownership/ACL,
no-follow and nonblocking OS lock checks as the record lease. A loaded plugin
model holds this lease for its lifetime. Other native processes cannot load or
mutate the same private profile until it is unloaded; kernel exit releases it.
Disk-only operations hold it through authorization/scan/transaction. Their
short record lease remains distinct; a Session lease cannot authorize record I/O.
Key rotation and explicit setup respect the same gate. Read-only state inspection
can still authenticate the record under its short record lease.

Each bound model also retains the generation it loaded. Saving/checkpointing
must match that generation before changing local contents, in addition to
whole-record CAS. A stale model refuses a save instead of overwriting a newer
record. Successful checkpoints and local-key rotation update its expected
generation. Ordinary local writes change only `local`/generation and preserve
accepted history, pending intent and backup. These are cooperative process
guarantees, not isolation from a compromised process with the user's keys.

Local-key rotation preserves the whole schema-2 record, including accepted head
and pending recovery, instead of repacking it as a laboratory event. Encrypted
handoff/removal refuses a pending import until recovery is resolved.

## Budgets and release boundaries

The local ceiling remains 10,000 ordered items, 256 MIME formats/item, 1,024 ASCII
bytes/MIME name and 32 MiB of effective MIME data/names. The complete plaintext
record is capped at 128 MiB, including repeated accepted/target/backup snapshots
and event packs. Imports can therefore be refused below the per-snapshot ceiling
when their combined record exceeds it. Local-only saves no longer duplicate
their contents in a Base64 laboratory event. Native DataFile adoption uses bounded content-addressed materialization; missing
or unsafe files refuse. Arbitrary file references and custom converters are
not silently read, dropped or normalized. Pinned/locked Tags checks precede
import journaling in both loaded and unloaded paths.

Import/recovery disk transactions run in a worker with cancellable GUI model
dispatch. Authorized manual state callbacks return operation tokens. Public
saver callbacks and boundary checkpoints remain synchronous atomic durability
barriers; no delayed CopyQ cache write is treated as confirmation.
Subsequent publication and an opt-in asynchronous automatic cycle are
implemented in [automatic sync](AUTOMATIC-SYNC.md). Live visible-tab updates, persistent opt-in scheduling and explicit multi-tip
resolution now use this same record. Automatic Python-state conversion remains unfinished. Manual first/next device
setup and the fresh-profile transition are described in [device setup](DEVICE-SETUP.md).
Matching native Windows GUI/Flatpak execution is required for each candidate;
see the current reports and [installation matrix](INSTALLATION.md).

`native-unified-state` is mandatory in both OS CI inventories. It tests real
private files, 15 subprocess exits across import commits, five migration exits,
restore-intent interruption, offline recovery, divergent-edit retention, shared-
key identity, rekeying a pending/joined record and cross-process profile exclusion.
An independent Python encoder/AES-GCM oracle supplies the frozen schema-2 vector.
Actual-module tests cover migration, stale models and the real scriptable object
with a public-API model for cold loading/editor refusal. A separate official
unmodified CopyQ 17 AppImage driver exercises authenticated Qt-packed Join,
FastForward, restart and dirty-edit refusal, alongside the existing lifecycle
tests. Only public synthetic fixtures are used; fixture tools are not installed
or packaged. These tests do not certify physical power loss or unexecuted platforms.

## Schemas 5/6 and live scheduling

Schema 5 appends up to four encrypted local snapshots and an optional sorted
list of tips confirmed by the user's conflict decision. It does not change
schemas 1–4 or the transport protocol. Archive restore swaps a selected backup
with current local contents; removal is explicit and rejects a stale record.
Pending resolution projection must match the accepted head and original backup.
Reservation checks both eventual projection phases against the total-record
ceiling before publishing. Older backups can be removed during a resolution;
its active last backup cannot be removed. Schema 6 appends the sorted, bounded
history witness index. Saves, key transitions and offline recovery retain it;
see [conflicts and history](CONFLICTS-AND-HISTORY.md) for downgrade constraints.

Workers prepare/deliver immutable events while GUI callbacks reserve/accept
state serially with local saves. Publication finalization retains edits made
after capture. Live replacement uses the same prepare/local/readback/head
coordinator against the exact callback-owned model and public Qt editor guard.
A shared session lease excludes another process. Model loading is refused during
an import/state transaction; transport-only workers retain the existing loading
behavior. Ordinary imports and key/setup/handoff keep their explicit guards.
