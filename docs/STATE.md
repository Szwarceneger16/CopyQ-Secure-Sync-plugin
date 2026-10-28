# Encrypted private transaction store

`state::FileStore` implements the existing `transaction::Store` port on Linux
and Windows/NTFS (see [Windows backend](STATE-WINDOWS.md)). The import/recovery
coordinator can use a real encrypted record on disk. The main native module also
uses this store for opt-in local snapshots and a password-protected key vault.
Manual unloaded-tab import/recovery is integrated through [unified state](UNIFIED-STATE.md);
manual Seed/adoption and an explicit fresh-profile Python transition are also integrated;
automatic runtime and conversion of Python metadata remain unfinished. The codec
is portable C++17 with platform crypto.

## One record, one commit

A single `record-v1.cqr` contains schema, binding, generation, accepted event and
MIME snapshot, and (if pending) the target, original snapshot and recovery phase.
Advancing a head and retiring its journal are a single atomic replacement.
Nothing writes separate plaintext backup or journal files.

The format is deliberately separate from remote `.cqs` events and from Python
0.1.1 `state.json`/`pending-import.json`. Existing histories, keys and Python state
must not be reset or implicitly migrated. `initialize()` requires an explicit
lease and an otherwise empty, already provisioned private directory; any old
state, orphan or unknown file blocks setup. A corrupt/missing record never
becomes an empty record through `load()` or `commit()`.

The setup/runtime must supply a validated private directory **outside** the
transport and a provisioned binding tied to device, tab, K-SYNC and transport.
FileStore checks path safety, not whether an arbitrary folder is synchronized by
some other application. The native profile validator enforces path separation;
it must remain in the eventual runtime. Constructor arguments do not cause an
import or create a missing directory. K-SYNC is supplied in memory by the caller;
FileStore never discovers, exports or writes a key file.

## Codec and authentication

Wire format: ASCII `CQSREC01` (8 bytes), a random 96-bit nonce (12 bytes), then
AES-256-GCM ciphertext and its 16-byte authentication tag. Each seal obtains a
new nonce from the existing operating-system-backed crypto implementation.
There is no nonce-from-generation or deterministic production option.

AAD is `CopyQ-Secure-Sync-private-state-v1`, including its terminating NUL,
followed by the 8-byte magic and the validated binding. This differs from event
AAD, so a remote event cannot be substituted as a private record. Domain
separation does **not** replace nonce uniqueness: all writers sharing K-SYNC
must use secure independent randomness and remain within the key's GCM usage
budget. This batch does not add automatic key rotation or claim nonce collisions
are mathematically impossible.

Plaintext has an exact binary schema. Schema 2 appends an authoritative local
snapshot and a 64-byte hex K-SYNC identity to the schema-1 fields; schema 1's
vectors stay unchanged. Schema 3 additionally appends the allocated outbound sequence, optional
publication target and exact encrypted envelope, and optional preserved snapshot.
Older schema-1/2 vectors stay unchanged. Local generations are independent of remote sequences.
Integers and lengths are unsigned 64-bit
big-endian; presence flags and phase are one byte, restricted to 0/1. The record
contains schema, a length-prefixed ASCII binding, generation, optional head and
optional pending data. Each head encodes revision ID/device/sequence/parents,
original event plaintext length, ordered opaque base64 items and effective MIME
snapshots. Each snapshot is an ordered item list of lexically sorted MIME maps.
Length prefixes precede raw bytes; no Unicode, newline or NUL normalization is
performed. `Import=0`, `Restore=1`. Unknown schemas/flags, trailing bytes,
duplicate/unsorted MIME keys and malformed revision metadata are rejected.

Decoding authenticates before parsing. Limits are checked before allocating
variable-length fields. The default aggregate plaintext-record ceiling is
128 MiB, including repeated checkpoint/backup content; callers may only lower
it. Existing 10,000-item, 256-format/item, 1,024-byte MIME-name and 32 MiB/snapshot
ceilings apply, with 32 MiB of packed bytes per head. The wire ceiling adds only
36 bytes. These are byte/count budgets, not a process RSS guarantee. Large
snapshots may exceed the aggregate budget and are refused before any file change.
There is no compression in the private format and no decompression stage.

`serialize()`/`parse()` are memory-only codec APIs. Their buffers are plaintext
and must never be logged or written. The disk adapter calls only the authenticated
wire path. Temporary plaintext byte buffers and the store's key copy are wiped
on destruction; this does not guarantee erasure of every STL allocation, swap,
core dump or snapshot copy. Returned records necessarily contain plaintext in
memory. Semantic pack-to-MIME consistency remains the Clipboard/coordinator's
responsibility; codec validation is not a CopyQ item-import authorization.

## Password protection and explicit transitions

The optional `Protection::Password` envelope uses `CQSVLT01`, a random 16-byte
salt, big-endian 600,000 PBKDF2-HMAC-SHA256 iterations, random 12-byte nonce and
AES-GCM tag, with 56 bytes of overhead. Its complete header extends the AAD;
the mode is explicit with no fallback. Parameter/size rejection precedes KDF.
Existing key-mode vectors remain unchanged. See [vault contract](KEY-LIFECYCLE.md).

`initialize(record)` creates a complete initial record, while
`checkInitializable()` performs the same create-only metadata check without a
write. Both require a lease. `transition(expected, replacement, newSecret,
newProtection)` verifies whole-record CAS and exactly one generation advance,
then atomically changes credentials and/or binding. It updates in-memory
credentials only after confirmed replacement; an unconfirmed post-publication
failure requires reopening with old/new credentials, never a rollback write.
These are explicit setup/migration operations, not ordinary remote import.

## Linux paths and leases

The directory must be user-owned mode 0700. Lock and record files must be
single-link, user-owned regular files of mode 0600. Every absolute path component
is pinned with no-follow directory handles. Relative paths, traversal, symlinks,
FIFOs, devices, sockets, unexpected ownership/permissions and file hardlinks are
rejected. Existing files are pinned using `O_PATH` before content access and
reopened via trusted `/proc/self/fd`, not a transport-supplied symlink.

`.cqs-state.lock` is a permanent, empty lock inode. It is never unlinked on normal
release. A new open-file description plus `flock(LOCK_EX|LOCK_NB)` excludes other
instances and processes; contention returns no lease. A try-lock operation gate
also refuses same-instance contention without waiting for ongoing disk work.
Load/commit/setup require the acquiring thread's active lease. Inherited leases
cannot authorize operations after fork, and a child's lease destructor must not
explicitly unlock the parent's shared open-file description. Lease lifetime can
safely exceed the FileStore facade's lifetime.

Run I/O in the plugin worker, **not** on the GUI thread. Owning operations still
perform disk reads/fsync, which can wait for the storage device. There is no
arbitrary I/O deadline. Releasing a lease from a different thread can wait for
an in-flight owner operation; callers must not fork concurrently with a call.
The internal operation gate intentionally covers I/O and protects lease lifetime.

## Compare-and-swap and failure behavior

`commit(expected, replacement)` reloads and authenticates the current record
under the lease and compares its complete canonical encoding with `expected`,
not just its generation. Binding/schema/content mismatches cannot be treated as
a successful CAS. Generation must advance exactly once without wrapping.

The replacement is validated and encrypted in memory, then written into an
anonymous mode-0600 `O_TMPFILE` inode in the same directory and fsynced. Setup
links it directly to the final name without replacing anything. An update links
it to a random private staging name, checks the old and staged inodes, then
atomically renames that staging name over the expected record. The new inode
and parent directory are synced before success is returned. File types,
ownership, sizes, link counts, ctime/mtime, names and directory mappings are
rechecked. Failed filesystems do not trigger an unchecked I/O fallback.

Before the final link/rename, failure leaves the old record intact (or no record
for setup). Afterwards, failure is `CommitUnconfirmed`: the authoritative name
may already contain the new record. Never delete it or assume rollback. Release
the lease, reopen/reload, and let explicit recovery inspect the actual state.
Temporary names are removed only while they still identify our staging inode.
Process termination may leave encrypted staging files; readers ignore them and
never promote them as authority. Automatic orphan cleanup is not implemented.

These guarantees assume cooperative users of the lease, trusted procfs and a
local filesystem implementing O_TMPFILE, hardlinks, atomic rename and fsync.
They do not defend privileged/same-UID process compromise. Metadata rechecks
are not an atomic transaction against arbitrary noncooperating local writers.
A renamed parent can invalidate a result after the operation took effect.
Authentication and generation do not prevent replay of an entire older valid
private directory by an attacker: an external monotonic anchor would be needed.
This record store alone does not establish remote-history freshness. The native
runtime additionally retains schema-6 fingerprints to detect changes or missing
files relative to previously observed history; see
[conflicts and history](CONFLICTS-AND-HISTORY.md).

## Executed verification and boundaries

```sh
./tests/run-state.sh
CXX=clang++ ./tests/run-state.sh
CXX=clang++ SANITIZE=1 ./tests/run-state.sh
```

The 47 named scenarios run against real disposable files and public synthetic
keys. They cover codec limits/authentication, 10,000 malformed/mutated plaintext
inputs, full-record CAS, cross-process and cross-thread contention, private path
attacks, inode replacements, ctime changes with restored mtime, 300 failed reads
without FD leaks, five process-termination boundaries, and before/after-rename
failures. Recovery exercises the **real existing Importer plus disk FileStore**
with a deliberately modeled Clipboard; no CopyQ persistence is claimed.

GCC and Clang release builds, Clang ASan/UBSan at O0, and a run as unprivileged
`nobody` are used. The script also compiles the Linux backend without hooks.
CTest registers the suite as `state` on Linux; complete native Qt/CMake and
Windows builds are separate checks. Tests do not simulate actual power loss,
prove hardware flush honesty, touch user profiles or certify production release
readiness. No CI workflow, runner activation or release is part of this batch.

API references: Linux [open/O_TMPFILE](https://man7.org/linux/man-pages/man2/open.2.html),
[flock](https://man7.org/linux/man-pages/man2/flock.2.html),
[rename](https://man7.org/linux/man-pages/man2/rename.2.html),
[fsync](https://man7.org/linux/man-pages/man2/fsync.2.html), and
[OpenSSL EVP AEAD](https://docs.openssl.org/3.3/man3/EVP_EncryptInit/).
