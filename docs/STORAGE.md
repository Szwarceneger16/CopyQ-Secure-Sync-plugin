# Transport directory I/O

`storage::Directory` connects an existing, user-selected local folder to the
v1 authenticated event reader. This batch implements `src/storage_linux.cpp`.
The public interface uses C++17, without Qt, Python or another CopyQ plugin.
It reuses the existing crypto/compression dependencies and adds no runtime
library. There is no UI, watcher, worker service or automatic sync in this layer.

This page describes the Linux backend (`O_PATH`, `O_TMPFILE`, procfs). The separate
[Windows NTFS backend](STORAGE-WINDOWS.md) now implements native handle scans and
publication with explicit private staging. Neither uses an `ifstream` or an
exists-then-write fallback. Live CopyQ/Flatpak runtime synchronization remains
outside these transport tests.

## Layout and selected root

```text
<selected-existing-root>/
  events/
    mint-lab/000000000001.cqs
    win-lab/000000000001.cqs
```

The caller supplies an absolute root path, not a value from a remote JSON
header. Both root and `events/` must already exist. Neither scanning nor
construction creates them. An unavailable mount/folder must not turn into a
new, empty history or trigger reseeding. Explicit first-time folder creation
belongs in the later setup UI. Other files at the root (e.g. a transport's
metadata) are not traversed; **every entry inside `events/` is accounted for**.

Root components are opened one by one with `openat`, directory/no-follow flags
and close-on-exec handles. `.` / `..`, NUL, relative roots, filesystem root,
oversized paths/components and symlinks at any component are rejected. Root
and `events/` identities remain pinned and are checked again for each operation.
Changing the selected folder means constructing a new `Directory`, not silently
retargeting an old handle. Ordinary Unicode and space-containing root names
are allowed. Device IDs and filenames use the strict portable v1 grammar.

The selected root, `events/`, device directories and event files must belong to
the effective user and must not be group/world writable. Ancestors can be
system-owned (e.g. `/home` or `/tmp`). Nested filesystem changes below the root
are rejected. Local filesystems are required: this is not a WebDAV/NFS adapter.
A user-configured symlink should be resolved explicitly by the future setup UI,
not followed implicitly by the worker. No filesystem permissions are loosened.

## Scan: all or nothing

1. Validate the K-SYNC length and reader limits even for an empty directory.
2. Enumerate sorted device/file names with budgets for every entry and device,
   including empty directories. No recursive walk, arbitrary nesting or following
   of paths from JSON occurs. A conflict copy, hidden leftover or unknown name
   blocks the scan; it is not skipped, renamed or deleted automatically.
3. Pin each event with `O_PATH|O_NOFOLLOW`. Check the inode before opening its
   contents: only a regular, single-link, user-owned file on the same filesystem
   is accepted. FIFOs, sockets, symlinks and hard links are rejected.
4. Account advertised sizes before allocating/reading content. Reopen only the
   checked inode via the kernel's `/proc/self/fd/N`, not the transport pathname.
   Bound reads to the recorded size plus a one-byte growth check.
5. Check inode, mode, owner, link count, size, mtime and ctime before/after the
   read. Authenticate all envelopes through `events::AuthenticatedHistory`.
6. Recheck every file handle **and its directory entry**, device directory
   timestamps, the device listing and the root path mappings before returning.
   Never return a partial graph on an error.

The procfs reference above is deliberately followed: it names our own already
checked file descriptor, not a symlink supplied by Nextcloud. Trusted procfs
must be available. Handles are released on exceptions and normal returns.

Defaults are 4096 directory entries, 128 devices, and the reader's existing
1000-event / 25 MiB per-event / 256 MiB aggregate wire ceilings. Reader payload
and decompression ceilings also apply. Budgets may be reduced, not increased.
Retained O_PATH handles consume file descriptors: exhaustion fails closed;
a later runtime may choose smaller limits to leave room for the GUI.

## Publication: no overwrite, no visible partial event

`publish(key, Envelope{expectedId, encryptedBytes})` accepts a **prepared encrypted
v1 event**, not plaintext items and not a new sequence to allocate. It copies,
validates and authenticates the exact bytes before any write. It then:

1. Creates only the authenticated device directory if necessary (mode 0700),
   checks its type/ownership/mapping, and syncs the `events/` directory.
2. Writes to an anonymous `O_TMPFILE` inode in that same device directory,
   mode 0600. No partial `.cqs` or named staging file is visible to Nextcloud.
3. Syncs the staged file and rechecks all destination mappings.
4. Atomically links **that inode** to the final name using `linkat`, which must
   fail if any destination already exists. If unprivileged `AT_EMPTY_PATH`
   is unavailable, the trusted procfs descriptor reference is used instead.
5. Syncs the containing directory and verifies the final name/inode and content
   metadata. No current event is truncated, replaced or unlinked, even if its
   bytes happen to be identical to the requested publication.

An exception before the link closes and discards anonymous staging. An empty
device directory may remain. A failure **after** the link reports
`PublishedUnconfirmed`: a complete final file may be visible although durability
or its final identity could not be confirmed. Do not delete it, advance the
local head or create another revision automatically. The future engine must
reconcile that exact ID/bytes against its pending transaction first.

The filesystem must support anonymous staging and hard linking. Unsupported
filesystems fail closed, without a named-tempfile or overwriting-rename fallback.
Successful fsync calls provide the OS/filesystem durability contract, not proof
against a storage device lying about flush completion.

The extra private-staging argument is for Windows only; Linux rejects a supplied
folder and never substitutes it for anonymous staging.

## Limits of this layer

Metadata rechecks are optimistic concurrency detection, **not** a transaction
across the entire directory. A new file can appear immediately after return.
Keep serialized engine operations and retained local heads/equivocation checks;
recheck before committing a CopyQ import. Authenticated files alone do not prove
freshness or prevent replay/withholding by a cloud service.

This code does not defend a compromised same-UID process or privileged attacker
who can manipulate the application's memory, descriptors or mount namespace.
Pinned directory handles prevent following replacement paths; concurrent directory
relocation can still leave a publication in the original pinned directory and
must be treated as an unconfirmed operation when detected. Do not claim sandbox
isolation or an atomic whole-history snapshot.

No API deletes transport files, stores a K-SYNC, opens a CopyQ profile, chooses
a conflict winner, reserves a sequence or changes sync state. Plaintext from
`scan()` is returned in memory by the existing reader and must not be logged.
Only ciphertext is written by `publish()`. Error messages do not echo file
contents, keys or attacker-supplied names. The v1 wire protocol is unchanged.

## Verification

```bash
./tests/run-storage.sh
CXX=clang++ ./tests/run-storage.sh
CXX=clang++ SANITIZE=1 ./tests/run-storage.sh
./tests/run-crypto.sh
```

The 44 scenarios use disposable directories and public repository fixtures.
They cover UTF-8 paths; symlinks, hard links, FIFOs and sockets; hidden/conflict
names; budgets; missing parents; authentication; inode replacement; growth,
truncation and same-size writes with restored mtime; late additions; root
relocation; permission checks; staging failure; unconfirmed publication;
200 rejected scans without descriptor leaks; and six two-process publication
races with a barrier after **both** files have been staged and synced.

Deterministic hooks are compiled only with `CQS_STORAGE_TESTING`. The script
also compiles the production backend without hooks. Post-link failure injection
checks error handling, not real power-loss behavior. Test results are not an
independent security audit. No real user's keys, tabs or transport are accessed.

## Primary API references

- [open / openat / O_PATH / O_TMPFILE](https://man7.org/linux/man-pages/man2/open.2.html)
- [linkat: no overwrite and anonymous-inode publication](https://man7.org/linux/man-pages/man2/link.2.html)
- [fsync: file and directory durability](https://man7.org/linux/man-pages/man2/fsync.2.html)

The Windows follow-up must use Windows guarantees rather than emulate POSIX
with unchecked path operations; see the official CreateFile reparse/sharing and
SetFileInformationByHandle/FILE_RENAME_INFO documentation.
