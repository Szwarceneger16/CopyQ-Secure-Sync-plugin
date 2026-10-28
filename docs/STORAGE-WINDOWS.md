# Windows transport on local NTFS

`src/storage_windows.cpp` implements `storage::Directory::scan()` and `publish()`
with native Windows APIs. The plugin's explicit **Inspect selected transport**
action now uses this backend and the Windows K-SYNC reader. The GUI remains
read only: publication is an API for the future runtime, not an enabled button.

## Paths and access policy

The selected root and `events/` must already exist. Only explicit drive paths
on fixed local NTFS with persistent ACLs are supported. UNC/device namespaces,
substituted drives, traversal and ambiguous components fail closed. The chain
is anchored to a volume GUID and stays pinned without delete sharing. Reparse
points, junctions, symlinks, nested volumes, offline/recall entries and special
files are rejected. Event files must have one hard link. Read handles deny write
and delete sharing, including an already-open incompatible writer.

Root, events, device directories and files must be owned by the process user's
SID and have a non-NULL ordinary DACL. Others may read ciphertext, including via
inherited rules, but write/append/delete/child-deletion, EA/attribute changes,
ownership and ACL changes may be granted only to the user, LocalSystem or Builtin
Administrators. Inheritance-only grants are checked too; object/callback rules
are rejected. This mirrors Linux's no-broad-write transport policy without
requiring protected ACLs on every file created by a sync client. No impersonation
or automatic ACL repair occurs. Ordinary system-owned ancestors remain allowed.

Private staging is stricter: a protected user-owned DACL with a user grant and
allow trustees limited to the user, LocalSystem and Builtin Administrators.
The backend does not defend a hostile administrator or process with this SID.

## Scan

Listings use `GetFileInformationByHandleEx` and independent handle cursors.
Variable-length records, names, offsets and duplicates are bounded and checked.
Every non-dot entry counts; unknown names, conflict copies, hidden leftovers and
unexpected types block the scan rather than being skipped. IDs come from strict
v1 filenames, independently of authenticated JSON headers.

Ceilings match Linux: 4096 entries, 128 devices, 1000 events, 25 MiB per event and
256 MiB aggregate wire data. Caller budgets may only be lowered. Even an empty
history checks key/reader limits. Sizes are accounted before allocation; chunked
reads check the recorded size and EOF. All files stay pinned through history
authentication/validation. No path-only enumeration or `ifstream` fallback is used.

Before returning, every file identity, size, link count, write/change time and
DACL is rechecked, along with device directories, events and the root chain.
The full name inventory is independently re-enumerated with the same budgets;
directory timestamps alone are not a namespace snapshot. No partial graph is
accepted on failure. Missing parents defer history, and conflicts retain all tips.
These checks detect changes but do not promise an atomic snapshot or freshness
against replay/withholding. Runtime imports still require serialization/rechecks.

## Publication

Windows requires an explicit fourth argument:

```cpp
directory.publish(key, encryptedEnvelope, readerLimits, privateStagingFolder);
```

The staging folder must exist outside the transport, not contain it, have the
private ACL policy and reside on the same volume. Overlap is checked with pinned
directory identities and ancestor chains. No TEMP/profile/key-path guess or
implicit setup is used. Linux rejects this option and keeps anonymous O_TMPFILE.

The native plugin supplies its optional `publication_staging` setting, falling
back to the private data directory for existing profiles. The configured folder
must also be separate from the vault. This allows local data on C: with transport
on D: by selecting a private staging folder on D: outside Nextcloud. Neither
the vault nor the record needs to move. `checkPublicationStaging()` performs
the same directory/volume/ACL/overlap checks and requests file-creation access
without creating any file or device directory. The plugin calls it before
allocating a new event ID. Publication repeats those checks; preflight does not
guarantee future availability. Correcting this auxiliary path leaves the record
binding unchanged and permits retry of the same reserved ciphertext.

The exact envelope is copied and authenticated before anything is created.
Only its authenticated device directory may be created. A random CREATE_NEW
ciphertext file is written/flushed with WRITE_THROUGH in private staging;
its type, size, mapping and permissions are checked before publication. The
cloud folder never contains this partial staging file.

`MoveFileExW(MOVEFILE_WRITE_THROUGH)` moves within that NTFS volume without
REPLACE_EXISTING or cross-volume copy flags. Only a complete final `.cqs` becomes
visible. Existing names are never overwritten, even for identical bytes. The
retained handle must identify the moved file; final mapping/DACLs are rechecked
and the file is flushed again. No sequence/head/state changes occur here.

Pre-move cleanup deletes only this operation's own staging handle. A confirmed
existing-destination rejection also permits cleanup. Other move errors and any
post-move failure report PublishedUnconfirmed: reconcile that exact ID; never
delete a possibly published event or blindly allocate another sequence. Process
interruption can leave private encrypted orphans, which are not scanned or
automatically deleted. An empty device directory may remain.

The move's source pathname is in a protected **non-cloud** namespace. Ordinary
outside principals cannot swap it, and ancestors are pinned. This is not same-SID
hostile-process isolation. Windows success means WRITE_THROUGH move, file flushes
and final identity checks completed, not POSIX directory fsync, an administrative
whole-volume flush or physical power-loss certification.

## Native tests

`storage-windows` is required in CI and has 27 NTFS scenarios: missing/Unicode
paths, unsafe entry types/names, ACL policy, budgets, authentication/ancestry,
conflicts, sharing, late changes, impersonation, private staging, publication,
cleanup and unconfirmed moves. Three subprocess interruption boundaries and
three two-process races after both ciphertexts are staged/flushed exercise real
Windows operations. Repeated reads check handle counts. Symlink setup failure
fails the suite; scenarios cannot silently return success by skipping.

`native-inspector` adds nine Qt worker/key/transport scenarios on both OSes,
including busy controls, missing parents, conflicts, fixed diagnostics and
awaited shutdown. All fixtures/keys/folders are synthetic or public and disposable.
The workflow for the exact commit determines Windows/MSVC/NTFS verification;
Linux success is not Windows I/O verification. Native import remains gated by
the separate [CopyQ persistence barrier](COPYQ-PERSISTENCE.md).

Primary APIs: [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex),
[MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw),
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
