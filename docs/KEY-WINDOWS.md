# Windows K-SYNC reader

`native/key_reader_windows.cpp` implements the same `readKeyStrict()` interface
as Linux. It reads an **existing** raw 32-byte K-SYNC key. It never generates a
key, changes permissions, creates files, accesses CopyQ's DEK or prints secrets.
It is compiled into the Windows core and is now used by the inspector together
with the [NTFS transport backend](STORAGE-WINDOWS.md). Inspection remains read only.

## Accepted storage and paths

Only an explicit drive-qualified path on a **fixed local NTFS volume** with
persistent ACLs is supported. UNC/network paths, removable drives, substituted
drives, device namespaces, alternate data streams, traversal, DOS device names,
ambiguous trailing dots/spaces/separators and malformed UTF-16 are rejected.
Ordinary Unicode, spaces and valid UTF-16 surrogate pairs are supported.
The syntax validator is shared with the private-state backend; syntax checks
alone do not authorize I/O.

The drive is resolved to a volume GUID before opening the chain. Every ancestor
is opened with `OPEN_REPARSE_POINT` and stays pinned without delete sharing.
Each handle must name an ordinary disk directory on that same volume. Symlinks,
junctions, mounted volumes, other reparse points and offline/recall entries fail
closed. A key directly in the volume root is not accepted.

The leaf must be an ordinary, single-link file with a size of exactly 32 bytes.
Its read handle denies write and delete sharing; an already-open incompatible
writer also prevents the read. `OPEN_EXISTING` is used for every open. There is
no path-based stream fallback and no automatic ACL repair.

## Ownership and permissions

Both the key and its immediate parent must be owned by the process user's SID
and have a non-NULL, protected DACL with a user grant. Allow rules may name only
that user, LocalSystem or Builtin Administrators. Other allow trustees, including
Everyone and inherited-only public grants, are rejected. Ordinary deny rules
are permitted; object, callback and conditional ACEs are rejected rather than
approximated. Inheritance-only user rules do not satisfy the user-grant check.
Read-only key permissions are sufficient. No thread impersonation is allowed.

Higher ancestors need safe pinned directory handles, not user-owned private
DACLs: a normal Windows profile path traverses system-owned directories. The
immediate parent must meet the strict policy independently of the file.
Selecting a broadly accessible key or folder reports failure and leaves its
permissions unchanged. Provisioning a compliant key remains an explicit task.

## Read and failure behavior

Name-to-handle identity, volume, attributes, leaf size/link count and leaf
write/change times are checked before and after reading. The two private DACLs
and process identity are rechecked too. Directory timestamps can change when
unrelated sibling files change; directory identity and attributes remain fixed.
A bounded 33-byte read verifies the 32-byte content and EOF. Any failure after
reading wipes the temporary buffer through RAII. On success the caller owns
exactly 32 bytes and must wipe them after use.

All rejected paths, ACLs and filesystem failures use the same fixed diagnostic
as Linux. No selected path, OS error details, trustee identity or key bytes are
included. This is not protection against an administrator or a hostile process
already running as the same user; sharing checks and rechecks do not establish
an atomic filesystem/security snapshot against that adversary.

## Native tests

`key-reader-windows` is a required CTest suite in the Windows CI gate. It uses
only synthetic byte sequences and disposable NTFS folders. Its scenarios cover
exact bytes, read-only access, Unicode, missing paths, unsupported path syntax,
wrong sizes, directory/symlink/hardlink rejection, public/unprotected/NULL ACLs
on the key and parent, impersonation, existing writers, writes/deletes/renames
during a pinned read, ACL changes after read, late failure cleanup and repeated
success/error handle counts. Test hooks are compiled only into the test target.
Symlink setup failure fails the suite; it cannot return success by skipping.

The source and tests must be compiled with MSVC and executed by the real
Windows/NTFS job. Linux core/native tests verify regression safety only and do
not prove Windows I/O behavior. Consult the workflow for the precise commit's
result; no Flatpak or complete runtime synchronization claim follows from it.

Primary APIs: Microsoft's `CreateFileW`, `GetVolumeNameForVolumeMountPointW`,
`GetVolumeInformationByHandleW`, `GetFileInformationByHandleEx`, `GetSecurityInfo`
and `ReadFile`. No additional runtime library is introduced.
