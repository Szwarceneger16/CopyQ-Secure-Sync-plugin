# Windows NTFS private-state backend

`src/state_store_windows.cpp` implements the same `state::FileStore` interface
as the Linux backend: lease, authenticated load, explicit initialization and
whole-record compare-and-swap. CMake selects it on Windows 10/11. It is **source
implementation awaiting a Windows SDK build and real NTFS execution**, not a
claim of validated Windows support or a released plugin.

This change does not implement Windows transport scanning, K-SYNC file loading,
CopyQ imports, setup UI actions or automatic synchronization. The native panel
remains read-only. There is no dependency on Python or Synchronize; it uses the
existing CNG/record codec and Windows system libraries Kernel32/Advapi32.

## Existing format, separate OS operations

`record-v1.cqr`, `CQSREC01`, AEAD domain separation, generation, binding and
checkpoint/pending/backup encoding are unchanged. Both backends call the same
`seal`, `unseal` and `serialize`. AES-GCM on Windows uses the existing BCrypt
backend. A format roundtrip is not a disk-durability test. Do not copy one
computer's bound record to another profile or migrate Python state implicitly.

The caller supplies a provisioned private directory OUTSIDE the synchronized
transport, a validated profile binding and a 32-byte key in memory. No key is
read from a file by this backend, stored in settings, printed or sent to a
process. Record encryption occurs before opening staging. Only ciphertext is
written; comparison byte buffers and the retained key use the existing wipe API.

## Path and permissions contract

The public path is an absolute drive-letter path such as
`C:\Users\name\AppData\Local\CopyQSecureSync\native-state`. Separators may be
forward or backward slashes. UNC, device/extended namespaces, relative paths,
ADS colons, reserved DOS names, dot traversal, trailing dots/spaces, invalid
UTF-16 and excessive path length/depth are rejected before opening.

Resolve the drive to its volume GUID and perform subsequent opens under that
stable namespace. Only a fixed local NTFS volume with persistent ACLs is
accepted, not FAT, SMB/WebDAV, removable or substituted drives. Every directory
component is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and inspected. Ancestor
handles are retained without `FILE_SHARE_DELETE`, preventing ordinary rename
while the store exists. No junction, symlink, mount point, offline placeholder
or other reparse point is followed. Other supported local filesystems require
separate guarantees/tests; there is no unchecked fallback.

The selected directory and files must be owned by the current process user and
have a **protected, non-null DACL**. Conventional allow ACEs may grant only that
user, LocalSystem and Builtin Administrators. There must be an effective user
grant. Broad user/group grants, inherited-only privacy, callback/object/conditional
ACEs and unsupported ACL forms fail closed instead of being approximated.
Existing permissions are never broadened or silently rewritten. Setup must
provision these ACLs explicitly; a normally inherited AppData folder is not
itself the dedicated state directory. Impersonated calls are refused.

Created files get an explicit owner and protected DACL. All handles are
non-inheritable. Files must be ordinary single-link disk files on the pinned
volume. Root mappings, ACLs, lock identity and file IDs/metadata are rechecked.
Read handles deny write/delete sharing. Access to metadata and already-created
memory mappings is not isolated by share flags; this is not protection against
an administrator or a hostile process running under the same user SID.

## Leases and CAS

The stable `.cqs-state.lock` file must be empty, private, non-reparse and
single-link. It is never truncated or removed. `LockFileEx` acquires an exclusive
one-byte range with `LOCKFILE_FAIL_IMMEDIATELY`; locking beyond EOF is allowed.
Contention returns no lease. The handle denies delete sharing during the lease,
preventing replacement of the lock file. Process exit releases it.

A mutex and owner thread/process checks enforce the public lease contract.
Another thread cannot use the owner's lease. A lease can be destroyed by a
different thread, serializing its close with any active operation. No handle
is inherited by subprocesses. Load does not reset a missing or damaged record.

Commit authenticates and compares the **entire** expected record under that
lease and demands an exact generation increment. It does not compare just a
counter or trust unauthenticated bytes. Initialization is explicit/create-only
and refuses existing records, legacy state or unknown files in the directory.

## Replacement and durability boundary

1. Seal the complete replacement in memory with a fresh nonce.
2. `CREATE_NEW` an unpredictable private ciphertext-only staging file in the
   same pinned directory. Never use `CREATE_ALWAYS` or truncate the final file.
3. Write all bytes, `FlushFileBuffers`, then recheck staging/old record/lease.
4. Close the old non-delete-sharing read handle immediately before replacement.
   The OS lease serializes cooperating writers across this interval; it is NOT
   an atomic filesystem CAS against a hostile same-SID writer ignoring the lease.
5. Move with `MOVEFILE_WRITE_THROUGH`, adding `MOVEFILE_REPLACE_EXISTING` ONLY
   after successful CAS. No `COPY_ALLOWED`, cross-volume, reboot or delete-first
   fallback exists. Initialization omits replacement, so an existing name wins.
6. Flush the still-open new file handle and verify the final name, file identity,
   metadata, private ACL and lease before reporting success.

An error before the move leaves the old record intact. Cleanup uses our own
staging handle, not an untrusted filename. Before attempting the move, cleanup
is disabled: a false return or post-move verification/flush error is conservatively
`CommitUnconfirmed`. The final record is NEVER deleted by rollback cleanup.
Release the lease and reload authenticated state before deciding what happened.
A definite create-only collision is `AlreadyInitialized`.

Crashes can leave private `.tmp` ciphertext. It is never promoted to an
authoritative record and is not synchronized. Existing-record load ignores it;
initialization refuses a directory with such leftovers. This layer neither
selects an orphan winner nor discards user state to get past an error.

**Flush boundary:** Windows uses the documented write-through move and file
flush requests, not Linux `fsync(directory)`. The code does not attempt an
administrator-only volume flush or silently ignore a failed requested flush.
Microsoft's explicit `MOVEFILE_WRITE_THROUGH` copy/delete guarantee must not be
presented as a universal POSIX namespace-durability guarantee. Crash/power-loss
validation on the supported NTFS/Windows/storage stack is still a release gate.
The existing hook label `DirectorySynced` marks completion of the Windows
post-move file flush; it does not mean a directory handle was flushed.

## Tests and actual verification status

Portable **path syntax** checks ran on Linux: 52 checks passed with GCC, Clang
and Clang ASan/UBSan. They do not exercise Win32 permissions, filesystem or locks.
The available clang Windows-target SDK probe failed on missing `windows.h`;
there is no Windows SDK, cross-compiler or Windows/Wine runtime in this working
environment. The backend and `state-windows` suite have NOT been compiled/run.
No prior Linux test result is represented as Windows validation.

`tests/state_windows_test.cpp` provides native tests for provisioning/reopen,
private ACLs, wrong key/binding, corrupted records, budget checks, full CAS,
thread/process leases, hardlinks/symlinks, protected reads, failures before/after
publication and process termination at five write boundaries. Subprocesses use
only disposable paths and the public test key; handles are not inherited.
Symlink tests explicitly report SKIP without Developer Mode/privilege. Other
failures, including a non-NTFS temporary volume, are not masked as passes.
This tests process termination, not real power loss or live CopyQ.

Build in a Windows x64 toolchain with the existing zlib dependency available:

```powershell
cmake -S . -B build-win -DCQS_BUILD_NATIVE_PLUGIN=OFF -DBUILD_TESTING=ON
cmake --build build-win --config Release --parallel 2
ctest --test-dir build-win -C Release -R 'state-(codec|windows)|windows-state-path' --output-on-failure
```

Normal CMake builds also compile the production backend without test hooks.
`CQS_STATE_TESTING` is defined only on the separate test executable, as for Linux.
No workflow is started by this change and the self-hosted runner stays untouched.

## Primary API references

- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex
- https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew
