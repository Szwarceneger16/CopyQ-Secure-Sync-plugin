# Native builds and real-platform tests

`Native build and tests` runs on pushes to `main` and on pull requests. Feature
branches run through PR updates only, avoiding duplicate push/PR builds for the
same head. `workflow_dispatch` is declared too; GitHub exposes its manual UI once
the workflow exists on the default branch. All jobs use GitHub-hosted runners,
with `contents: read`, no custom secrets, no persistent shared PR cache and no
`pull_request_target`. The private runner is not used or enabled.

## Actual native build, not just core tests

Both jobs configure `CQS_BUILD_NATIVE_PLUGIN=ON` and `BUILD_TESTING=ON` and compile
`libsecuresync.so` / `securesync.dll`. They execute every CTest suite, including
Qt settings and `QPluginLoader` tests. The staged module is loaded a second time
before that exact file is packaged. A missing SDK is a failure, not permission
to skip the native build.

`ci/check-tests.py` validates the test inventory and JUnit. Required native/OS
tests must exist, have executable commands, and not be disabled or skipped.
Even a Windows executable that returns 0 after printing SKIP fails this gate.
`Native CI gate` requires both native platform jobs, installed Flatpak GUI, and source/DEB/strict-Snap installation acceptance. Python unit discovery validates native gate, host-export, installation and
release/package acceptance/rejection contracts. It runs on both platforms,
including host-export regressions for an export nested under an enclosing Git repository,
a clean CRLF checkout and exclusion of untracked local files.
The Windows inventory also requires `key-reader-windows`: real NTFS key/ACL,
sharing and rejection tests. A missing or skipped key-reader suite fails the
gate alongside `state-windows` and the native module tests.
Both inventories also require `packed-items` and `native-model-clipboard`.
The latter compiles the actual pinned CopyQ model and serializer into a test
executable and validates effective MIME equality, access/epoch guards and
synthetic persistence-port decisions. It does not certify live encrypted
CopyQ disk persistence. `native-inspector` is also required on both platforms,
and Windows additionally requires `storage-windows` for real NTFS reads,
publication, subprocess interruption and two-process no-overwrite races.
Both platforms now require `native-host-persistence`, which uses actual
QCA-enabled CopyQ encryption, serializer and disk storage, plus the CQS encrypted
state backend. Missing QCA/provider fails the suite. The build also compiles the
modified CopyQ browser/factory/itemstore sources; it never patches the clean
dependency checkout. QCA 2.3.10 and Qt Core5Compat are SDK dependencies only;
the plugin does not link QCA. Native migration forwards the registered metatype's
opaque DEK envelope transiently in memory, with wiped stream buffers; it never
reads CopyQ key files or persists that native key. Windows builds its pinned
OpenSSL test dependency with the same MSVC/CRT. There are 22 required CTest suites on each platform, including
`native-standalone-storage` for the main module and `native-standalone-lab` for
the original laboratory. The latter loads the actual separate module and exercises encrypted checkpoint storage, unload/reload
and child-process interruption with unchanged CopyQ model/API sources. The
legacy host suite is historical coverage, not the accepted installation design.
See [standalone experiment and actual process tests](STANDALONE-PROTOTYPE.md).

## Windows: native VM with NTFS

`windows-2022` provides the Windows Server 2022 kernel, VS 2022 and Windows SDK.
The script selects x64 MSVC, installs pinned Qt 6.10.3 and builds pinned zlib with
the same toolchain/CRT. TEMP/TMP must be on fixed local NTFS. Developer Mode is
enabled only in the disposable runner VM so symlink tests actually execute.

This is not a Windows Server Core container or Wine. A Linux container mounting
NTFS does not implement LockFileEx, DACLs, Windows sharing flags or reparse-point
behavior. Native executables test the real Win32 backend, including subprocess
termination. Windows 11-specific GUI and physical power-loss behavior are not
covered by this Windows Server VM. Moving Linux builds to WSL later does not
provide a Windows kernel; keep a hosted Windows job or a separate Windows VM.

## Linux: restricted offline build container

The SDK container uses Ubuntu 24.04 x86_64, pinned by image digest, plus Qt 6.10.3
and its matching ICU archive. SDK/dependency preparation uses the network. The
actual build/test/container run is unprivileged with `--network none`, read-only
root and source mounts, no capabilities and no Docker socket inside it. Only
the output mount and disposable /tmp are writable. Resource limits bound memory,
processes, CPU and descriptors; /tmp supports the Linux storage tests' O_TMPFILE.

The image identity and build logs are retained. The container command can later
be adapted to the private runner, but must not run untrusted PR code directly on
a persistent trusted host. The Linux artifact targets native Ubuntu 24.04 ABI,
not all Ubuntu versions or Flatpak automatically. A matching Flatpak SDK/load
test remains necessary; this pipeline never changes the user's host glibc.

## Dependencies and artifacts

Action invocations and CopyQ/zlib checkouts are pinned by full commit SHA.
`ci/toolchain.json` pins Qt 6.10.3, aqtinstall 3.3.0, CopyQ 17 and zlib 1.3.1.
The public Qt downloader retains archive verification. Python is a build/test
helper only; it is not a runtime sync daemon. Qt is provided by the matching
CopyQ installation and is not included in plugin ZIPs.

This is not a bit-reproducible release environment: apt updates, hosted runner
images and transitive Python dependencies still evolve. Fully hashed dependency
locks and release attestation remain later hardening work.

Scoped reports and JUnit survive failures for 7 days. Only a successful job
uploads its module ZIP, build metadata, license notices and SHA256SUMS (14 days).
The package excludes SDKs, tests, fonts, temporary state, keys and profiles. The build workflow creates no GitHub Release. The package is the main native
synchronization product with independent storage, publication/import, automatic
scheduling, conflict recovery and key/history transitions. Successful builds do
not certify the remaining product acceptance/performance gates.

Versioned ZIP inventory, member checksums, embedded module version, compatibility
and third-party notices are validated by `ci/distribution.py` and its rejection
tests. The separate [release workflow](RELEASING.md) only promotes exact binaries
from a complete successful current-main run. It verifies native JUnit, installed
GUI/Nextcloud reports and strict Snap confinement, adds exact corresponding
sources, combined checksums and release provenance, and defaults to preparation
without publication. PR artifacts cannot become releases through this workflow.

`native-unified-state` requires actual encrypted files and subprocess exits
during import/migration, offline recovery and profile-session locking. It runs
on each platform; a skipped/missing suite cannot pass the gate. GUI/process
integration inside an existing CopyQ remains a separate installed-host check.

## Validating CI on the public repository

The CI status for the exact current commit is the acceptance evidence.
Older builds from the private development repository are not a substitute
for a fresh Linux, Windows, Flatpak and installation test run in this
repository. The new repository does not inherit historical Actions runs.

## Primary references

- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container
- https://aqtinstall.readthedocs.io/en/latest/cli.html
- https://learn.microsoft.com/en-us/cpp/error-messages/compiler-warnings/compiler-warning-level-1-c4530
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex

`native-standalone-storage` is also required on both OSes. It tests the main module;
legacy host regression is explicitly enabled only in CI, not linked into that module.
Normal packages no longer include host patches.

## Installed GUI gates

Windows additionally verifies the SHA256 of official `copyq-17.0.0.zip`, runs its
existing executable with our DLL and exercises visible bidirectional updates,
unlock-only restart scheduling and conflict dialogs. A fixture-only public Qt
module drives synthetic dialogs; it is never installed/packaged for users.
Each Windows server is in a kill-on-close Job and its disposable profile has a
protected user/SYSTEM/Administrators ACL. These are native Windows GUI processes,
not Wine. No CopyQ application rebuild is performed.

The separate Flatpak job uses installed Flathub CopyQ 17 and KDE SDK 6.10. It
checks the app version/runtime, records their installed identities, compiles only
our module and fixture targets inside that SDK, and runs the same GUI cycle under
Xvfb. Folder permissions are scoped to public test reports and the module folder;
no permanent filesystem override or host glibc update is made. A different future
application/runtime fails instead of silently certifying a mismatched package.
The matching Flatpak ZIP is generated for the installed GUI test and uploaded
only after it passes. Windows and Flatpak test the archive checksum, private
installation, stopped-process replacement, restart with unchanged encrypted
state/vault, explicit native encrypted handoff, module deletion and byte-exact
reopening in stock CopyQ. This covers replacing the current package, not every
historical binary version or interruption boundary.

Linux additionally runs `ci/test-nextcloud.sh`: official CopyQ 17 AppImage,
four audited bundled renderers, two separate transport roots, actual
`nextcloudcmd` desktop clients and a disposable pinned Nextcloud server. Its
Docker network is internal, with no public ports. The fixture records versions,
event hashes and delivery logs, including offline resume and explicit conflict
resolution. No real account, key or clipboard data is used. See [Nextcloud](NEXTCLOUD.md).

## Installation-specific acceptance

`tools/install.py` admission tests cover version/Qt/OS/CPU/compiler mismatches,
Flatpak SDK isolation, Snap common-data paths, independent profile suggestions
and package integrity. These unit tests do not replace the installed-host tests.

The shared GUI harness now probes public CopyQ info and, for package tests,
stages the module through CopyQ itself, verifies its bytes, restarts with that
module and continues the full data/key/conflict/removal cycle. Windows runs it
separately against the checksum-pinned official portable ZIP and setup.exe.

The installed Flatpak also has a separate default-namespace test without
COPYQ_* directory overrides or host download-folder grants. It checks that
ungranted host files stay unreadable, transfers the module through stdin into
provider-supplied persistent XDG_DATA_HOME, restarts and verifies the actual
plugin slot. Separate public marker bytes also verify persistence/access for
both suggested private state/vault directories. This catches older Flatpak
versions whose writable default CopyQ XDG state path is ephemeral across
sandbox invocations; no extra host permission is used to mask the issue.
The existing full GUI test keeps its explicitly scoped synthetic directories.

`Linux / source + DEB + strict Snap / system Qt 6.4` compiles the plugin with
Ubuntu 24.04's system Qt, independently of the Qt 6.10 SDK. It compiles a pinned,
unmodified stock CopyQ 17 **test host**, tests its source installation, removes
only the disposable fixture prefix, installs a generated DEB with dpkg and tests
it separately. These hosts are never included in the plugin artifacts. This
validates the installation mechanism, not a claim about every distro's package;
for example the observed noble PPA still contained CopyQ 13/Qt5.

A separate strict core24 Snap fixture packages that same clean host with the
provider-reported Qt plugin directory and dpkg-reported QCA providers. Runtime
dependencies are collected from ldd on those explicit build assets. The
launcher retains all reported dependency directories, including private
subdirectories such as libproxy's backend, rather than assuming two lib roots. snapd
creates the real namespace; the job requires strict confinement and connects
only the fixture's declared x11/desktop/home interfaces and network-bind for
CopyQ's local GUI/CLI socket server. Its writable profile
parent is obtained through `snap run --shell` and SNAP_USER_COMMON, never guessed.
A declared read-only Snap layout exposes the clean host's compiled resource
prefix; the host is built with normal system-QCA support, not AppImage's
bundled-provider mode. Snap launch preserves the real user-systemd bus/runtime for cgroup tracking;
it is not wrapped in a private bus without a user manager. No devmode/classic
fallback is allowed. The actual GUI test is independent of
the source/DEB tests. This is a fixture, **not certification of an unnamed Store
Snap**. A missing runtime, failed confinement or GUI failure fails the final
gate. The tested system-Qt module ZIP is uploaded only after all three pass;
CopyQ fixture DEB/Snap applications are not published. Reports retain separate
source, DEB, Snap and Flatpak default-installation results.
