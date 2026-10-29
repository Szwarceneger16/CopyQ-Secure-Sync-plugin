# CopyQ Secure Sync

Native, GPL-3.0-or-later CopyQ plugin for encrypted synchronization of a selected tab through a local synchronization folder.

The native module runs without a Python agent, system service or dependency on the CopyQ Synchronize plugin. Qt and the CopyQ plugin ABI remain required.

**Installation requirement:** users must be able to add the module to an existing
CopyQ 17 installation without patching or recompiling CopyQ. The previous optional
host extension is not the accepted production architecture. The original
[standalone storage experiment](docs/STANDALONE-PROTOTYPE.md) tests a separate
module using the existing loader/saver API and an encrypted private checkpoint.

The main `securesync` now has [opt-in standalone local storage](docs/STANDALONE-STORAGE.md),
with explicit setup and standard loader/saver callbacks. A separate password
protects independent local and shared keys; see [key lifecycle](docs/KEY-LIFECYCLE.md)
for sharing, rotation, backup and encrypted removal. A [unified record](docs/UNIFIED-STATE.md)
now connects local contents, accepted history and recovery, with explicit unloaded-tab
Seed/Join/import. [Subsequent publication and opt-in automatic synchronization](docs/AUTOMATIC-SYNC.md)
are integrated, including selected visible-tab updates, persisted opt-in startup,
editor guards and explicit conflict choices with encrypted local backups.
[Conflict recovery and history protection](docs/CONFLICTS-AND-HISTORY.md) include
preserving post-crash edits, durable history witnesses and safe capacity limits.
[Installation and compatibility](docs/INSTALLATION.md) use CopyQ-reported paths and in-sandbox module staging, without searching user folders. Separate acceptance targets cover source, DEB, AppImage, installed Flatpak and a strict Snap fixture; Store Snap certification requires a named compatible package.
The [native settings panel](docs/NATIVE-SETTINGS.md) integrates device/recovery
actions, live status with local-save evidence and explicitly copied redacted diagnostics.

## Guided setup design (not implemented)

The [stage-1 device trust design](docs/DEVICE-TRUST-DESIGN.md) specifies future
peer-verified pairing, two-device approval after one-time bootstrap, equal device
authority and explicit recovery. The [installer and wizard contract](docs/GUIDED-SETUP-DELIVERY.md)
preserves existing CopyQ encryption and normal advanced settings. The
[acceptance matrix](docs/DEVICE-TRUST-ACCEPTANCE.md) records implementation gates
and planned tests; it is not evidence that these features already work. Current
RC installation and manual key transfer remain unchanged.

## Build and test pipeline

**Native build and tests** uses GitHub-hosted runners: an Ubuntu 24.04 SDK
container for Linux and a Windows Server 2022 VM with real local NTFS and MSVC.
Both compile the actual Qt 6.10.3 plugin, run the core and native Qt tests, then
load the installed module again before packaging it. See [CI setup](docs/CI.md).

The workflow runs on PR updates and pushes to `main`; feature branches are not
also built on push. The final **Native CI gate** requires Linux, native Windows, installed Flatpak, and the separate source/DEB/strict-Snap fixture checks.
Diagnostics/JUnit are uploaded even after failures. Successful jobs produce separate native Linux, system-Qt Linux, Windows and Flatpak artifacts containing the synchronization module, version, changelog, compatibility/license notices, build metadata and checksums.
The native version is **0.2.0-rc.1**; `VERSION` is authoritative.
The [release workflow](docs/RELEASING.md) promotes exact tested artifacts after
all current-main CI gates pass and adds corresponding sources. Preparation is
the default; publication is explicitly requested. Stable releases additionally
require the outstanding product qualification evidence.

The private self-hosted runner is not used or enabled. No repository secret,
write token or user profile is passed to tests. Pipeline execution for a specific
SHA is the source of truth; older documents include their original authoring-time
validation notes. The first actual builds already exposed SDK/flag/fixture bugs
that are fixed without disabling their tests.

## Incremental implementation

- **Crypto core:** AES-256-GCM backends (Linux/OpenSSL and Windows CNG),
  bounded zlib decompression and regression/interoperability tests.
- **Revision history:** C++17 graph validation, ancestry, stable tips and explicit
  conflict detection. Missing remote parents defer sync; malformed histories are
  rejected. See [the integration contract](docs/HISTORY.md).
- **Authenticated event reader:** bounded v1 JSON/base64 decoding, authenticated
  header and payload, and graph construction only after every event verifies.
  See [the reader contract and limits](docs/EVENTS.md).
- **Linux transport directory:** handle-pinned bounded scans and anonymous-staged
  publication without overwriting an existing ID. See [storage](docs/STORAGE.md).
- **Windows transport directory:** bounded NTFS handle scans and publication from
  explicit private staging outside the cloud folder, with no-overwrite moves.
  Optional staging on the transport volume supports private data on another
  drive; invalid staging refuses before reserving a new ID. The read-only
  inspector runs on Windows too. See [NTFS transport](docs/STORAGE-WINDOWS.md).
- **Native frontend:** registration, real file/folder choosers, isolated settings
  and authenticated read-only inspection in a plugin-owned worker. The native
  build uses pinned CopyQ ABI sources, not other plugins. See [settings](docs/NATIVE-SETTINGS.md).
- **Import/recovery coordinator:** guarded MIME replacement, durable prepare/commit
  ordering and explicit retry/restore over adapter interfaces. Its historical CopyQ
  adapter is now test-only; runtime integration must use plugin-owned storage. See [transactions](docs/TRANSACTIONS.md).
- **CopyQ MIME/model adapter:** bounded pack() decoding and guarded Qt model
  operations, tested against the actual pinned CopyQ model and serialization.
  The main module uses callback-bound models and independent encrypted checkpoints.
  The earlier [host extension](docs/COPYQ-PERSISTENCE.md) is retained only for regression tests. See [adapter contracts](docs/COPYQ-ADAPTER.md).
- **Unified state and manual import:** one atomic local/head/pending record,
  actual shared-key identity, explicit legacy migration, process/session exclusion,
  guarded unloaded-tab Seed/Join/FastForward, preserved-tab adoption and offline recovery.
  See [first device, Join and Python transition](docs/DEVICE-SETUP.md).
- **Key lifecycle:** password-protected vault, separate device-local/shared keys,
  encrypted transfer/backup, atomic password change, recoverable local-key rotation,
  explicit legacy migration and encrypted handoff to stock CopyQ.
- **Encrypted state:** common AEAD record codec, Linux disk Store and independent
  frozen vectors. See [state](docs/STATE.md) and [codec tests](docs/STATE-CODEC-TESTS.md).
- **Windows private state:** NTFS handles, protected ACLs, process leases and
  write-through replacement. Native Windows tests run in CI, not in a Linux
  filesystem emulation. See [Windows guarantees](docs/STATE-WINDOWS.md).
- **Windows K-SYNC reader:** volume-anchored NTFS handles, private owner/DACL
  checks, bounded 32-byte reads and required native regression tests. It is used
  by Windows UI inspection. See [key loading](docs/KEY-WINDOWS.md).

Offline scripts remain available in `tests/run-*.sh`. Native widget/loader tests
need a matching Qt SDK (Linux 6.4+, Windows 6.10+) and the pinned CopyQ 17 checkout. QCA is required only for the
optional historical host regression, explicitly enabled in CI. All tests use
synthetic/public fixtures and disposable directories, not real K-SYNC material.

## Current product boundary

**The native plugin is a release candidate with encrypted local storage and
integrated synchronization**, including publication/import, automatic scheduling,
conflicts and key/history transitions. Complete production qualification is still
pending; it is not a certified replacement for the Python 0.1.1 agent. Automatic
Python-state conversion, physical cloud delivery and complete platform acceptance
remain unfinished. [Nextcloud delivery](docs/NEXTCLOUD.md) now has an actual
server/desktop-client acceptance test with separate device folders. Generated
package replacement and encrypted removal are connected to the platform GUI
tests; results must pass for the current commit. Historical-version upgrades and
additional interruption scenarios remain separate gates.
The main module no longer depends on the patched-host bridge and its packages
do not include a CopyQ patch. Independent storage works on unmodified CopyQ through
public callbacks. Bounded native DataFile migration and stock Pinned/Tags
integration are described in [native data and protection](docs/NATIVE-DATA-AND-PROTECTION.md).
Full platform lifecycle verification remains a release gate.

Linux CI targets native Ubuntu 24.04-compatible applications, not every Ubuntu
release. Flatpak CI builds a separate module inside its matching KDE SDK and loads it
in the installed application; only successful runs produce that platform artifact. No host glibc change is required by this pipeline.
Windows NTFS process-interruption tests are not physical power-loss certification.

See the [release readiness checklist](docs/RELEASE-READINESS.md) for the last
completed milestone, the observed CI blocker and the remaining implementation
and delivery requirements.

Shared-key rotation, compact history rollover and guarded peer migration: [history transitions](docs/HISTORY-TRANSITIONS.md).

Versioned changes: [changelog](CHANGELOG.md). Package contents, licenses, compatibility and publication: [release procedure](docs/RELEASING.md).
