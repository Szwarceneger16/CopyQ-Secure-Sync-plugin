# Native plugin release readiness

The release must install into an existing, unmodified CopyQ 17. Users do not
patch or rebuild CopyQ. CopyQ discovers modules at startup, so installation
requires a restart. Native/Flatpak modules require matching Qt/platform ABI.

## Installation compatibility milestone

[Installation](INSTALLATION.md) now obtains paths and ABI from the selected
running CopyQ via public info()/version()/env(), with Flatpak runtime metadata
and Snap's revision-independent common-data path. No user-directory search or
host-path guessing is used. A checksum-checked package can be staged through
CopyQ into a fresh module directory inside its own namespace; activation is an
explicit restart with COPYQ_PLUGINS. Existing libraries/settings/state/vaults
are not overwritten by staging. Suggested private directories are per profile.

Actual build Qt/CPU/pointer/compiler metadata travels with each package. The
helper refuses unsupported CopyQ/Qt/OS/architecture and cross-sandbox packages.
System-Qt Linux builds are separate from the Qt 6.10 native SDK and KDE Flatpak
SDK. Separate source, generated-DEB and strict core24 Snap **fixture** tests,
official Windows setup.exe and portable ZIP tests, and default-namespace Flatpak
staging/permission tests are required by CI. Results for the current commit,
not this checklist, establish which tests have passed. The Snap fixture does
not establish support for an unverified Store package; old distro CopyQ/Qt5
packages are incompatible. No user is asked to rebuild or patch CopyQ.

## Versioned packaging and publication

`VERSION` defines native candidate 0.2.0-rc.1. Normal packages contain the full
main synchronization module, changelog, exact ABI/compatibility data, license
notices and internal/external checksums. They exclude host patches, lab/test
modules and CopyQ executables. The [release workflow](RELEASING.md) promotes
only exact complete current-main CI artifacts and adds corresponding sources
and a provenance manifest; it defaults to preparation, with publication explicit.
Stable publication also checks every pending qualification entry in
`release/qualification.json`. Packaging readiness does not clear those gates.

## Implemented milestones

The [native UI](NATIVE-SETTINGS.md) integrates applied-profile Seed/Join,
synchronization, protected migration, recovery and encrypted removal actions.
Live status separates local-save evidence from transport progress and gives a
next step for failures. Explicitly copied diagnostics use a fixed field allowlist,
excluding paths, identifiers, raw errors, keys and clipboard data. Current CI
also exercises a real Preferences synchronization button and diagnostics copy.

The main `securesync` module has configuration, authenticated read-only transport
inspection and opt-in authoritative local storage through public loader/saver
callbacks. The historical patched-host bridge is test-only, neither linked nor
packaged. The laboratory module remains a separate disposable experiment.

Local key lifecycle is now implemented: separate Secure Sync password, independent
random local key and shared K-SYNC, encrypted vault/transfer/backup, atomic password
change, journaled local-key rotation, explicit earlier-experiment migration,
create-only setup/recovery and guarded encrypted handoff to normal CopyQ storage.
CopyQ retains its own password and lock. The public API exposes neither DEK nor
password. See [key lifecycle, loss and removal](KEY-LIFECYCLE.md).

The [unified schema-2 record](UNIFIED-STATE.md) now combines independent local
contents, accepted history and pending recovery with an actual K-SYNC identity.
Explicit migration discards artificial local revision metadata without dropping
contents. Manual unloaded-tab Join, FastForward and offline recovery are connected.
Manual Seed with a reserved ciphertext/sequence journal, preserved-tab adoption
and Join with an encrypted local backup are integrated. Subsequent publication
and opt-in automatic synchronization are implemented, including persisted
scheduling after unlock, selected visible-tab updates and public Qt editor
guards. Explicit conflict decisions preserve local contents in encrypted backups
and merge authenticated tips through protocol-v1 events. See [automatic sync](AUTOMATIC-SYNC.md).

Outbound publication uses protocol-v1 packed MIME, canonical authenticated
metadata and AES-GCM, with a durably reserved per-device ID and exact ciphertext
in the local record before transport writes. Retry confirms that same file
without allocating another ID and preserves subsequent local edits. Reservation
also checks the captured snapshot, accepted parent and a strictly increasing
sequence. Windows has an optional private publication-staging folder so data and
Nextcloud can reside on separate NTFS volumes. Its permissions, file-creation
access and transport volume are checked before reserving an ID and again before
moving the complete ciphertext. Correcting staging leaves the record binding
and existing publication intent unchanged.

Import and recovery now execute their encrypted state transactions on a worker
with cancellable GUI dispatch for the callback-bound model. Manual state commands
use operation tokens instead of blocking the GUI for their disk transaction.
Settings invalidation, tab destruction and shutdown stop stale callbacks;
shutdown cancels GUI waits before joining and checkpoints committed model edits.
Native tests cover responsive GUI dispatch, edits/editors between steps,
retained encrypted recovery intent, profile invalidation and shutdown.

Automatic work now has monotonic scheduling, bounded transport-directory
notifications, burst coalescing, a 30-second idle fallback and capped retry
intervals. The plugin's independent local checkpoint timer runs even with
automatic synchronization off and retains dirty edits across temporary storage
failures. Imports suppress outgoing notifications; actual accepted snapshot
comparison prevents publication echo. Native regressions cover debounce bounds,
cooldown under notification noise, missing-record restoration, watch rearming
and actual-module retry admission. Unresolved conflicts block publication while
still observing history, allowing a clean device to import an authenticated
merge created by another device without another Start action.

Two official unmodified CopyQ 17 AppImage processes exercised bidirectional
publication/import with visible selected tabs and unlock-only automatic resume
after restart. The platform GUI workflow now tests the official Windows portable
binary and a separately built matching-SDK module in installed Flatpak. Results
must be read for the current commit; adding a job does not certify its platform.
The generated-package GUI driver now includes installation/replacement and
explicit encrypted handoff/removal checks. Its seven local official-AppImage
scenarios passed, including exact ordered MIME readback after module deletion.
Text/image/notes/FakeVim can remain
enabled, including Pinned/Tags with protected row checks; incompatible storage
and unknown loaders remain blocked by name.
Pinned/tag-locked rows must not be silently deleted by a model import.

## Current validation

Linux's full build includes 21 required suites, including unified state and the historical host
regression, password envelope, actual main-module local storage and vault tests.
The default build does not prepare a patched host; the build with that regression
disabled has 20 suites and independently checks module symbols for absence of
private host-bridge/DataFile linker dependencies. All fixtures are public and disposable.

The official unmodified CopyQ 17.0.0 AppImage (Qt 6.11.1, QCA 2.3.12) passed actual
process/GUI lifecycle checks using the external main module built with Qt 6.10.3.
They cover durable binary storage/restart/interruption, native Encrypt Tabs and
password change, plugin password/local-key change, native expiry and both unlock
dialogs, refusal with an open editor, guarded encrypted handoff, interruption
before final opt-out, and restart after removing the plugin. A public-Qt helper
controls only disposable test dialogs and is excluded from packages. These tests
do not rebuild CopyQ. The AppImage requires glibc 2.43, supplied in a separate
Ubuntu 26.04 test container; the host libraries were not upgraded.

The unified-state process driver additionally exercises real empty-tab Join,
FastForward, accepted-head retention during local edits, dirty-import refusal
and restart with authenticated Qt-packed binary/empty fixtures. Its test-only
fixture executable is excluded from module installation and packages.

Device setup adds an actual unmodified-CopyQ process test: native encrypted-tab
preservation/adoption, explicit Seed with idempotent retry, protected shared-key
transfer to a second independently configured CopyQ server, Join with exact binary
data, both servers' restart and interrupted/stale-cache recovery. It passed ten
checks on the official AppImage. Both processes share a local test transport;
physical-machine cloud-client delivery remains a separate test. A real disposable
Nextcloud server and actual desktop clients have now passed six local GUI
checks with separate transport roots, bidirectional delivery, restart, editor
deferral, explicit conflicts and offline resume. Ciphertexts were compared
byte-for-byte with server downloads. See [Nextcloud](NEXTCLOUD.md); this is not a
physical Windows/Flatpak network certification.
Native tests also exercise ten Seed state-commit exits, three transport-publication
exits, nonempty preserved Join/recovery, later-edit retention, key rotation with
reserved publication, duplicate IDs/conflicts and an independent schema-3 vector.

Earlier successful CI results belong to the private development repository
and cannot validate this public source snapshot. The new repository must
run its complete Linux, Windows, Flatpak and installation checks for the
exact commit being released. Production qualification remains separate.

The local managed environment has neither the Flatpak runtime nor permission to
fetch Flathub, and cannot provide a native Windows kernel or strict snapd
confinement. Those tests run on disposable GitHub-hosted VMs; ordinary container
tests or AppImage results are not substituted for them. NTFS process-termination
tests are not physical power-loss certification.

## Remaining milestones

1. **Close storage/lifecycle delivery gates.** Verify the new device-setup
   transition tests and actual platform GUI/install/upgrade/removal for the current SHA.
   ABI admission and separate native/system-Qt/Flatpak packages are implemented;
   a named Snap Store package/revision still needs its own certification. Bounded native DataFile
   adoption and handoff recovery, plus Pinned/Tags anchors, are now implemented;
   require the current commit's native and actual platform GUI results. Missing
   or corrupt sources refuse without creating an empty replacement.

2. **Agent migration.** Manual Seed, Join and protected adoption support the
   documented fresh-profile Python 0.1.1 transition. Automatic conversion of
   Python state remains separate work. Missing/corrupt established state must
   never initialize an empty profile.

3. **Runtime delivery.** Subsequent publication and asynchronous automatic
   cycles use durable reservations and shared model/job session exclusion. Certify
   native Windows GUI shutdown/upgrade and physical Nextcloud delivery. The actual
   local server/client acceptance is connected to Linux CI. Persisted startup and public-API visible-model/editor-safe updates are implemented.

4. **History transition validation.** Shared-key rotation re-encrypts the full
   graph into a new transport; compact rollover starts one root and retains the
   old encrypted archive. Suspended source vaults, exact-ciphertext journals,
   explicit peer Join and single-value profile activation are integrated; see
   [the transition contract](HISTORY-TRANSITIONS.md). Require current native
   interruption and installed-host GUI results before certifying this milestone.

5. **Conflict/recovery UI.** Automatic cycles stop on concurrent local/remote
   changes or pending recovery. Explicit merge choices, protected backup restoration,
   preserve-and-recover for divergent edits, durable whole-history witnesses and
   bounded safe refusal are integrated; see [the contract](CONFLICTS-AND-HISTORY.md).
   Rich content previews for large/file-backed data remain a usability improvement.

6. **Two-device acceptance and versioned release.** Demonstrate Seed, Join,
   binary/empty ordered data, concurrent edits, conflicts and interruption/recovery
   through actual CopyQ processes on packaged platforms. Finish install/upgrade,
   migration, compatibility, key/recovery documentation, versioned artifacts,
   checksums, changelog and release automation without shipping a replacement
   CopyQ application.

A production release requires the two-device cycle and passing installed-platform
tests in addition to local encryption. The current result integrates keys, unified state, publication/import, automatic
scheduling, conflict/recovery UI and installed-platform acceptance; it remains
an experimental development build while the listed gates are open.
