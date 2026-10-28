# Packages and release procedure

`VERSION` is the native product version. It drives CMake, embedded Qt plugin
metadata, Preferences description, package filenames and `BUILD-INFO.json`.
The Python 0.1.1 predecessor has its own historical version; it is not bundled.
The initial native version is **0.2.0-rc.1**, a release candidate. No existing
failed or incomplete CI run authorizes its publication.

## Delivered product and compatibility

The normal ZIP contains exactly one `securesync` module and the reviewed
installer, user documentation, changelog, compatibility and license notices.
It includes encrypted local storage, Seed/Join, publication/import, automatic
synchronization, conflict recovery and key/history transitions. Setup and key
sharing remain explicit; automatic synchronization is opt-in.

There is no replacement CopyQ, host patch, SDK, laboratory plugin, test driver,
profile, key or runtime Python agent in that ZIP. Historical host code remains
only in the repository/corresponding-source archive for regression review.

| Package target | Installation |
| --- | --- |
| `windows-x86_64` | Stock CopyQ 17 portable ZIP / setup.exe, MSVC Qt 6.10, NTFS |
| `linux-ubuntu24.04-x86_64` | Ubuntu 24.04-compatible native/AppImage CopyQ, Qt 6.10+ within the installer-validated range |
| `linux-system-qt6.4-x86_64` | System Qt 6.4 source/DEB installations; the tested strict core24 Snap fixture |
| `linux-flatpak-kde6.10-x86_64` | Installed Flatpak CopyQ with KDE Platform/SDK 6.10 |

`COMPATIBILITY.json` is the machine-readable matrix. The actual Qt, compiler,
architecture, commit and module hash travel in `BUILD-INFO.json`. The installer
still probes the selected running CopyQ; a filename never overrides ABI checks.
No unnamed Snap Store package/revision, arm64, macOS or arbitrary CopyQ version
is certified. Install the matching ZIP and restart CopyQ; see [installation](INSTALLATION.md).

Every ZIP has `PACKAGE-SHA256SUMS` for all members except itself. CI artifacts
include an external `SHA256SUMS` for the complete ZIP. Release assets additionally
have a combined checksum file and `RELEASE-MANIFEST.json` identifying the exact
successful CI run, attempt, jobs, artifact identities, commit and asset hashes.
Checksums detect corruption; obtain them from the trusted release together with
the CI/source identity. This workflow does not claim cryptographic attestation
or bit-for-bit reproducible native builds.

## Preparation

1. Update `VERSION` and add its exact entry to `CHANGELOG.md`. Candidate versions
   use `MAJOR.MINOR.PATCH-rc.N`; stable versions use `MAJOR.MINOR.PATCH`.
2. Review `release/compatibility.json`, license/dependency notices and migration
   instructions. Update pinned workflow dependencies together with `ci/toolchain.json`.
3. Merge the reviewed changes and wait for **Native build and tests** on that
   exact current `main` commit. Linux, Windows, Flatpak, source/DEB/strict Snap
   and **Native CI gate** must all execute successfully. A green PR synthetic
   merge, partial job, skipped test, missing report, expired artifact or runner
   failure cannot substitute for this run. CI also validates packages and release
   rejection cases through Python unit tests.
4. On `main`, run **Prepare or publish native release**, selecting that native CI
   run ID and leaving **publish=false**. It promotes the already tested ZIPs,
   validates all native/installed-host reports, and constructs corresponding
   sources. It never recompiles, renames or modifies a tested ZIP.
5. Download `securesync-release-candidate` and review its notes, matrix, manifest,
   sources and checksums. No tag or GitHub Release exists at this stage.

A candidate can be prepared only after the workflow is merged onto `main`.
The workflow does not turn today's unverified build into a production release.

## Stable qualification

Candidates still require all automated platform gates. Stable releases also
require reviewed, committed `passed` results and HTTPS evidence links in
`release/qualification.json` for **all** remaining product gates:

- Physical two-device Nextcloud acceptance, including offline/restart/conflict.
- Remaining fault matrix and historical-binary upgrade acceptance with data.
- Responsiveness and memory at the supported production limits.

These entries are currently pending. Merely removing `-rc.N` from `VERSION`
does not enable a stable publication. See [release readiness](RELEASE-READINESS.md)
for the test scope; human review must assess the linked evidence.

## Publication and recovery

After reviewing the concrete candidate, explicitly run the same workflow on
`main` with the same successful CI run ID and **publish=true**. It prepares and
validates the assets again, then the separate `release` environment job checks
current main/CI and every asset once more. Only that publication job has
`contents: write`; tests/preparation use read-only tokens. Repository owners can
configure required reviewers for the `release` environment. The default action
only prepares assets.

Publication creates `v<VERSION>` at the tested commit with all four module ZIPs,
corresponding sources, notes, manifest and combined checksums. Candidates are
marked prerelease; stable versions require qualification evidence. Assets are
uploaded to a draft before the draft is made public. Existing tags/releases are
refused, never overwritten. If publication stops after draft/tag creation,
inspect that draft and its assets manually; do not retag it or force an automatic
retry over an existing version. A later main commit, changed CI attempt or expired
artifacts requires a new successful run/preparation.

Corresponding sources contain exact, credential-free shallow Git checkouts of
this plugin, CopyQ and zlib, original licenses, and offline-build instructions.
They preserve Git identities required by CMake without copying local work,
credentials, SDKs or user data. Qt and Linux system libraries are not distributed.
Native module ZIPs remain separate from this larger source archive.
