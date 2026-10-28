# Changelog

## 0.2.0-rc.1 — 2026-10-19

First native release candidate for an independently installed module in stock
CopyQ 17.0.0. This is a candidate version, not a claim of completed production
qualification. Publication requires successful tests for its exact commit.

- Password-protected independent local storage and separate local/shared keys.
- Seed/Join, preserved-tab adoption, bounded native DataFile migration and
  Pinned/Tags protection through the public plugin API.
- Journaled publication/import, opt-in automatic synchronization, conflict
  decisions, encrypted backups and interrupted-operation recovery.
- Shared-key rotation preserving full history, compact successor histories,
  offline-peer Join and recovery from an old history's capacity limit.
- Separate Windows, native Linux, system-Qt Linux and matching KDE Flatpak ZIPs;
  installation paths and ABI are obtained from the selected CopyQ instance.
- Versioned package manifests, checksums, license notices, corresponding source
  archives and a manually invoked, CI-gated release workflow.

Migration: Python 0.1.1 users follow `docs/DEVICE-SETUP.md` with a new native
profile and preserved data. Do not use both writers on one history. Existing
native schema-6 data are retained on replacement; back up state and vault before
upgrading. Older modules cannot read schema 6; do not downgrade in place.

Known qualification gaps: physical two-device Nextcloud acceptance, the remaining
fault/historical-binary upgrade matrix and target-limit performance measurements.
A strict core24 Snap fixture does not certify an unnamed Store Snap revision.

## Python agent 0.1.1 — historical

Separate predecessor implementation. It is not included in native module ZIPs
and is not a runtime dependency of the native plugin.
