# Guided setup and installer contract

Status: future product requirements, stage 1. No automatic installer or public-key
pairing is delivered by this document. Current installation remains described in
[INSTALLATION.md](INSTALLATION.md). Security rules are defined in
[DEVICE-TRUST-DESIGN.md](DEVICE-TRUST-DESIGN.md).

## Supported first delivery

Target stock CopyQ 17 x86_64 on Windows 11 (installed and portable) and Mint with
the installed CopyQ Flatpak. Probe actual CopyQ/Qt/compiler/runtime compatibility;
never admit a platform merely because a filename or nominal version matches.
No promise of arbitrary Snap, macOS, arm64 or all Linux distributions is made.
Do not patch, recompile or replace the user's CopyQ as an installation shortcut.
User-facing installation MUST NOT require Python, a compiler or terminal commands.

The installer and the in-plugin wizard are distinct components. Installation
activates the correct module; the wizard configures device trust and sync. Use
shared narrow APIs rather than duplicating secret handling in an external helper.
No new always-running agent, service or web account is required.

## Installer transaction

| Step | Required result and failure behavior |
| --- | --- |
| Select | Discover through supported launch/install metadata or let the user select CopyQ; resolve ambiguities and the exact session. No recursive home scan. |
| Inspect | Query actual provider paths and ABI, inspect existing launch settings and competing plugins without reading clipboard contents or keys. |
| Verify | Authenticate package origin and signed version/compatibility metadata using a documented trust anchor. A SHA256 file downloaded alongside a ZIP is only an integrity check. Reject tampering and unsupported downgrade. |
| Prepare | Stage a new immutable module in application-visible persistent storage; provision private folders and record an installation journal. Do not overwrite a loaded DLL/SO. |
| Activate | Preserve unrelated launch entries, close only the selected GUI normally, persist the intended launcher/autostart configuration, and restart. Do not force close unsaved editors. |
| Confirm | Verify the actual GUI server loaded the expected build and that its paths persist across restart. A CLI client reporting the plugin capability is insufficient. |
| Complete | Show successful installation and offer the wizard. An unconfirmed launch remains resumable or reverses only installer-owned changes. |

Persist previous launcher/permission values and installed version before mutation.
Rollback uses compare-before-restore semantics: do not overwrite a user's later
edits. Do not reset all Flatpak overrides, delete arbitrary modules or stop
unrelated sessions. Switching back to an old module is allowed only before an
incompatible state migration or with proven schema compatibility. Otherwise
retain the new state and offer supported recovery, never unsafe binary downgrade.

The binary/package-signing mechanism, publisher trust-anchor bootstrap, expiry,
key rotation, release reproducibility evidence and installer framework need
selection before distribution. Bootstrap trust for the installer itself must be
documented; embedding a verification key does not authenticate an already
substituted installer. Installer updates require the same protections.

## Paths and permissions

Allocate independent private state, vault and installation journal locations
automatically using persistent paths reported from the selected application
namespace. Do not place these inside Nextcloud or ordinary clipboard files.
Validate overlaps, symlinks/reparse points, permissions, filesystem capabilities
and available space before activation; never silently migrate existing folders.

Windows private storage requires fixed local NTFS and protected user-owned DACLs.
If transport is on another fixed NTFS volume, provision private publication
staging on that volume. Transport delivery still uses the host Nextcloud client.

Flatpak needs a module built for the actual admitted KDE runtime and paths from
its own persistent XDG data space. Grant only the selected transport directory;
do not grant host/home-wide access. Explain that a Flatpak override applies to
the whole app, not just one CopyQ session. Prefer a narrowly scoped launcher
where feasible, and account for desktop/autostart entry points. Preserve other
custom entries and record exactly which grant or variable was added.

A portal selection is not proof of persistent access or required atomic file
operations. Probe actual read/write and publication capabilities in a disposable
installer-owned test directory before enabling sync. Refusal must not broaden
permissions or fall back to unsafe filesystems. Removal of access pauses sync
without resetting storage or interpreting the folder as a new empty history.

## Wizard and normal settings

The entry screen offers **Create synchronization** and **Join synchronization**.
Choose a local Nextcloud directory and a non-identifying device alias. Default
to password-protected local storage; optional OS-keychain unlocking requires
separate Windows and Flatpak qualification and explicit user choice. Never save
an unlock password in ordinary settings or shell arguments.

For Create, provision private storage, create a new root and keys, prepare the
recovery package, create the tab and seed the selected new group transactionally.
Do not infer global emptiness merely from a local directory scan: simultaneous
offline Create can produce independent roots. Conflicting roots pause setup;
never merge or overwrite them automatically.

For Join, implement the request, peer verification, approvals, key delivery,
local initialization and history Join stages of the security contract. Require
1 approval only for recorded initial bootstrap and 2 thereafter. Display progress
without requiring manual state/vault paths, key export/import, Seed or Join actions.
Offer safe resume/cancel after each durable stage. Cancellation cannot promise
recall of files or keys already delivered to a remote device.

An existing nonempty `synced_tray` needs an explicit choice and a verified
encrypted backup or preserved source tab. Closed editors and protected-item
guards still apply. No plaintext intermediate export or automatic replacement.
Automatic synchronization begins only after successful local onboarding and the
user's visible consent. It resumes after the chosen local unlock method succeeds.

Keep all advanced actions in ordinary Preferences, organized as Synchronization,
Devices, Recovery, and Keys and security. Do not remove existing key/recovery/
history/removal operations or make them developer-only. Legacy v1 actions must
be clearly scoped and cannot bypass new membership authorization.

Advanced actions must show their scope and require appropriate confirmation.
Completed key/recovery actions can take immediate effect; Cancel in the enclosing
Preferences dialog must not imply undo. Wizard cancellation instead records its
own resumable state and explains which local or remote effects already occurred.

## Preserve CopyQ encryption

Core **Encrypt Tabs** and the legacy GnuPG **Encryption** item plugin are distinct.
Preserve both settings and existing protected data. The installer MUST NOT
silently disable Encryption, Encrypt Tabs, Synchronize or third-party loaders.
Disabling an unrelated GPG loader is not an acceptable general installation step.

The current global inventory refusal in `native/plugin_inventory.h` must stay
until safe coexistence is demonstrated. Investigate actual saver/loader routing
so Secure Sync owns only its intended tab while other protected tabs and items
retain their existing encryption. Do not solve the problem by deleting a guard.
Reject competing ownership of `synced_tray` and explain the affected tab/plugin.
If migration is necessary, require a deliberate choice, encrypted backup and
post-restart verification before source removal. If coexistence cannot be
qualified on stock CopyQ, document the limitation and revisit architecture;
do not ship the simple wizard with an undisclosed loss of protection.

## Status and diagnostics

Separate current preflight conditions, the last action's result, local encrypted
save evidence and per-peer acknowledgement. Re-run relevant checks when plugin
settings, session, transport permission or profile changes. Never present an old
inventory refusal as proof that current settings are wrong.

Show distinct states for missing permissions, wrong/unsupported package, waiting
for approvals, waiting for files, membership conflict, local storage locked and
interrupted setup. A generic error must not falsely identify a wrong password or
plugin. Where the failure cannot be safely distinguished, say it is unconfirmed
and provide a non-destructive next step. Do not initialize over uncertain data.

No secrets or clipboard content in logs, telemetry, crash attachments, QR previews
or clipboard-based diagnostics. Redacted diagnostics remain explicitly copied
and must not include identifying paths/hostnames. Pairing QR payloads deliberately
contain only the reviewed public verification material, never raw group secrets.

## Upgrade, uninstall and compatibility

Upgrades preserve vault/state and complete journals, retain explicit format
versions and refuse unsupported mixed writers. Versioned migration to the new
trust protocol retains the old v1 archive; it does not grant trust based only on
possession of a copied K-SYNC file. New members require the new policy.

Uninstall offers safe encrypted handoff or deliberate retention of encrypted
archives, and removes only owned launch entries, module and permissions after
confirmation. Verify the encrypted handoff before removing the module. Never
delete keys, state, original tabs or user-controlled cloud archives by default.

## Existing implementation anchors

| Foundation | Reuse boundary / remaining work |
| --- | --- |
| `tools/install.py`, `tools/installation.js` | Selected-session probe, compatibility checks and immutable staging exist; GUI installer, authenticated distribution and activation transaction do not. |
| `native/settings_widget.cpp` | Existing normal Preferences/actions remain; add a wizard and understandable state presentation. |
| `native/plugin.cpp` | Reuse guarded model operations, cancellation and epochs; replace stale-status presentation and integrate onboarding coordination. |
| `native/key_vault.cpp`, `native/unified_state.cpp` | Existing private key and state transactions are foundations; they do not supply pairing or a signed membership log. |
| `native/history_transition.cpp` | Reuse preservation/journal concepts; adapt to membership-authorized, per-recipient future-key delivery. |
| `native/plugin_inventory.h` | Current global guard is a known limitation pending real coexistence tests. |

See the [acceptance matrix](DEVICE-TRUST-ACCEPTANCE.md) for delivery evidence and
the [Flatpak permission model](https://docs.flatpak.org/en/latest/sandbox-permissions.html)
and [CopyQ encryption documentation](https://copyq.readthedocs.io/en/latest/password-protection.html)
for upstream constraints. These requirements do not expand today's support matrix.
