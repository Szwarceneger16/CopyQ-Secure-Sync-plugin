# Nextcloud transport

Secure Sync uses the **Nextcloud desktop client** to deliver encrypted event
files. It does not connect to a cloud account, store Nextcloud credentials,
upload plaintext or require a replacement CopyQ executable. Nextcloud can be
self-hosted. The same external plugin runs in unmodified CopyQ 17.

## Configure two devices

1. Create a dedicated folder in Nextcloud, for example `CopyQ-Secure-Sync`, and
   let the desktop client download it on both devices. Create its `events`
   subfolder before configuring the plugin.
2. Select each device's **local path** to that folder as Secure Sync's transport.
   The paths may differ. Select **always keep on this device** if virtual files
   or files on demand are enabled: the plugin needs complete ordinary local files.
3. Keep the private state directory, password vault and any raw key import file
   outside the Nextcloud tree. Transfer K-SYNC through the documented encrypted
   key-transfer operation; each device has its own local key, password and ID.
4. Complete [Seed and Join](DEVICE-SETUP.md), then enable automatic synchronization
   on both devices. Wait for Nextcloud to deliver the initial history before Join.
5. For Flatpak, grant CopyQ access to that specific local transport directory
   and the chosen private directories. The ordinary desktop client performs
   delivery outside the sandbox; no Nextcloud library is compiled into CopyQ.

Transport files must be owned by the local user and not writable by other users.
Private state/key directories have stricter owner-only requirements. The plugin
reports unsafe permissions and never silently broadens them. Root directories
and keys are checked separately from downloaded encrypted event files.

## Delivery and recovery

The server receives immutable encrypted `.cqs` events. Device IDs, event names,
file sizes and delivery timestamps remain visible; clipboard MIME contents are
encrypted by Secure Sync, independently of Nextcloud's server settings.

An offline device continues to retain its local encrypted data. Its desktop
client delivers events after reconnecting. A child arriving before a required
parent, or a temporary/incomplete client download, makes synchronization wait;
it does not initialize a new empty history. Concurrent offline edits can create
two branches: use **Compare and resolve conflicts** after delivery. Nextcloud's
own conflict copy does not replace an authenticated Secure Sync decision.

Sync the complete `events` subtree and retain published history. Deleting an
accepted event or supplying different bytes under an existing event name stops
synchronization for recovery. The plugin cannot turn a folder scan into a
distributed lock or infer that an unavailable event was intentionally deleted.

## Actual acceptance fixture

`bash ci/test-nextcloud.sh out/linux` starts a disposable real Nextcloud server
and uses actual `nextcloudcmd` desktop clients between **separate** transport
roots. There are no public ports and no user credentials. The test runs two
official CopyQ 17 AppImage processes with the externally built module, including
bundled text/image/notes/FakeVim loaders. It exercises bidirectional delivery,
unlock-only restart, the actual inline editor, explicit conflict resolution,
offline delivery/resume and byte-for-byte encrypted event readback from the
server. Server/client versions and event hashes are recorded with the reports.

The pinned server is an isolated test fixture, not a deployment recommendation.
This does not certify every Nextcloud release, virtual-file provider, physical
machine or network failure. Missing-parent and interrupted-publication boundaries
remain covered by the mandatory native history/transaction suites. Physical
Windows/Flatpak clients and additional interruption scenarios remain release gates.
