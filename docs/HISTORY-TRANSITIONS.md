# Shared-key rotation and history rollover

Secure Sync provides three explicit **Devices and recovery** actions in stock
CopyQ 17. No CopyQ patch, service, raw key in settings or protocol-v1 rewrite
in place is required. Install the matching module and restart CopyQ first.

| Action | Result |
| --- | --- |
| Rotate shared key — retain history | New K-SYNC, new local key/vault/state and new transport. Every authenticated event is encrypted again; IDs, parents, ordering and payloads are preserved, including branches. |
| Start compact successor history | New K-SYNC and private storage. The current local tab becomes one new root; old history, local state, keys and backups remain in their original locations. Unsent local edits are included. Other branches are retained in the old archive, not silently merged into the chosen current contents. |
| Join successor — preserve local edits | Independently authenticate the new key through its password-protected transfer. Import the successor tip into fresh private storage. Keep divergent current local contents in an encrypted protected backup and retain the old profile. |

Rollover is explicit. No event, ancestor, backup, vault or source directory is
automatically deleted. A full history remains readable; use the compact action
before continuing publication. Re-encrypting the entire graph preserves its
size and therefore does not free capacity. Repeating compact rollover produces
independent generations without reusing identities within a key/transport.

## First device

1. Stop automatic synchronization on **every** device and close editors.
   Full-history rotation requires readable authenticated old history and completed
   imports/publications/resolution. Compact rollover instead explicitly chooses
   the current durably saved local tab. Pending operations and other old branches
   remain in the encrypted source archive; no old-key publication is required.
2. Keep an offline encrypted backup of the old state, vault and full transport.
   Select the rotation or compact action. The command checkpoints and ordinarily
   unloads the tab; it never forces an editor closed.
3. Enter the current Secure Sync password. Choose a dedicated, existing private
   journal folder, a separate successor transport containing `events/`, and new,
   separate private state/vault folders. Private folders need user-only access.
   On Windows also select private staging on the transport's fixed NTFS volume.
   Choose paths **inside the running CopyQ namespace**: Flatpak's persistent
   app-data area or Snap's common-data area for private files, and an explicitly
   permitted Nextcloud folder for transport. Never place the journal in Nextcloud.
4. Wait for verified activation. The new vault uses this device's Secure Sync
   password; both its local key and K-SYNC are newly random. Automatic mode stays
   off. Back up the new vault and state. Use **Share encrypted synchronization
   key** to deliver only the new K-SYNC with a separate transfer password.
5. Confirm each device's successor profile and exact data before enabling
   automatic synchronization again. Keep old archives until their retention is
   deliberately reviewed outside the plugin. Keep the sealed journal receipt too;
   it identifies the retained source archive.

A K-SYNC compromise cannot be repaired by publishing the new secret encrypted
under the compromised old key. Transfer the new key/password through trusted
channels. Revoke the old device's cloud-folder access separately. Rotation cannot
undo plaintext/key disclosure that already happened.

## Other devices

Wait for the new transport's files to arrive through Nextcloud. With the old
profile still selected, use **Join successor — preserve local edits**. Supply
this device's Secure Sync password, separate new private folders/journal, the
new transport and the independently obtained encrypted key transfer/password.
The new local vault does not import another device's local encryption key.

Joining refuses an ambiguous multi-tip successor, incomplete or altered history,
unsafe paths, and insufficient backup/record capacity. Pinned/locked tagged
items retain their normal import protection. Resolve/release protections only
when intended, then retry. It never silently publishes an offline device's old
contents over the new generation. Those contents remain in the old profile and,
when different, an encrypted protected backup in the new profile; use the guarded
backup restoration/conflict actions if they need to be incorporated. An existing
identical protected backup is reused. If all four slots are occupied, explicitly
review/remove an unrelated backup before Join; this is permitted with an old
reserved publication, without sending it. The active resolution's recovery backup
cannot be discarded. No backup is deleted automatically.

An old/offline device is **not remotely erased or automatically switched**.
Its later edits remain in the old history until that device explicitly joins.
Full-history rotation detects old-folder changes during copying and refuses
activation. Compact/Join explicitly select local state/new history respectively;
old-folder changes remain in the retained old generation. These local-state
transitions work even when the old folder is offline, corrupt or over capacity.
They still refuse missing, corrupt or changed private source state.

## Interrupted operations and activation

The password-encrypted private journal binds the exact source profile, source
record, target profile, mode and newly generated keys. Full rotation additionally
binds the authenticated source history; Compact/Join use the local private record
and never scan or publish to the old transport.
Before each immutable event publication it retains the exact ciphertext. Retry
confirms an existing event byte for byte; it neither replaces files nor allocates
a different key/event under the same intent.

The source vault enters a durable `suspended` phase before destination writes.
Normal loads, saves, synchronization, key rotation and encrypted handoff refuse
that source while suspended. Older modules do not recognize this phase and also
refuse it. New version-2 journals additionally retire the source data record into
an authenticated archive binding derived from the exact source/successor profiles.
This atomically increments its generation without changing snapshots, accepted
head, pending recovery/publication, witnesses or backups. A different process
holding cached old keys cannot read or save through the normal source binding.
The old transport is never rewritten. Retain the sealed journal receipt: it keeps
the profile mapping needed to authenticate this archive, without key material.
The suspended source password cannot be changed until completion/cancellation;
it also opens the preparation journal and destination vault. Rebuilding a missing
suspended vault requires that original journal password. After activation the
new vault password can change independently; journal sealing accepts its original
password separately if needed.

On failure, keep **both profiles, every transport and the journal**. With the old
profile active, choose **Resume interrupted history/key transition** and the same
journal/password. It authenticates all prior work, checks source changes and
continues. There is no empty initialization after a failed read. An unrelated
pre-existing destination vault/state or unexpected public event is refused.

Only a completely verified successor can be activated. Its entire profile is
written as one settings value. A crash sees the old profile (suspended; Resume)
or the successor profile, rather than mixed paths. An authenticated predecessor
binding allows the ordinary CopyQ cache marker to hand over once; its generation
cannot exceed the verified successor record. Cache bytes never authorize a save.
If activation was unconfirmed, restart and inspect the selected profile before
retrying. Once the successor is active, operate on that profile; do not manually
repoint it to old paths or downgrade to an older module.

**Cancel incomplete transition** records cancellation before reactivating the
old vault. For version-2 transitions it also atomically restores the source data's
normal binding with another generation increment. Repeated cancellation cannot
roll back later local edits. Keep destination files separate and never Join that cancelled target.
A Ready journal may be cancelled only after the GUI verifies that the saved
active profile is still the source. Once activation selected the successor, this
old-profile cancellation is refused. A cancelled journal can never resume; a later
attempt needs new dedicated target/journal directories.

After confirmed activation the plugin automatically seals the completed journal:
its key fields are replaced by a receipt. A crash before this step leaves an
**encrypted key backup**, still protected by the password used to create it.
With the successor active, use **Seal journal of active successor** to complete
this step (supply the original journal password if the vault password changed).
A sealed journal cannot resume or cancel the source. Changing a vault password
does not re-encrypt old backups or an unsealed journal; keep them private.

## Verification

The mandatory native history-transition suite exercises re-encryption of complete
graphs, exact binary/empty data, peer Join with preserved divergent edits,
bidirectional synchronization after the switch, rollover and wrong-password
refusal. A real 999-event reservation races another peer taking slot 1000: Compact
retains the exact unsent old ciphertext and starts a usable new history. Offline
peer Join retains old pending work and respects backup capacity. Tests also cover
corrupt/unavailable old transports, cached-key refusal, restoring/repairing a
missing suspended source vault and idempotent cancellation after later edits. Twenty actual child processes terminate at journal creation, vault suspension,
source data retirement,
vault creation, ciphertext reservation/delivery/progress, state creation and
Ready; reopening resumes with the same keys and exact immutable event files.
Installed CopyQ GUI checks additionally exercise activation, cache handover and
restart. Only passing results for the current commit establish platform coverage.
