# Conflicts, recovery and retained history

This is the standalone CopyQ 17 module's integrated contract. It uses public
plugin callbacks, the existing encrypted local record, and the protocol-v1
folder transport (including a Nextcloud desktop client's local folder).

## Explicit choices and merge events

**Compare and resolve conflicts** offers the current local version, one selected
authenticated tip, or all distinct ordered items from local data and the tips.
There is no automatic winner. Confirmation preserves local contents in an
encrypted backup, reserves an immutable encrypted event and allocates its device
sequence durably before publication. A fresh graph and complete record comparison
reject stale decisions. Two parents fit protocol v1; more branches are joined by
successive events with the same selected contents. New branches or local edits
require another decision. Editors and Pinned/locked Tags retain their normal
protection during projection into the tab.

**Restore a protected conflict backup** publishes the selected backup as a new
revision, preserving the current local contents in its place. This does not
rewrite old event files or roll the history back.

## Recovery after interruption

Ordinary pending imports use **accept pending target**, **retry pending import**
or **restore pending original**. These work offline from the authenticated local
journal. Acceptance requires the complete target to be present. Once a Restore
intent is durable, an interrupted restore must finish as a restore.

If edits or a partially applied replacement match neither original nor target,
ordinary recovery refuses. Two explicit commands handle that case:

- **Preserve new edits and retry pending import** creates an encrypted local
  backup of the current contents before retrying the journal's target.
- **Preserve new edits and restore pending original** first backs up current
  contents, then restores the journal's original without changing its prior head.

These commands use the normal password, checkpoint and ordinary unload path;
they never force an editor closed. The journal's original and an active
resolution's last backup stay intact. The backup and each projected checkpoint
must fit the record before any data replacement. An unconfirmed backup write
requires reload/retry; an existing identical backup is reused. Later edits are
checked again and cannot be silently overwritten. The protected backup can be
restored as a new synchronized revision after the pending operation is finished
(and Seed/Join is completed if recovery returned to an unjoined profile).

There are four protected backup slots. Filling them refuses another decision or
divergent recovery. **Remove a protected conflict backup** explicitly confirms
permanent removal of a selected backup; it is also available during pending
recovery to free capacity. It cannot remove the active resolution's last backup.
Keep an offline copy of the encrypted record and vault before discarding data
that may still be needed. No backup is removed automatically.

## Durable observations and rollback protection

Schema 6 appends up to 1000 sorted event-ID/SHA-256 pairs to the same encrypted,
authenticated, atomically committed record. Fingerprints cover domain-separated,
length-framed ID, device, sequence, ordered parents and packed items. JSON layout,
nonce and compression are not semantic identity. Exact reserved publications
still require exact ciphertext confirmation. Fingerprints are computed once
during the background authenticated scan; GUI reservation callbacks reuse that
immutable result.

Successful synchronization observations retain all authenticated events,
including unaccepted conflict branches and ancestors, also when retrying an
already reserved publication stops for review. Conflict dialogs compare the
complete authenticated fingerprint map as well as tips before reserving a merge. A prepared import retains
the observation with its journal. Missing previously witnessed events defer the
operation without dropping their fingerprints or accepting a shorter history.
A changed authenticated event pauses automatic synchronization for review, even
when the accepted head itself is unchanged. Restore trusted files and explicitly
start synchronization to retry. Local saves and offline recovery keep witnesses;
they never reset this index. The read-only inspector does not update trust.

Schemas 1–5 retain their frozen byte layout and are readable. The first new
synchronization observation upgrades an authoritative record without clearing
its contents, journal, counters, backups or key identity. It cannot establish the
old contents of ancestors that the older module never recorded. Older modules
refuse schema 6: retain a backup before upgrade, and do not downgrade in place.
The settings schema, vault and transport format are unchanged.

This detects rollback/withholding relative to retained local observations. It
cannot detect an event never delivered to this device, prove global freshness,
or detect rollback of the entire local record and its backups together. A
folder scan is not a distributed lock.

## Limits and safe refusal

Production ceilings remain:

| Resource | Limit |
| --- | --- |
| History events / retained witnesses | 1000 |
| Aggregate encrypted history / decompressed history JSON | 256 MiB each |
| Single encrypted envelope / decompressed event JSON | 25 MiB / 32 MiB |
| Transport devices / directory-entry scan budget | 128 / 4096 |
| Local snapshot | 10,000 items, 256 MIME formats per item, 32 MiB |
| Aggregate encrypted-record plaintext | 128 MiB |
| Protected conflict/recovery backups | 4 |

A new publication checks event count and aggregate encrypted/decompressed bytes
before reserving a sequence and again before transport publication. Private
record preflights include the future publication fingerprint, including every
resolution projection phase. A delivered event with a reserved ID must also
match the retained authenticated contents before witnessing or accepting it. Multi-tip
resolution also requires enough event slots for all remaining merges; each
step checks byte capacity again. A race can retain a reserved event for review,
but cannot authorize exceeding these bounds. A history exactly at the limit
remains readable. Further local edits remain local; no event is deleted to make
room. Oversized scans pause automatic synchronization with a recovery message.

There is no automatic pruning or in-place K-SYNC replacement in protocol v1.
Use **Start compact successor history** to start one new root from the current
local tab and free publication capacity. The old state, vault, branches and full
transport are retained. **Rotate shared key — retain history** re-encrypts the
complete graph under a new key without reducing its size. Both use the durable
[history transition](HISTORY-TRANSITIONS.md) and explicit successor Join on peers.
Do not delete ancestors, reset private records or interpret an absent mount as empty.

## Verification

Native tests cover persisted ancestor replacement, withheld unaccepted branches,
restarts, real process interruption before divergent recovery, an interrupted
backup commit, full archive capacity, exact aggregate publication boundaries and
the actual 1000-event ceiling. Existing tests retain explicit two-/three-tip
merges, stale decisions, projection interruptions, protected rows and exact
reserved-publication retries. Frozen schema-1–5 vectors remain unchanged; an independent Python/AES-GCM
oracle also freezes schema 6.

The official CopyQ GUI driver additionally restarts with a withheld non-head
ancestor and with a freshly authenticated replacement under the public fixture
key. It checks unchanged accepted/local state, paused automatic synchronization
and explicit resumption after trusted files are restored. Its separate Nextcloud
mode keeps testing real desktop-client delivery without intentionally corrupting
server files.
