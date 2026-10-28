# Subsequent publication and opt-in automatic synchronization

The external `securesync` module operates on unmodified CopyQ 17. No patched
host, external Python writer or service is required. Complete [device setup](DEVICE-SETUP.md)
and finish any pending recovery before using these commands.

## Commands

- **Publish local changes** publishes the durable local snapshot if the accepted
  head is still the sole authenticated tip. An unchanged snapshot does nothing.
- **Synchronize now** imports a newer tip when local contents are clean, or
  publishes dirty local contents when remote history has not advanced. Local
  and remote changes together refuse; no winner is selected.
- **Retry reserved publication** completes an interrupted later publication
  using exactly the reserved ciphertext and sequence. Pending first Seed uses
  **retry reserved Seed**. Ordinary local edits never replace a reserved target.
- **Start automatic synchronization** enables change notifications and periodic
  checking through a supervised CopyQ action, and persists the preference. Stock text, image, notes and FakeVim
  plugins and stock Pinned/Tags may remain enabled. Disable incompatible storage plugins
  (`itemsync`, `itemencrypted`) and unknown third-party
  loaders; refusals name the incompatible loader. This avoids bypassing locked
  tags/pins or competing tab ownership. A locked vault waits for explicit unlock.
  A second loop is refused. No password is stored in scripts or settings.
- **Stop automatic synchronization** stops scheduling. An operation already
  inside an atomic commit may complete it; later import steps are cancelled.
  Reload and explicitly recover a retained journal. No worker is forcibly killed.

Automatic synchronization works while the selected tab and main window are
visible. Transport scan/encryption/delivery run in a worker. Reservation and
head acceptance run serially with local saving; later edits are retained rather
than overwritten by a captured publication. Incoming replacement uses the
existing journal/import coordinator on the callback-bound public Qt model.
The same profile session lease spans a job and any loaded model.

Import/recovery transactions run on a worker, including encrypted record reads,
journal commits and authenticated durable readback. Only model capture, policy
checks and replacement are dispatched to the GUI thread. The same model adapter
spans those calls, so intervening edits (including an edit-and-undo), a new editor
or a destroyed tab cannot authorize a stale replacement. While the worker owns
the record, saver/loader callbacks fail fast; on return, current committed model
contents are checkpointed with any retained journal before normal saving resumes.
The public synchronous saver callback and boundary checkpoints still require a
confirmed atomic save. They never wait for CopyQ's delayed cache write or a timer.

## Scheduling, local durability and retry

The plugin observes committed model changes and uses its own local checkpoint
timer even when automatic synchronization is off. A short burst is saved after
250 ms of quiet; continuous edits request a checkpoint within 1 second. These
are scheduling deadlines, not disk-I/O deadlines: a busy GUI or an import worker
can defer execution. Ordinary synchronous CopyQ saver callbacks still commit
immediately and only acknowledge a verified durable record. Scheduled edits
remain in memory until their checkpoint succeeds; abrupt process termination
before that barrier can lose those newest edits. Normal shutdown checkpoints
committed model contents before CopyQ destroys tabs.

During import the worker exclusively owns the record. Its Qt model notifications
do not trigger outgoing work. Completion checkpoints the current committed model
with the authoritative journal, including intervening user edits. Only contents
different from the authenticated accepted snapshot can become a new outgoing
version. Repeated unchanged saves and import notifications do not allocate IDs.

Local changes and transport notifications coalesce for 500 ms, with a 2-second
maximum scheduling delay during a continuous burst. A bounded, shallow directory
watch covers transport, `events/`, device directories and an existing ancestor
for missing-folder recreation. Watch registration is refreshed after changes and
cycles. Notifications confer no trust: every actual operation still authenticates
history through pinned filesystem handles. Watch failure, missed notifications
or unobserved device directories are covered by a 30-second idle poll.

Transient transport errors, incomplete delivery and reserved-publication failures
retry after 1, 2, 4, 8, 16 and 30 seconds. Further attempts become recovery probes
at most once per 60 seconds. Folder noise and additional edits do not bypass
this delay. Successful reconciliation resets the retry burst.
An unavailable accepted-history file also defers an already reserved publication;
restoration must authenticate against the retained head before that exact intent
can proceed. A changed accepted event or divergent branches still require review.
Local checkpoint failures have their own identical retry policy, retain dirty model contents and
do not depend on transport availability. A missing/corrupt private record never
initializes a replacement. File-system recovery can therefore resume saving
without dropping the pending local changes.

Editors, protected rows, removed tabs and incompatible plugins defer work and
are checked again after 2 seconds. Locked encryption and unfinished setup/key
lifecycle wait for explicit unlock/setup. A conflict blocks publication but
continues to inspect changed history and poll periodically: an authenticated
merge delivered from another device can be imported when local data are clean.
Unresolved branches never select a winner. Recovery and reserved operations
requiring a decision pause attempts; notifications cannot discard a journal.
Unlock, an explicit Start, a completed manual recovery or an
applied profile permits a fresh check. No password prompt is opened by a timer.

The scheduling client asks the server for its next due time and keeps a bounded
heartbeat; idle heartbeats do not scan transport or rewrite encrypted state.
Failure to launch the client uses the same capped retry intervals. A stale
client is terminated, then killed after a grace period if necessary; workers and
the CopyQ GUI server are never forcibly terminated by that mechanism.

Stop, settings invalidation and shutdown cancel outstanding GUI requests. Shutdown
cancels before joining, so the worker cannot wait for the GUI thread that is
joining it. It then checkpoints committed edits before tab destruction. The
current kernel I/O/atomic commit is allowed to return; cancellation does not
prove that an in-flight commit did not become durable. Tab deletion cancels the
bound job without recreating the tab or resetting its encrypted record.

Authorized manual state/import/recovery actions return immediately from the plugin
callback. Capability `device-setup/5` returns `Working:<token>`; query
`operationStatus(token)` for `Working` or the final result. The provided CopyQ
commands poll from their script action; the GUI event loop remains available.
Tokens identify one invocation, not authority to reuse a previous result.
Admission is reserved before password dialogs open their nested event loop;
Stop/settings changes invalidate the authorization before it starts a worker.
The scheduling action supplies the public tab list each cycle and waits if the
configured tab was deleted. A completed manual action also checks tab existence
before showing it; neither completion nor scheduling silently recreates a tab.

A live update requires an identified public Qt item view bound to that exact
model. Writable text widgets and the documented external-editor signal/slot
contract defer replacement; unknown or missing view identity also defers.
Closing the editor lets a later cycle proceed. The loop never closes editors,
hides the window, switches tabs or forces unloading. Manual setup/key/handoff
commands retain their existing ordinary-unload guards.

The **automatic synchronization** preference persists across CopyQ restarts.
Only the GUI server supervises it; CLI/plugin test processes do not spawn loops.
The supervisor schedules an ordinary action using the installed CopyQ executable,
with no extra daemon or shipped helper. After restart, unlock Secure Sync once:
scheduling resumes without another Start action. A locked vault waits without
repeated prompts or saved passwords; an unjoined profile still requires Seed/Join.
Stop clears the persisted preference. Cancelling a generic CopyQ action while
this preference stays enabled allows the supervisor to resume scheduling.

Stop cancels read-only preparation and future cycles. An already reserved event
finishes or retains its exact journal; shutdown joins an in-flight worker.
Changing settings or stopping during a conflict dialog invalidates that decision
before reservation. Keys remain in memory while a loaded model or authorized
loop needs them, and are never written into scripts/settings.

## Explicit conflicts and protected backups

**Compare and resolve conflicts** offers local contents, all distinct items
from local and authenticated tips, or one selected tip. There is no automatic
winner. Confirming creates an encrypted local backup and freezes the chosen
result in a reserved revision. Fresh graph and whole-record checks reject
stale dialogs. A new branch or later local edit stops continuation for review.
Protocol v1 permits two parents: several tips are joined by successive merge
events carrying the same chosen result. History remains immutable.

The resolution wizard continues even when ordinary automatic sync is off.
After the last merge, a journal projects the accepted result into the tab;
an active editor postpones this step. Interrupted resolution projection resumes
from its original/target journal, while ordinary interrupted imports still use
explicit recovery. Divergent local edits require the explicit preserve-and-recover
commands described in [conflicts and history](CONFLICTS-AND-HISTORY.md).

An exact publication already reserved before new branches arrived can be
reconciled through an explicit confirmation in the conflict dialog. It never
allocates a new sequence or replaces the frozen ciphertext; the current
branches then require another decision.

**Restore a protected conflict backup** publishes that snapshot as a new
revision and replaces its backup slot with current local contents. Up to four
backups are retained, subject also to the 128 MiB total-record ceiling. Capacity
refuses a new decision without deleting anything. **Remove a protected conflict
backup** requires a separate explicit confirmation and a fresh whole-record CAS. During
an interrupted resolution, older backups can be removed while its active original
backup remains protected. The complete future projection journal is budgeted
before reserving/publishing a chosen result, including its local checkpoint phase.
For offline preservation stop synchronization/close CopyQ and retain both the
private encrypted record and its password vault; a vault-only backup does not
contain tab data. Published remote versions remain in transport history.

## Atomic publication and state version

Private record schema 4 extends schema 3's binary layout and permits a pending
publication alongside its retained accepted head. Its one parent must equal that
head until an explicit schema-5 resolution is started. Older schemas 1–3 and their frozen fixtures remain readable. Upgrade is
explicit on the first subsequent publication; settings remain schema 3 and the
transport remains protocol v1. Older plugin versions refuse schema 4: keep an
encrypted backup before upgrading and use the documented encrypted handoff for
removal, rather than downgrading an active private record.

Before any event write, one authenticated atomic state commit reserves the
per-device sequence and exact encrypted envelope. The allocation counter is
independent of local save generations and received devices' sequences. It never
moves backwards; the next sequence also accounts for authenticated transport
history. Missing accepted heads, changed accepted contents, multiple tips and
exhausted counters refuse publication. An established missing/corrupt record
never initializes an empty profile.

Publishing uses immutable no-overwrite event names. Exact ciphertext readback
and durability confirmation precede committing the accepted head and clearing
the publication intent. Windows uses the optional **Private publication staging
folder** (`publication_staging`), or the private data directory when unset.
It must already exist, permit file creation, have a protected private DACL and
reside on the same fixed NTFS volume as transport, outside its directory tree
and separate from the vault. For example, private data on C: and Nextcloud on
D: require a private staging folder on D: outside Nextcloud. The plugin checks
this before reserving a new ID, then rechecks pinned directory handles at
publication. It never falls back to cross-volume copying or a public TEMP folder.
Linux keeps anonymous staging and does not use this setting.

The staging path is an I/O setting, not part of the record/vault binding. Stop
automatic work and unload the tab before correcting it in settings; no reset,
new device ID or key migration is needed. A previously reserved event retains
its exact ciphertext and sequence. Retry can confirm an already published event
even if its former staging folder is unavailable. Uncertain writes retain old
or new whole state; retry reconciles that exact event instead of allocating
another ID.

Transport delivery may create a competing branch after a scan. A later scan
reports conflict and stops; no scan can establish a distributed global lock.
Conflicts require the explicit resolution described above.
Incomplete/offline/unsafe transport leaves data intact and reports waiting.
Pending import/publication or local/remote divergence stops automatic work and
requires explicit recovery. Only an already confirmed resolution projection can resume automatically.

## Validation scope

Core/native tests cover bidirectional subsequent publication, independent device
counters, unchanged cycles, ten additional publication state-commit crash points,
three additional transport-publication crash points, retained later edits, missing accepted heads, divergent local/remote contents and
pending-intent refusal. An independent Python AES-GCM/binary encoder supplies a
frozen schema-4 vector without changing earlier vectors. Actual-module tests
exercise the asynchronous worker, exclusivity, key retention and stop behavior.

The disposable two-process driver supports `--device-setup --auto-sync`: it uses
two isolated official CopyQ 17 AppImage sessions, shared local transport and only
public fixture keys. It exercises Seed/Join, automatic publication/import in both
directions, exact supported MIME data, stop/restart and absence of extra revisions.
This does not certify physical cloud delivery, native Windows GUI or Flatpak.

Schema 5 appends bounded encrypted conflict backups and confirmed resolution tips.
Schemas 1–4 keep their frozen byte layout. A resolution publication uses parents
from those confirmed tips; final projection must match its accepted head and
original backup. An independent Python AES-GCM oracle includes schema 5.
Schema 6 additionally retains fingerprints of all observed history, including
unaccepted branches. See [conflicts and history](CONFLICTS-AND-HISTORY.md) for
recovery choices, rollback checks, limits and upgrade/downgrade constraints.
Older modules refuse newer schemas rather than discarding additional state.

The cross-platform GUI driver loads the external module into official CopyQ 17,
checks selected visible tabs, bidirectional publication, unlock-only restart
resume and actual conflict choice dialogs. Windows runs it on hosted native
Windows/NTFS with the checksum-verified portable release. Flatpak builds the
module in KDE SDK 6.10 and tests the installed Flathub application with scoped
fixture-folder access; exact app/runtime identities are retained in reports.
A workflow definition is not evidence that a platform run passed: consult the
specific commit's CI reports. Install/upgrade/removal acceptance and physical
cloud delivery remain separate release gates.

Resolution regression tests inject 25 process exits across reservation, head
acceptance and projection commits, alongside exact-event reconciliation after
new branches and stale archive-removal refusal.
