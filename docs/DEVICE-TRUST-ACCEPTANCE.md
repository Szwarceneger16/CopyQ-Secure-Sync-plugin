# Device trust: acceptance matrix and gates

Status: stage-1 design deliverable. Every case below is planned, not passed.
This matrix does not replace the current [release gates](RELEASE-READINESS.md).
Scope and guarantees: [security design](DEVICE-TRUST-DESIGN.md) and
[installer/UX contract](GUIDED-SETUP-DELIVERY.md).

## Required acceptance evidence

All fixtures must use synthetic clipboard data, public test keys, disposable
directories and device aliases. No real secrets or identifying paths in CI.
Each future report records the tested commit, platform, test identifier and
result; a listed case or successful old RC test is not new-feature evidence.

| ID | Scenario | Required outcome |
| --- | --- | --- |
| AUTH-01 | Genesis member adds second device | Exactly one independently verified signature accepted, bootstrap consumed durably; both complete onboarding. |
| AUTH-02 | Two members add third; four members add fifth | Respectively 2/2 and any 2/4 required; any current device can approve, no founder dependency. |
| AUTH-03 | Duplicate vote, applicant vote, renamed/duplicated installation, same signing key under different IDs | One signing identity counts once; reject duplicate keys/ID collisions; candidate cannot approve itself. |
| AUTH-04 | Missing second vote or offline approver | No compliant key release or completed admission; retain visible pending state. |
| AUTH-05 | Restore old snapshot, hide members, remove/reinstall client | Never regain the one-vote bootstrap exception in an established group; require supported recovery where witnesses are lost. |
| AUTH-06 | Change key, root, request, parent, operation, policy or expiry after display | Invalidate verification and approvals; do not sign or release keys for changed bytes. |
| AUTH-07 | Malicious discovery file claims a familiar hostname | No trust from the label/self-signature; independent bidirectional verification fails or remains required. |
| AUTH-08 | Guess/grind comparison code; retry across sessions | Reviewed construction and attempt policy meet the documented threat model; replayed verification cannot authorize another request. |
| AUTH-09 | Valid key envelope but invalid/missing certificate | No membership or local Join; a bare K-SYNC transfer is not admission. |
| AUTH-10 | Repeated, cancelled or expired request | Durable idempotency or refusal; no new membership/identity from retry. |
| FORK-01 | Two honest disjoint pairs sign children of same parent | Demonstrate the fixed-threshold fork limitation; once observed halt membership, release and auto sync; preserve protected local saves. |
| FORK-02 | One compromised signer equivocates in a three-member group | Same conflict handling; never claim that sign-once on honest clients prevents all forks. |
| FORK-03 | Branch withheld, old membership replayed, local witness retained | Reject observed rollback; report only the locally known state, never guarantee detection of hidden evidence. |
| FORK-04 | Concurrent joins/removals, stale approvals, partial delivery | Do not combine votes across parents/branches; fresh verification on changed intent. |
| FORK-05 | Conflicting child arrives for an ancestor several epochs behind current head | Detect the deep fork using retained history, halt and preserve both; do not inspect only current-head siblings. |
| FORK-06 | Honest members reserve different partial proposals; expiry/cancel/restart follows | Visible blocked state and explicit recovery if progress is impossible; never discard reservations to sign another child. |
| KEY-01 | Package delivered before/after candidate acknowledgement | Show authorization, delivery and completed local Join separately. |
| KEY-02 | Remove founder with three members | Other two authorize; fresh future-data key reaches only survivors; they retain approval capability. |
| KEY-03 | Removal target signs, one survivor only, or two-device loss | Refuse normal removal/admission; no silent threshold reduction. |
| KEY-04 | Offline removed client returns with old writes | Preserve old edits; never accept them as new-generation writes or hand out successor keys to that identity. |
| KEY-05 | Revoked client knows old keys and retained ciphertext | Future keys not delivered under old group key alone; no claim to recall old data. |
| KEY-06 | New member joins archive; compaction or rollover | Explain full-history access, verify trust chain/root/policy survives data compaction. |
| REC-01 | Recover with offline credential and required encrypted material | Fresh verified group/root and keys; retain original archive, explicit peer rejoin. |
| REC-02 | Only ordinary password, wrong credential, stale/incomplete backup | No fabricated quorum or empty replacement; clearly state recoverable scope and retain evidence. |
| REC-03 | Fresh-machine restore and recovery-credential rotation | Verify included generations/snapshot, detect missing data, invalidate old authority under the selected recovery design. |
| IO-01 | Symlink/reparse/hardlink/special file/path swap, oversized/ambiguous JSON | Bounded safe rejection; no out-of-root access, decompression before authentication, code execution or secret echo. |
| IO-02 | Crash after each durable pairing/key/membership step | Resume exact intent and bytes or stop safely; never duplicate signing, seed or nonce under a different operation. |
| IO-03 | Missing permissions, unmounted folder, disk full, conflict copies | Pause/refuse without resetting storage; retain vault, state and local edits. |
| UI-01 | New user installs/pairs two machines | No terminal, Python, compiler or manual private-path management. |
| UI-02 | Three devices, then add fourth with two nonfounders | All normal approval UI works without founder online; progress accurately reports 0/2 and 1/2. |
| UI-03 | Toggle other plugin settings after inventory refusal | Current preflight refreshes independently of last action; no stale error portrayed as current diagnosis. |
| UI-04 | Existing key, recovery, history and removal actions; Cancel Preferences afterward | Remain in normal Preferences with scope/confirmation; explain immediate effects and never imply completed actions were undone. |
| ENC-01 | Core Encrypt Tabs, other encrypted tabs, synced tab | Preserve settings, exact contents and verified encrypted storage after save, unlock and restart. |
| ENC-02 | Legacy GPG plugin for other tabs/items plus Secure Sync | Prove saver/loader coexistence or refuse with data intact; never disable global encryption or just remove guard. |
| ENC-03 | Competing ownership of synced tab; populated tab; protected rows/editor | Explicit backed-up migration or refusal; no plaintext intermediate export or silent replacement. |
| INS-01 | Clean Windows installed/portable and installed Mint Flatpak | Correct ABI module and GUI server proof; works as standard user without developer tools. |
| INS-02 | Restart, autostart, multiple CopyQ sessions | Same intended module/profile loaded; unrelated sessions/launch entries preserved. |
| INS-03 | Flatpak access grant and removal | Only selected directory access, persistent provider paths; no broad grant or override reset; lost access safely pauses. |
| INS-04 | Tampered package/metadata, old version, substituted installer | Authenticated distribution model validated, wrong origin/version refused, bootstrap trust explicitly documented. |
| INS-05 | Staging/activation crash or user edits old launch configuration | Resume or compare-before-restore owned changes; do not overwrite later edits or touch keys. |
| INS-06 | Update and attempted downgrade after schema migration | Preserve records; unsupported downgrade refused with recovery path. |
| INS-07 | Uninstall after encrypted handoff or retained archive | Verify handoff before module removal; never delete state/vault/original data by default. |
| MIG-01 | Existing v1 archive and old/new writers | Explicit preserved successor migration; legacy transfer cannot bypass new admission. |
| SYS-01 | Real Windows + Mint + real Nextcloud desktop delivery | Pair, text/image sync both ways, offline edits, restart, loss/recovery and removal; verified on exact build. |

## Implementation gates

The product decisions above form the stage-1 baseline. The following unresolved
engineering decisions are mandatory gates with an accountable work item and
reviewed evidence, not defaults implementers may guess or a request for routine
user permission. No new-protocol production key release until G1-G5 are resolved
and reviewed. Distribution additionally requires G6; stable qualification requires
G7. Development/test prototypes use synthetic keys and data only.

| Gate | Deliverable / exit condition |
| --- | --- |
| G1: peer verification | Select a reviewed authenticated pairing/SAS or QR construction, including both-end root binding, anti-grinding, attempt limits, expiry/clock rules and restart behavior. Obtain protocol/security review. |
| G2: encoding and crypto | Specify exact versioned canonical signed bytes, domains, signature/HPKE suite and maintained cross-platform library, parser budgets and frozen independent vectors. No custom primitive or shortened-code assumption. |
| G3: membership state machine | Model bootstrap, 2-distinct approvals, local sign-once durability, concurrent operations, fork detection and fail-closed recovery. Demonstrate FORK-01/02 rather than claim asynchronous consensus. |
| G4: recovery/key lifecycle | Specify independent offline authority, encrypted package contents/freshness, recovery rotation, key generations, future-key release and protected local journals; prove crash recovery. |
| G5: compatibility | Specify versioned event signatures and v1 migration; qualify real CopyQ saver/loader coexistence and unsupported mixed writers. |
| G6: delivery | Select installer framework, signed distribution/root bootstrap, update/rollback transaction, persistent launcher and scoped permission mechanism. Qualify clean-machine lifecycle. |
| G7: product qualification | Complete exact-build matrix, physical devices, independent security review of code and design, restore drill and privacy scan; no stable-release claim based solely on model/CI results. |

## Planned implementation slices

| Slice | Output | Relevant foundations |
| --- | --- | --- |
| 1 (this change) | Reviewable design, threat boundary, product contract and acceptance IDs. No runtime/protocol/workflow change. | Existing docs and source contracts. |
| 2 | G1-G4 concrete protocol decisions; isolated policy/state model and adversarial tests; synthetic vectors before production crypto integration. | `src/history.*`, private state/vault transactions. |
| 3 | Signed membership, per-device identity, pairing/key package coordinator and durable resume; versioned events/migration (G5). | `native/key_vault.*`, `native/unified_state.*`, `native/history_transition.*`. |
| 4 | Wizard, current-state reporting, normal advanced Preferences, coexistence qualification. | `native/settings_widget.*`, `native/plugin.cpp`, `tests/native_settings_test.cpp`. |
| 5 | Windows and Mint Flatpak automatic installer/update/uninstall (G6); framework work may run alongside slice 4 once interfaces stabilize. | `tools/install.py`, `tools/installation.js`, installed-host GUI tests. |
| 6 | Multi-device recovery/removal/migration hardening, physical acceptance and independent review (G7). | `tests/key_vault_test.cpp`, `tests/history_transition_test.cpp`, `tests/run-copyq-gui-platform.py`, `tests/run-flatpak-installation.py`. |

Normal data synchronization keeps existing editor, protection, save and history
guards. Do not disable tests, weaken path checks or broaden CI privileges to make
new acceptance pass. Workflow implementation, if needed later, is a separate
reviewed change. No task completion here means that any future acceptance case
has run: implementation reports must link actual results.
