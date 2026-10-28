// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "ui_actions.h"
#include <QJsonDocument>
#include <QJsonObject>
namespace cqs::native {
// No input string is ever echoed: diagnostic fields are an explicit allowlist.
struct UiContext {
    bool configured=false, enabled=true, locked=true, busy=false, automatic=false;
    bool dirty=false, verified=false, saveProblem=false;
    bool pendingImport=false,pendingPublication=false,pendingResolution=false,unjoined=false;
    bool historySuspended=false;
};
struct UiStatus {
    QString code, title, detail, saved, next;
    QString text() const { return title+"\n"+detail+"\n"+saved+"\n"+next; }
    QString diagnostic(const UiContext &c) const {
        return QString::fromUtf8(QJsonDocument(QJsonObject{
            {"format",1},{"component","securesync"},{"state",code},
            {"automatic",c.automatic},{"locked",c.locked},{"operation_active",c.busy},
            {"local_save",c.saveProblem?"unconfirmed":c.dirty?"pending":c.verified?"verified":"unchecked"}
        }).toJson(QJsonDocument::Indented));
    }
};
inline UiStatus presentStatus(const UiContext &c,const QString &result={}) {
    UiStatus s{"ready",uiText("Ready"),uiText("No synchronization operation is running."),
        uiText("Local data: not verified in this session. Unlock and load the tab to check."),
        uiText("Next: synchronize now, or enable automatic synchronization.")};
    if(c.verified) s.saved=uiText("Local data: the committed tab contents were verified in encrypted storage. Uncommitted editor text is excluded.");
    if(c.dirty) s.saved=uiText("Local data: recent edits are waiting for an encrypted save. Keep CopyQ running until saving succeeds.");
    if(c.saveProblem) s.saved=uiText("Local data: saving is unconfirmed. An older or newer complete record may exist; keep CopyQ running and retain the record and vault.");
    auto state=[&](const char *code,const char *title,const char *detail,const char *next){s.code=QLatin1String(code);s.title=uiText(title);s.detail=uiText(detail);s.next=uiText(next);};
    if(result=="Applied"||result=="Restored"||result=="AdoptedPreservedTab"||result=="MigratedUnifiedState")
        s.detail=uiText("The operation completed with a verified encrypted record. Publication in the local sync folder does not confirm delivery to another device.");
    else if(result=="UpToDate")s.detail=uiText("The last check required no change. Delivery to another device is confirmed only by that device.");
    else if(result=="Initialized"||result=="InitializedFromSharedKey")s.detail=uiText("Empty encrypted storage is initialized. Use Seed on the first device or Join on a later device.");
    else if(result=="Enabled"||result=="Started")s.detail=uiText("Automatic synchronization is enabled. It resumes after Secure Sync is unlocked.");
    else if(result=="Stopped")s.detail=uiText("Automatic synchronization is stopped. Independent local saving remains active.");
    else if(result=="PasswordChanged"||result=="KeyRotated"||result=="VaultBackedUp"||result=="VaultRestored"||result=="VaultRepaired"||result=="SyncKeyExported")
        s.detail=uiText("The requested key operation completed. This does not confirm a new save of the tab or delivery to another device.");
    else if(result.startsWith("HistoryTransitioned")){
        s.detail=uiText("The successor key and history are active. The old encrypted profile and history were retained. Automatic synchronization is off.");
        s.next=uiText("Next: back up the new vault, share the NEW key separately, and Join successor on other devices before enabling automatic synchronization.");
        if(result.contains("journal still contains"))s.next=uiText("Next: use Seal journal of active successor with the original journal password. Until then the private journal remains an encrypted backup of the new keys.");
    }
    else if(result=="HistoryTransitionFinalized")s.detail=uiText("The active successor was verified and the transition journal now contains a receipt without encryption keys.");
    else if(result=="HistoryTransitionCancelled")s.detail=uiText("The old profile is active again. Keep incomplete destination files separate; never Join that cancelled destination.");
    else if(result=="Cancelled")s.detail=uiText("The dialog was cancelled. No decision was accepted.");
    else if(result=="BackupRemoved")s.detail=uiText("The selected protected backup was explicitly removed. Current tab data and published history were retained.");
    else if(result=="PreservedNativeTab"||result=="AlreadyPreserved")s.detail=uiText("The ordinary CopyQ tab is preserved separately. Apply independent storage setup, then import the preserved tab; keep the source.");
    else if(result=="MigratedLegacyStorage")s.detail=uiText("Earlier encrypted local storage was migrated. Load and verify the tab before Seed or Join.");
    else if(result=="No protected conflict backups")s.detail=uiText("There are no protected conflict backups to restore or remove.");
    else if(result=="DetachCancelled")s.detail=uiText("Pending removal was cancelled. Secure Sync continues to own its encrypted storage.");
    else if(result=="DetachPrepared"){
        s.code="recovery";s.title=uiText("Encrypted removal pending");s.detail=uiText("Encrypted handoff is prepared; removing the plugin is not yet safe.");s.next=uiText("Next: finish encrypted removal from Devices and recovery or the CopyQ command menu.");
    }
    else if(result=="Detached"){
        s.code="detached";s.title=uiText("Encrypted handoff completed");s.detail=uiText("CopyQ has confirmed encrypted ownership of the tab. Independent Secure Sync storage is disabled.");s.next=uiText("Next: retain verified backups and restart CopyQ before removing the module file.");
    }
    else if(!result.isEmpty()&&result!="Unlocked"&&result!="Locked"&&result!="Checkpointed") {
        if(result.contains("history/key transition")||result.contains("profile activation"))
            state("history-transition","History/key transition needs attention","Retain both encrypted profiles and any private transition journal. The old profile may be suspended.","Next: check passwords and paths. If a journal exists and the old profile is active, Resume or Cancel it; otherwise repeat the original action. Restart after unconfirmed activation, then inspect the active profile.");
        else if(result.contains("unconfirmed",Qt::CaseInsensitive)||result.startsWith("Cancelled:")||result.startsWith("Stopping")||result.startsWith("Stopped:"))
            state("recovery","Recovery required","The operation was interrupted or its result is unconfirmed. Encrypted recovery state is retained.","Next: check the saved state, then retry the reserved publication or choose pending import recovery. Never initialize over existing state.");
        else if(result.startsWith("Conflict")||result.contains("multiple authenticated tips"))
            state("conflict","Conflict","More than one version requires an explicit decision. No automatic winner was selected.","Next: compare and resolve conflicts; existing versions remain available.");
        else if(result.contains("unlock Secure Sync"))
            state("locked","Locked","Secure Sync keys are locked; synchronization cannot proceed.","Next: unlock Secure Sync using its separate password.");
        else if(result.contains("key lifecycle"))
            state("setup","Key setup requires attention","An interrupted setup, key rotation or encrypted removal must finish before synchronization.","Next: use the matching key or removal action; retain the existing record and vault.");
        else if(result.contains("preserve local edits"))
            state("recovery","Local edits require a decision","Current data differ from the expected version. No edits were discarded.","Next: for a pending import, back up new edits and retry or restore. Otherwise publish local edits or compare conflicts first.");
        else if(result.contains("configured tab was removed"))
            state("waiting","Synchronized tab is unavailable","The configured tab was removed. Its encrypted record is retained; synchronization does not recreate it automatically.","Next: review the retained record and deliberately restore the tab before resuming synchronization.");
        else if(result.contains("incompatible")||result.contains("plugin inventory"))
            state("error","Plugin configuration requires attention","The active plugin inventory is incompatible with safe Secure Sync storage.","Next: review enabled storage plugins. Keep supported renderers, Pinned and Tags; disable competing storage plugins before retrying.");
        else if(result.contains("scheduling client"))
            state("waiting","Waiting for CopyQ scheduling","The automatic synchronization client could not connect to this CopyQ session.","Next: check that CopyQ can launch its own command client. Automatic mode retries with backoff; restart CopyQ if needed and unlock Secure Sync.");
        else if(result.contains("editor")||result.contains("pinned or locked")||result.contains("unload")||result.contains("model verification"))
            state("waiting","Waiting for the tab","The tab cannot safely be replaced while an editor or item protection blocks it.","Next: finish editors, release the relevant protection if intended, and retry. No forced unload is used.");
        else if(result.contains("Seed or Join")||result.contains("no authenticated history")||result.contains("history already exists")||result.contains("already joined")||result.contains("device ID"))
            state("setup","Device setup required","The selected device operation does not match the existing history or tab.","Next: use Seed only for a new history; use Join with a unique device ID for an existing history. A nonempty tab can Join with a protected backup.");
        else if(result.contains("all four protected backup")||result.contains("capacity reached"))
            state("recovery","Storage capacity reached","Protected backups or the private record have reached their safe limit. Existing state is retained.","Next: keep an offline record and vault backup, export verified data, then explicitly remove an unneeded protected backup and retry.");
        else if(result.contains("limit reached"))
            state("recovery","History capacity reached","The history has reached a safe event, file or byte limit. Publication is paused.","Next: retain an offline backup and use Start compact successor history while the history is readable. Keep the old record, vault and full transport; never delete ancestors.");
        else if(result.startsWith("Waiting")&&!result.contains("unlock Secure Sync")&&!result.contains("key lifecycle"))
            state("waiting","Waiting for files","Synchronization cannot yet verify all required files or access the synchronization folder.","Next: check Nextcloud desktop delivery and folder availability. Automatic mode retries; keep existing history files.");
        else if(result.contains("pending")||result.startsWith("Recovery")||result.startsWith("Pending"))
            state("recovery","Recovery required","A pending operation or history verification issue needs review. Encrypted state is retained.","Next: restore trusted history files if needed; retry the reserved publication or choose accept, retry or restore for the pending import.");
        else if(result.contains("staging"))
            state("error","Publication folder requires attention","Windows publication needs a private staging folder on the synchronization folder's fixed NTFS volume.","Next: choose a valid private publication staging folder, apply settings, then retry the reserved operation.");
        else state("error","Action requires attention","The request was refused or could not be verified. No empty replacement of existing private state was created.","Next: check the applied profile, password, private folder permissions and active plugins. Retry after correcting the cause; retain existing files.");
    }
    if(!c.locked&&s.code=="ready"){
        if(c.pendingImport)state("recovery","Pending import recovery","The encrypted record contains an unfinished import. Loading the tab does not accept or discard that operation.","Next: choose accept pending target, retry import or restore original. Back up divergent new edits before replacing them.");
        else if(c.pendingResolution)state("recovery","Pending conflict decision","An encrypted conflict decision has not finished publication or local application.","Next: unlock Secure Sync and enable automatic synchronization to continue the retained decision. For an interrupted import, use its matching recovery action.");
        else if(c.pendingPublication)state("recovery","Pending publication","The encrypted record retains an exact reserved event. Its publication or acceptance is not yet confirmed.","Next: retry reserved Seed for the first event, or retry reserved publication for later events. Do not create another history or reset the record.");
        else if(c.unjoined)state("setup","Device setup required","Local encrypted data are available, but this device has not joined a synchronization history.","Next: Seed the first history, or Join an existing history. Use Join with a protected backup to keep nonempty local data.");
    }
    if(!c.configured&&s.code!="detached"){
        const auto outcome=s.detail;
        state("setup","Configuration required","Configure a private state folder and password-protected vault outside the synchronization folder.","Next: apply the configuration, initialize empty storage or import a shared key, then Seed or Join.");
        if(!result.isEmpty())s.detail=outcome+"\n"+s.detail;
    }
    else if(!c.enabled)state("disabled","Plugin disabled","Secure Sync actions are disabled.","Next: enable the plugin. Complete encrypted handoff before removing it.");
    else if(c.busy)state("syncing","Synchronizing","An operation is running. Its final save and publication result are not confirmed yet.","Next: wait for completion. Stop automatic synchronization requests safe cancellation and retains recovery state.");
    else if(c.saveProblem)state("error","Local save requires attention","The latest local save could not be confirmed.","Next: check private storage and keep CopyQ running. Retry saving before closing, locking or removing the plugin.");
    else if(c.historySuspended)state("history-transition","Old profile suspended","A recorded history/key transition owns this profile. Ordinary loads, writes and synchronization are blocked; encrypted data were retained.","Next: Resume the recorded history/key transition. Cancel is available only while the old profile is still active; keep every destination and archive.");
    else if(c.locked&&s.code=="ready")state("locked","Locked","Secure Sync keys are locked; synchronization cannot proceed.","Next: unlock Secure Sync using its separate password. No password is stored for automatic startup.");
    return s;
}
} // namespace cqs::native
