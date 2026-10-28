// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QString>
#include <QList>
#include <QCoreApplication>
namespace cqs::native {
struct UiAction { const char *id; const char *label; const char *confirmation; };
inline const QList<UiAction> &uiActions() {
    static const QList<UiAction> actions{
        {"rotateSyncKey", "Rotate shared key — retain history…", "Stop synchronization on every device first. Re-encrypt the complete authenticated history into a NEW folder with a NEW shared key? Old encrypted history and keys remain as an archive. Other devices must explicitly join using the separately shared new key."},
        {"compactHistory", "Start compact successor history…", "Stop synchronization on every device first. Start a NEW history and shared key from this tab's CURRENT local contents? Unsent local edits are included. Other branches and older versions remain in the retained old history. Other devices must explicitly join the successor."},
        {"joinSuccessor", "Join successor — preserve local edits…", "Switch to the separately authenticated new key and history? Current local contents will be preserved in an encrypted backup if they differ. The old profile and history will be retained."},
        {"resumeHistoryTransition", "Resume interrupted history/key transition…", nullptr},
        {"finishHistoryTransition", "Seal journal of active successor…", "Verify the active successor and remove key material from its transition journal? The journal becomes a receipt and cannot resume or cancel the old profile."},
        {"cancelHistoryTransition", "Cancel inactive history/key transition…", "Reactivate the old profile only while it is still selected in saved settings? Keep all destination files. Never Join or use that cancelled destination on other devices."},
        {"seedHistory", "Seed — first device…", "Publish this tab as the first encrypted history? Use Join on later devices. Existing history will never be overwritten."},
        {"joinHistory", "Join — empty tab…", "Import the existing authenticated history into an empty tab? A nonempty tab will be refused."},
        {"joinPreservingLocal", "Join — keep local backup…", "Import the existing history and keep this tab's current contents in an encrypted local backup?"},
        {"syncNow", "Synchronize now", nullptr},
        {"enableAutomaticSync", "Enable automatic synchronization", nullptr},
        {"stopAutomaticSync", "Stop automatic synchronization", nullptr},
        {"resolveConflict", "Compare and resolve conflicts…", nullptr},
        {"retrySeed", "Retry reserved Seed", nullptr},
        {"retryPublication", "Retry reserved publication", nullptr},
        {"acceptPendingTarget", "Accept pending imported version…", "Accept only if the current data match the pending imported version? Other data will be refused."},
        {"retryPendingImport", "Retry pending import", nullptr},
        {"restorePendingOriginal", "Restore version before import…", "Restore the encrypted version saved before the interrupted import? Divergent new edits will be refused."},
        {"preserveAndRetry", "Back up new edits and retry import…", "Keep divergent new edits in an encrypted local backup, then retry the pending import?"},
        {"preserveAndRestore", "Back up new edits and restore original…", "Keep divergent new edits in an encrypted local backup, then restore the version from before import?"},
        {"restoreArchive", "Restore protected backup…", nullptr},
        {"discardArchive", "Remove selected protected backup…", nullptr},
        {"restorePreserved", "Restore data kept before Join…", "Restore the data kept before Join? The guarded recovery refuses an incompatible current state."},
        {"preserveNativeTab", "Preserve ordinary CopyQ tab before setup", "Preserve the ordinary synced_tray tab under a separate name before enabling independent storage? CopyQ Encrypt Tabs must be enabled. The source is never overwritten."},
        {"adoptFromTab", "Import preserved CopyQ tab (keep source)", "Import the preserved ordinary tab into empty Secure Sync storage? The source tab will be kept."},
        {"migrateUnifiedState", "Upgrade earlier local checkpoint", nullptr},
        {"lockStorage", "Lock Secure Sync", nullptr},
        {"detachStorage", "Finish encrypted removal…", "Hand the tab back to CopyQ encrypted storage before removing Secure Sync? Enable CopyQ Encrypt Tabs first. Keep the plugin installed until handoff is confirmed."}
    }; return actions;
}
inline const UiAction *uiAction(const QString &id) {
    for (const auto &action:uiActions()) if(id==QLatin1String(action.id)) return &action;
    return nullptr;
}
inline QString uiText(const char *text) { return QCoreApplication::translate("SecureSyncUI",text); }
} // namespace cqs::native
