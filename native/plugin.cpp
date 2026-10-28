// SPDX-License-Identifier: GPL-3.0-or-later
#include "plugin.h"
#include "cqs-version.h"
#include <QIcon>
#include <QMessageBox>
#include <QVariantList>
#include <QInputDialog>
#include <QLineEdit>
#include <QApplication>
#include <QFileDialog>
#include <QDir>
#include <QCoreApplication>
#include <future>
#include <QCryptographicHash>
#include <set>
#include <algorithm>
#include <QScopeGuard>
#include "packed_items.h"
#include <QUuid>
#include "common/command.h"
#include "state_store.h"
#include "unified_state.h"
#include "storage.h"
#include "plugin_inventory.h"
#include "model_clipboard.h"
#include "gui_clipboard.h"
#include "ui_actions.h"
#include "history_transition.h"

struct SecureSyncJob {
    cqs::native::StorageConfiguration configuration;
    cqs::native::StorageKeysPtr keys;
    std::shared_ptr<cqs::transaction::Store::Lease> session;
    cqs::transaction::Record input;
    std::optional<cqs::events::AuthenticatedHistory> history;
    std::optional<cqs::transaction::Publication> publication;
    QString token,error;
    quint64 epoch=0,control=0;
    bool reviewedContext=false;
    std::shared_ptr<cqs::native::OperationControl> operation=std::make_shared<cqs::native::OperationControl>();
    std::shared_ptr<cqs::native::GuiClipboard> clipboard;
    std::optional<std::size_t> restoredArchive;
};

namespace {
bool copyqGuiServer(){
    if(!qobject_cast<QApplication *>(QCoreApplication::instance()))return false;
    const auto session=qEnvironmentVariable("COPYQ_SESSION_NAME");
    const auto expected=session.isEmpty()?QStringLiteral("copyq"):QStringLiteral("copyq-")+session;
    return QCoreApplication::applicationName()==expected;
}
struct Password { cqs::crypto::Bytes bytes; ~Password(){cqs::crypto::wipe(bytes);} };
cqs::crypto::Bytes password(const QVariantList &arguments,int index,const QString &title,bool confirm=false) {
    if(arguments.size()>index&&!arguments[index].isNull()){const auto &v=arguments[index];if(v.metaType().id()!=QMetaType::QByteArray)return {};
        const auto raw=v.toByteArray();return {reinterpret_cast<const std::uint8_t *>(raw.constData()),reinterpret_cast<const std::uint8_t *>(raw.constData())+raw.size()};}
    if(!qobject_cast<QApplication *>(QCoreApplication::instance()))return {};
    bool ok=false;QString text=QInputDialog::getText(nullptr,title,QStringLiteral("Secure Sync password (independent from CopyQ):"),QLineEdit::Password,{},&ok);
    if(!ok)return {};QByteArray raw=text.toUtf8();text.fill(QChar(0));
    if(confirm){QString repeated=QInputDialog::getText(nullptr,title,QStringLiteral("Repeat the new Secure Sync password:"),QLineEdit::Password,{},&ok);
        const auto same=ok&&repeated.toUtf8()==raw;repeated.fill(QChar(0));if(!same){raw.fill(0);return {};}}
    cqs::crypto::Bytes result{reinterpret_cast<const std::uint8_t *>(raw.constData()),reinterpret_cast<const std::uint8_t *>(raw.constData())+raw.size()};raw.fill(0);return result;
}
std::filesystem::path path(const QString &s) {
#ifdef Q_OS_WIN
    return std::filesystem::path(s.toStdWString());
#else
    return std::filesystem::u8path(s.toUtf8().toStdString());
#endif
}
QString operationFailure(){
    try{throw;} catch(const cqs::native::Cancelled &){return QStringLiteral("Cancelled: reload durable state; encrypted recovery retained.");
    } catch(const cqs::native::ModelError &e) {
        return e.code()==cqs::native::ModelErrorCode::ProtectedItems?QStringLiteral("Refused: release pinned or locked tagged items first; local data and accepted history retained."):QStringLiteral("Refused: model verification failed; encrypted data retained.");
    } catch(const cqs::transaction::Error &e) {
        using cqs::transaction::ErrorCode;
        switch(e.code()){
        case ErrorCode::BackupLimit:return QStringLiteral("Recovery: all four protected backup slots are full. Keep an offline copy of the record and vault, then explicitly remove a selected backup before retrying; current data and journal are retained.");
        case ErrorCode::HistoryLimit:return QStringLiteral("Recovery: history limit reached; encrypted data retained. Export data and keep the record, vault and history before creating a new history; do not delete old events.");
        case ErrorCode::Equivocation:return QStringLiteral("Recovery: previously observed history was replaced; encrypted state retained. Restore the trusted event files.");
        case ErrorCode::MissingHead:return QStringLiteral("Waiting: previously observed history is incomplete; restore delivery of the missing event files.");
        case ErrorCode::Rollback:return QStringLiteral("Recovery: history rollback refused; encrypted state retained.");
        case ErrorCode::LocalChanges:return QStringLiteral("Refused: preserve local edits before import or recovery; no data were discarded.");
        case ErrorCode::PendingRecovery:return QStringLiteral("Refused: finish pending publication with retry reserved Seed/publication, or pending import with accept, retry or restore.");
        case ErrorCode::HistoryExists:return QStringLiteral("Refused: history already exists; use Join instead of Seed.");
        case ErrorCode::DeviceInUse:return QStringLiteral("Refused: this device ID already occurs in history; configure a new unused device ID before Join.");
        case ErrorCode::Conflict:return QStringLiteral("Refused: multiple authenticated tips require conflict resolution.");
        case ErrorCode::NoRemote:return QStringLiteral("Refused: no authenticated history to Join; this does not Seed a new history.");
        case ErrorCode::NotJoined:return QStringLiteral("Refused: explicit Join of an empty tab is required.");
        case ErrorCode::AlreadyJoined:return QStringLiteral("Refused: already joined; use import next history tip.");
        case ErrorCode::PublicationStaging:return QStringLiteral("Refused: choose an existing private publication staging folder on the same fixed NTFS volume as the synchronization folder. Data and reserved IDs are retained.");
        default:return QStringLiteral("Refused: history/recovery verification failed; encrypted state retained.");
        }
    } catch(const cqs::events::Error &e) {
        return e.code()==cqs::events::ErrorCode::SizeLimit?QStringLiteral("Recovery: history/event byte limit reached; retain files and export before creating a new history."):QStringLiteral("Recovery: event authentication or payload validation failed; trusted history must be restored.");
    } catch(const cqs::history::Error &e) {
        if(e.code()==cqs::history::ErrorCode::MissingParent)return QStringLiteral("Waiting: referenced event files have not been delivered.");
        return e.code()==cqs::history::ErrorCode::LimitExceeded?QStringLiteral("Recovery: history event limit reached; retain files and export before creating a new history."):QStringLiteral("Recovery: invalid history; encrypted state retained.");
    } catch(const cqs::storage::Error &e) {
        if(e.code()==cqs::storage::ErrorCode::ScanLimit)return QStringLiteral("Recovery: transport history scan limit reached; retain files and export before creating a new history.");
        return QStringLiteral("Refused or unconfirmed: transport unavailable/unsafe, duplicate ID or publication changed; retain state and use the matching retry reserved Seed/publication.");
    } catch(const cqs::state::Error &e) {
        if(e.code()==cqs::state::ErrorCode::SizeLimit)
            return QStringLiteral("Recovery: private record capacity reached; local data and backups retained. Export verified data before freeing backup capacity.");
        if(e.code()==cqs::state::ErrorCode::CommitUnconfirmed)
            return QStringLiteral("Unconfirmed: an old or new complete record may be durable; reload and explicitly recover, never reset.");
        return QStringLiteral("Refused: missing/corrupt/busy or incompatible encrypted state; no empty replacement was created.");
    } catch(...) {return QStringLiteral("Refused: wrong/missing password, unsafe/busy paths or invalid input; encrypted data retained.");}
}
class Script final : public ItemScriptable {
    Q_OBJECT
    Q_PROPERTY(QString capability READ capability)
public:
    QString capability() const { return QStringLiteral("device-setup/5"); }
public slots:
    QString userAction(){
        // CopyQ exposes only zero-parameter Qt slots. Script arguments arrive
        // through the public ItemScriptable API, not Qt method parameters.
        const auto args=currentArguments();
        if(args.size()!=1||args[0].metaType().id()!=QMetaType::QString)return QStringLiteral("Refused");
        const auto name=args[0].toString();
        if(!cqs::native::uiAction(name))return QStringLiteral("Refused");
        const auto result=dispatchUserAction(name);
        call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("userActionResult"),name,result});
        return result;
    }
    QString diagnostics(){return action("diagnostics");}
    QString showStatus(){return action("showStatus");}
    QString initializeStorage(){return action("initializeStorage");}
    QString unlockStorage(){return action("unlockStorage");}
    QString changeStoragePassword(){return action("changeStoragePassword");}
    QString rotateLocalKey(){return action("rotateLocalKey");}
    QString backupVault(){return action("backupVault");}
    QString restoreMissingVault(){return action("restoreMissingVault");}
    QString exportSyncKey(){return action("exportSyncKey");}
    QString importSyncKey(){return action("importSyncKey");}
    QString resumeStorageSetup(){return action("resumeStorageSetup");}
    QString migrateLegacyStorage(){return action("migrateLegacyStorage");}
    QString migrateUnifiedState(){return stateAction("migrateUnifiedState",false);}
    QString rotateSyncKey(){return transitionAction("rotateSyncKey");}
    QString compactHistory(){return transitionAction("compactHistory");}
    QString joinSuccessor(){return transitionAction("joinSuccessor");}
    QString resumeHistoryTransition(){return transitionAction("resumeHistoryTransition",false);}
    QString finishHistoryTransition(){return transitionAction("finishHistoryTransition");}
    QString cancelHistoryTransition(){return transitionAction("cancelHistoryTransition",false);}
    QString joinHistory(){return stateAction("joinHistory");}
    QString seedHistory(const QByteArray &authorization={}){return stateAction("seedHistory",true,{},authorization);}
    QString retrySeed(){return stateAction("retrySeed");}
    QString joinPreservingLocal(){return stateAction("joinPreservingLocal");}
    QString restorePreserved(){return stateAction("restorePreserved");}
    QString preserveNativeTab(){
        if(call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("nativeMigrationStatus"),QVariant(),call("stats",{})}).toString()!="NativeStorage")return QStringLiteral("Refused: enable CopyQ Encrypt Tabs, disable incompatible storage plugins and keep independent storage off before preserving the ordinary tab.");
        const auto names=call("tab",{}).toStringList();const QString source="synced_tray",backup="synced_tray-before-secure-sync";
        if(names.contains(backup))return names.contains(source)?QStringLiteral("Refused: backup tab already exists; never overwritten."):QStringLiteral("AlreadyPreserved");
        if(!names.contains(source))return QStringLiteral("Refused: source tab is missing.");
        call("show",{source});switchAway();call("hide",{});
        if(!call("unload",{source}).toStringList().contains(source))return QStringLiteral("Refused: close editors first; original tab retained.");
        if(call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("nativeMigrationStatus"),QVariant(),call("stats",{})}).toString()!="NativeStorage")return QStringLiteral("Refused: encryption, profile or plugin inventory changed; original tab retained.");
        call("renameTab",{source,backup});const auto after=call("tab",{}).toStringList();
        return after.contains(backup)&&!after.contains(source)?QStringLiteral("PreservedNativeTab"):QStringLiteral("Unconfirmed: inspect tab names; do not delete either tab.");
    }
    QString adoptFromTab(const QByteArray &authorization={}){
        if(!authorization.isEmpty()&&call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("unlockStorage"),authorization}).toString()!="Unlocked")return QStringLiteral("Refused: Secure Sync unlock failed.");
        const QString source="synced_tray-before-secure-sync";
        if(!call("tab",{}).toStringList().contains(source))return QStringLiteral("Refused: preserve the original tab as synced_tray-before-secure-sync first.");
        call("show",{source});call("tab",{source});const auto count=call("size",{}).toLongLong();
        if(count<0||count>10000)return QStringLiteral("Refused: source exceeds the supported item limit.");
        if(count==0)return QStringLiteral("Refused: preserved source is empty or unavailable; unlock and verify it. An intentionally empty first device can use Seed directly.");
        const auto token=QUuid::createUuid().toString(QUuid::WithoutBraces);
        if(call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("beginNativeCapture"),token,count,call("info",{QStringLiteral("data")})}).toString()!="Started")
            return QStringLiteral("Refused: another source capture is active.");
        const auto cleanup=qScopeGuard([this,token]{try{call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("finishNativeCapture"),token});}catch(...){}});
        QVariantList packed;qsizetype total=0;
        for(qint64 i=0;i<count;++i){const auto value=call("read",{QStringLiteral("application/x-copyq-item"),i});
            if(value.metaType().id()!=QMetaType::QByteArray)return QStringLiteral("Refused: unsupported source value; original retained.");
            const auto bytes=value.toByteArray();if(bytes.size()>32*1024*1024-total)return QStringLiteral("Refused: source packed size exceeds limit; original retained.");
            total+=bytes.size();packed.append(bytes);
        }
        const auto captured=call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("finishNativeCapture"),token}).toString();
        if(captured!="Captured")return captured;
        call("setCurrentTab",{QStringLiteral("synced_tray")});call("hide",{});
        if(!call("unload",{source}).toStringList().contains(source))return QStringLiteral("Refused: close source editors first; original retained.");
        return stateAction("adoptSnapshot",true,packed,authorization);
    }
    QString publishChanges(){return stateAction("publishChanges");}
    QString retryPublication(){return stateAction("retryPublication");}
    QString restoreArchive(){return call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("restoreArchive"),QVariant(),call("stats",{})}).toString();}
    QString resolveConflict(){return call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("resolveConflict"),QVariant(),call("stats",{})}).toString();}
    QString discardArchive(){return call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("discardArchive"),QVariant(),call("stats",{})}).toString();}
    QString syncNow(){return stateAction("syncNow");}
    QString stopAutomaticSync(){
        const auto result=action("stopAutomaticSync");
        if(!result.startsWith("Stopping"))return result;
        while(action("automaticSyncStatus")=="Working")call("sleep",{25});
        return QStringLiteral("Stopped");
    }
    QString automaticSyncStatus(){return action("automaticSyncStatus");}
    QString enableAutomaticSync(){return action("enableAutomaticSync");}
    QString automaticSync(){
        const auto token=QUuid::createUuid().toString(QUuid::WithoutBraces);
        const auto started=call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("startAutomaticSync"),token,call("stats",{})}).toString();
        if(started!="Started")return started;
        for(;;){
            const auto state=call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("automaticSyncStatus"),token}).toString();
            if(state.isEmpty()||state=="Stopped"||state=="Refused")return QStringLiteral("Stopped");
            const auto delay=call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("automaticCycleDelay"),token}).toInt();
            if(state!="Working"&&delay==0)call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("automaticCycle"),token,call("stats",{}),call("tab",{})});
            call("sleep",{delay>0?std::min(delay,1000):250});
        }
    }
    QString fastForward(){return stateAction("fastForward");}
    QString acceptPendingTarget(){return stateAction("acceptPendingTarget");}
    QString retryPendingImport(){return stateAction("retryPendingImport");}
    QString restorePendingOriginal(){return stateAction("restorePendingOriginal");}
    QString preserveAndRetry(){return stateAction("preserveAndRetry");}
    QString preserveAndRestore(){return stateAction("preserveAndRestore");}
    QString lockStorage(){
        if(action("checkpointStorage")!="Checkpointed")return QStringLiteral("Refused");
        if(!call("unload",{QStringLiteral("synced_tray")}).toStringList().contains(QStringLiteral("synced_tray")))
            return QStringLiteral("Refused: close editors and switch away from synced_tray first; no forced unload was used.");
        return action("lockStorage");
    }
    QString detachStorage(){
        call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("setNativeRoot"),call("info",{QStringLiteral("data")})});
        auto result=call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("prepareDetach"),QVariant(),call("stats",{})}).toString();if(result!="DetachPrepared")return result;
        for(int i=0;i<2;++i){
            switchAway();
            call("hide",{});
            if(!call("unload",{QStringLiteral("synced_tray")}).toStringList().contains(QStringLiteral("synced_tray")))
                return QStringLiteral("Pending: close editors and switch away from synced_tray; then finish removal.");
            if(action("unlockStorage")!="Unlocked")return QStringLiteral("Pending: unlock Secure Sync to finish removal.");
            call("show",{QStringLiteral("synced_tray")});
            result=action("finishDetach");if(result=="Detached")return result;
        }
        return QStringLiteral("Pending: encrypted backup retained; finish removal before uninstalling.");
    }
private:
    QString dispatchUserAction(const QString &name){
        if(name=="rotateSyncKey")return rotateSyncKey();
        if(name=="compactHistory")return compactHistory();
        if(name=="joinSuccessor")return joinSuccessor();
        if(name=="resumeHistoryTransition")return resumeHistoryTransition();
        if(name=="finishHistoryTransition")return finishHistoryTransition();
        if(name=="cancelHistoryTransition")return cancelHistoryTransition();
        if(name=="seedHistory")return seedHistory();
        if(name=="joinHistory")return joinHistory();
        if(name=="joinPreservingLocal")return joinPreservingLocal();
        if(name=="syncNow")return syncNow();
        if(name=="enableAutomaticSync")return enableAutomaticSync();
        if(name=="stopAutomaticSync")return stopAutomaticSync();
        if(name=="resolveConflict")return resolveConflict();
        if(name=="retrySeed")return retrySeed();
        if(name=="retryPublication")return retryPublication();
        if(name=="acceptPendingTarget")return acceptPendingTarget();
        if(name=="retryPendingImport")return retryPendingImport();
        if(name=="restorePendingOriginal")return restorePendingOriginal();
        if(name=="preserveAndRetry")return preserveAndRetry();
        if(name=="preserveAndRestore")return preserveAndRestore();
        if(name=="restoreArchive")return restoreArchive();
        if(name=="discardArchive")return discardArchive();
        if(name=="restorePreserved")return restorePreserved();
        if(name=="preserveNativeTab")return preserveNativeTab();
        if(name=="adoptFromTab")return adoptFromTab();
        if(name=="migrateUnifiedState")return migrateUnifiedState();
        if(name=="lockStorage")return lockStorage();
        if(name=="detachStorage")return detachStorage();
        return QStringLiteral("Refused");
    }
    QString stateAction(const QString &name,bool loaded=true,const QVariant &data={},const QByteArray &authorization={}){
        if(!authorization.isEmpty()&&call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("unlockStorage"),authorization}).toString()!="Unlocked")return QStringLiteral("Refused: Secure Sync unlock failed.");
        if(loaded){
            call("show",{QStringLiteral("synced_tray")});switchAway();call("hide",{});
            if(action("checkpointStorage")!="Checkpointed")return QStringLiteral("Refused: local checkpoint unavailable.");
            if(!call("unload",{QStringLiteral("synced_tray")}).toStringList().contains(QStringLiteral("synced_tray")))
                return QStringLiteral("Refused: close editors and hide/switch away from synced_tray; no forced unload was used.");
        }
        auto result=call("callPlugin",{QStringLiteral("securesync"),name,authorization.isEmpty()?QVariant():QVariant(authorization),call("stats",{}),data}).toString();
        if(result.startsWith("Working:")){
            const auto token=result.mid(8);
            do{call("sleep",{25});result=call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("operationStatus"),token}).toString();}while(result=="Working");
        }
        // A removed tab is not implicitly recreated when a background manual
        // action returns. Its encrypted record remains available for recovery.
        if(call("tab",{}).toStringList().contains(QStringLiteral("synced_tray")))call("show",{QStringLiteral("synced_tray")});
        return result;
    }
    QString transitionAction(const QString &name,bool checkpoint=true){
        stopAutomaticSync();
        if(checkpoint){
            call("show",{QStringLiteral("synced_tray")});switchAway();call("hide",{});
            if(action("checkpointStorage")!="Checkpointed")return QStringLiteral("Refused: local checkpoint unavailable.");
        }
        if(!call("unload",{QStringLiteral("synced_tray")}).toStringList().contains(QStringLiteral("synced_tray")))
            return QStringLiteral("Refused: close editors and switch away from synced_tray; no forced unload was used.");
        auto result=call("callPlugin",{QStringLiteral("securesync"),name,QVariant(),call("stats",{})}).toString();
        if(result.startsWith("Working:")){const auto token=result.mid(8);
            do{call("sleep",{25});result=call("callPlugin",{QStringLiteral("securesync"),QStringLiteral("operationStatus"),token}).toString();}while(result=="Working");}
        if(result.startsWith("HistoryTransitioned")||result=="HistoryTransitionCancelled"||result=="HistoryTransitionFinalized")
            if(call("tab",{}).toStringList().contains(QStringLiteral("synced_tray")))call("show",{QStringLiteral("synced_tray")});
        return result;
    }
    void switchAway(){
        for(const auto &name:call("tab",{}).toStringList())if(name!=QStringLiteral("synced_tray")){
            call("setCurrentTab",{name});break;
        }
    }
    QString action(const QString &name){return call(QStringLiteral("callPlugin"),{QStringLiteral("securesync"),name}).toString();}

};
}

SecureSyncPlugin::SecureSyncPlugin() {
    scheduleClock_.start();
    connect(&transportWatch_,&cqs::native::TransportWatch::changed,this,[this]{schedule_.changed(scheduleClock_.elapsed());});
    connect(&storage_,&cqs::native::StandaloneStorage::modelEdited,this,[this]{schedule_.changed(scheduleClock_.elapsed());});
    connect(&storage_,&cqs::native::StandaloneStorage::localCheckpointed,this,[this]{schedule_.changed(scheduleClock_.elapsed());});
    connect(&storage_,&cqs::native::StandaloneStorage::unlocked,this,[this]{schedule_.reset(scheduleClock_.elapsed());});
    connect(QCoreApplication::instance(),&QCoreApplication::aboutToQuit,this,[this]{
        closing_=true;supervisor_.stop();if(runtimeJob_)runtimeJob_->operation->cancel();
        // Cancellation wakes a worker awaiting GUI dispatch. Join without an
        // event loop, then preserve committed edits before CopyQ destroys tabs.
        if(syncThread_)syncThread_->wait();
        try{storage_.finishAsyncImport();if(storage_.hasModels())storage_.checkpointModels();}catch(...){emit error(tr("Shutdown checkpoint unconfirmed; retain encrypted state and recover before synchronization."));}
    });
    supervisor_.setInterval(1000);connect(&supervisor_,&QTimer::timeout,this,&SecureSyncPlugin::superviseRuntime);
    storage_.setUnlocker([this]{return scriptCallback({QStringLiteral("unlockStorage")}).toString()==QLatin1String("Unlocked");});
    storage_.setHandoffGuard([this]{
        QSettings settings(settingsFile_,QSettings::IniFormat);
        return handoffEpoch_!=0&&handoffEpoch_==settingsEpoch_&&settings.value("Options/encrypt_tabs",false).toBool();
    });
    connect(&storage_,&cqs::native::StandaloneStorage::cacheFileObserved,this,[this](const QString &file){
        storage_.setCacheFile(file);QSettings settings(settingsFile_,QSettings::IniFormat);
        settings.setValue("Plugins/securesync/host_cache_file",file);settings.sync();
    });
    connect(&storage_, &cqs::native::StandaloneStorage::error, this, &SecureSyncPlugin::error);
    connect(&storage_,&cqs::native::StandaloneStorage::error,this,[this]{localSaveProblem_=true;refreshPanel();});
    connect(&storage_,&cqs::native::StandaloneStorage::checkpointVerified,this,[this]{if(!storage_.hasUnsavedChanges())localSaveProblem_=false;refreshPanel();});
    // Only the GUI server supervises the explicitly persisted preference.
    // CopyQ CLI processes also load plugins and never start a scheduling client.
    connect(&inspector_, &cqs::native::Inspector::finished, this, [this](const QString &status) {
        if (panel_) {
            panel_->setBusy(!isEnabled());
            panel_->setStatus(panel_ == inspectionPanel_ && panel_->profile() == inspectionProfile_ ? status
                : tr("A previous inspection has finished. Inspect the current selection to obtain its status."));
        }
        inspectionPanel_ = nullptr;
    });
}
SecureSyncPlugin::~SecureSyncPlugin(){
    closing_=true;if(runtimeJob_)runtimeJob_->operation->cancel();
    supervisor_.stop();
    if(runtimeClient_){runtimeClient_->terminate();if(!runtimeClient_->waitForFinished(1000)){runtimeClient_->kill();runtimeClient_->waitForFinished(1000);}}
    if(syncThread_){syncThread_->wait();delete syncThread_;syncThread_=nullptr;}
}
void SecureSyncPlugin::saveAutomaticPreference(bool enabled){
    automaticEnabled_=enabled;
    schedule_.reset(scheduleClock_.elapsed());
    transportWatch_.setFolder(enabled&&cqs::native::validateProfile(profile_,false).isEmpty()?profile_.transport:QString{});
    if(!settingsFile_.isEmpty()){QSettings settings(settingsFile_,QSettings::IniFormat);settings.setValue("Plugins/securesync/automatic_enabled",enabled);settings.sync();}
    if(panel_)panel_->setAutomaticEnabled(enabled);
}
void SecureSyncPlugin::stopRuntimeClient(){
    if(!runtimeClient_||clientStopping_)return;clientStopping_=true;
    QPointer<QProcess> client=runtimeClient_;client->terminate();
    QTimer::singleShot(1000,this,[client]{if(client&&client->state()!=QProcess::NotRunning)client->kill();});
}
void SecureSyncPlugin::superviseRuntime(){
    // QApplication and public application identity identify the GUI server.
    // CLI/monitor processes and module-test executables never launch children.
    if(closing_||!copyqGuiServer())return;
    if((!automaticEnabled_&&!resolving_)||!isEnabled()||!profile_.standaloneStorage)return;
    if(runtimeBusy_)return;
    if(resolving_&&!runtimeBusy_){
        if(!schedule_.begin(scheduleClock_.elapsed()))return;
        if(automaticToken_.isEmpty())automaticToken_=QUuid::createUuid().toString(QUuid::WithoutBraces);
        heartbeat_.restart();try{beginRuntime(automaticToken_);}catch(...){automaticStatus_="Recovery: resolution could not continue";storage_.releaseIdleSession();}
        if(!runtimeBusy_)recordRuntimeResult(automaticStatus_);return;
    }
    if(!automaticToken_.isEmpty()&&heartbeat_.isValid()&&heartbeat_.elapsed()>15000&&!runtimeBusy_){
        automaticToken_.clear();automaticKeys_.reset();if(!storage_.hasModels())storage_.releaseKeys();
        stopRuntimeClient();
    }
    if(runtimeClient_&&automaticToken_.isEmpty()&&!clientStopping_&&scheduleClock_.elapsed()-clientLaunchedAt_>15000){
        clientFailures_=std::min(7u,clientFailures_+1);clientRetryAt_=scheduleClock_.elapsed()+cqs::native::retryDelay(clientFailures_);
        automaticStatus_="Waiting: CopyQ scheduling client did not connect";uiResult_=automaticStatus_;refreshPanel();stopRuntimeClient();
    }
    if(runtimeClient_||!automaticToken_.isEmpty())return;
    if(scheduleClock_.elapsed()<clientRetryAt_)return;
    auto *client=new QProcess(this);runtimeClient_=client;clientStopping_=false;clientLaunchedAt_=scheduleClock_.elapsed();
    connect(client,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this,client]{
        if(runtimeClient_==client)runtimeClient_=nullptr;client->deleteLater();
        if(automaticEnabled_&&!automaticToken_.isEmpty()){
            clientFailures_=std::min(7u,clientFailures_+1);clientRetryAt_=scheduleClock_.elapsed()+cqs::native::retryDelay(clientFailures_);
        }
    });
    connect(client,&QProcess::errorOccurred,this,[this,client](QProcess::ProcessError e){if(e==QProcess::FailedToStart){
        if(runtimeClient_==client)runtimeClient_=nullptr;client->deleteLater();
        clientFailures_=std::min(7u,clientFailures_+1);clientRetryAt_=scheduleClock_.elapsed()+cqs::native::retryDelay(clientFailures_);
        automaticStatus_="Waiting: CopyQ scheduling client unavailable";
        uiResult_=automaticStatus_;refreshPanel();
    }});
    client->setStandardOutputFile(QProcess::nullDevice());client->setStandardErrorFile(QProcess::nullDevice());
    client->start(QCoreApplication::applicationFilePath(),{"eval","plugins.securesync.automaticSync();undefined;"});
}
void SecureSyncPlugin::recordRuntimeResult(const QString &status){
    uiResult_=status;refreshPanel();
    using Result=cqs::native::SyncSchedule::Result;
    const bool success=status=="Applied"||status=="UpToDate"||status=="Restored"||status=="AdoptedPreservedTab"||status=="MigratedUnifiedState";
    const auto result=success?Result::Success:
        status=="Conflict: compare versions before continuing"?Result::Conflict:
        status.contains("unlock Secure Sync")||status.contains("Seed or Join")||status.contains("key lifecycle")?Result::Locked:
        status.contains("editor")||status.contains("pinned or locked")||status.contains("configured tab was removed")||status.contains("incompatible")?Result::Deferred:
        status.startsWith("Waiting")?Result::Transient:Result::Review;
    schedule_.finish(scheduleClock_.elapsed(),result);
    if(success){clientFailures_=0;clientRetryAt_=0;}
    if(success&&resolving_)schedule_.reset(scheduleClock_.elapsed());
    transportWatch_.setFolder((automaticEnabled_||resolving_)&&cqs::native::validateProfile(profile_,false).isEmpty()?profile_.transport:QString{});
    transportWatch_.refresh();
}
void SecureSyncPlugin::launchRuntimeWorker(std::function<void()> work,std::function<void()> finished){
    auto *worker=QThread::create(std::move(work));syncThread_=worker;worker->setParent(this);
    connect(worker,&QThread::finished,this,[this,worker,finished=std::move(finished)]{
        syncThread_=nullptr;worker->deleteLater();finished();
    });worker->start();
}
bool SecureSyncPlugin::runtimeCurrent(const std::shared_ptr<SecureSyncJob> &job) const {
    try{job->operation->check();}catch(...){return false;}
    return !closing_&&runtimeJob_==job&&job->epoch==settingsEpoch_&&job->control==controlEpoch_&&
        (job->token.isEmpty()||job->token==automaticToken_);
}
void SecureSyncPlugin::importRuntime(const std::shared_ptr<SecureSyncJob> &job,bool recovery,cqs::transaction::Recovery action,bool projection){
    if(!runtimeCurrent(job)){finishRuntime(job,"Stopped: encrypted recovery state retained");return;}
    try{job->clipboard=storage_.beginAsyncImport(this,job->operation);}
    catch(...){finishRuntime(job,"Waiting: active editor or unverified view");return;}
    const auto protection=storage_.protection();automaticStatus_="Working";
    launchRuntimeWorker([job,recovery,action,projection,protection]{
        try{
            job->operation->check();
            if(projection){
                cqs::native::prepareResolutionProjection(job->configuration,job->keys,job->session.get());
                if(!cqs::native::readStorage(job->configuration,job->keys->local,job->keys->sync).pending)return;
            }
            const cqs::events::AuthenticatedHistory empty(job->keys->sync,{});
            cqs::native::importWorkerHistory(job->configuration,job->keys,job->history?*job->history:empty,job->clipboard.get(),
                recovery,action,protection,[control=job->operation]{control->check();});
        }catch(const cqs::native::Cancelled &){job->error="Stopped: encrypted recovery state retained";}
        catch(const cqs::native::ModelError &e){job->error=e.code()==cqs::native::ModelErrorCode::ProtectedItems?
            "Waiting: pinned or locked tagged items must be released before applying this version":"Recovery: model changed or editor opened; encrypted journal retained";}
        catch(...){job->error="Recovery: state/model verification failed; data and journal retained";}
    },[this,job]{
        try{storage_.finishAsyncImport();}catch(...){job->error="Recovery: local checkpoint unconfirmed; encrypted journal retained";}
        job->clipboard.reset();
        finishRuntime(job,job->error.isEmpty()?(runtimeCurrent(job)?"Applied":"Stopped: reload durable state"):job->error);
    });
}
void SecureSyncPlugin::finishRuntime(const std::shared_ptr<SecureSyncJob> &job,const QString &status){
    if(runtimeJob_!=job)return;
    if((status.startsWith("Conflict")||status.contains("multiple authenticated tips"))&&job->history)conflictHistory_=job->history;
    automaticStatus_=status;runtimeBusy_=false;runtimeJob_.reset();storage_.releaseIdleSession();
    if(resolving_)try{const auto r=cqs::native::readStorage(job->configuration,job->keys->local,job->keys->sync);
        if(!r.resolution&&!r.publication&&!r.pending){resolving_=false;if(!automaticEnabled_){automaticToken_.clear();automaticKeys_.reset();}}}catch(...){}
    if(!automaticToken_.isEmpty()&&automaticKeys_)storage_.useKeys(automaticKeys_);
    else if(!storage_.hasModels())storage_.releaseKeys();
    // QThread's functor may live until deleteLater; release the operation's
    // lease now, before reporting completion or allowing a tab to reload.
    job->session.reset();
    recordRuntimeResult(status);
    refreshPanel();
}
void SecureSyncPlugin::deliverRuntime(const std::shared_ptr<SecureSyncJob> &job){
    launchRuntimeWorker([job]{try{cqs::native::deliverPublication(job->configuration,job->keys,job->input,job->reviewedContext);
        cqs::storage::Directory directory(path(job->configuration.profile.transport));job->history=directory.scan(job->keys->sync);}
        catch(const cqs::transaction::Error &e){job->error=e.code()==cqs::transaction::ErrorCode::MissingHead?
            "Waiting: reserved publication retained; previously observed history not yet delivered":
            (e.code()==cqs::transaction::ErrorCode::Conflict?QStringLiteral("Conflict: reserved event needs review"):operationFailure());}
        catch(const cqs::events::Error &){job->error=operationFailure();}
        catch(const cqs::storage::Error &e){job->error=e.code()==cqs::storage::ErrorCode::ScanLimit?operationFailure():QStringLiteral("Waiting: reserved publication retained; transport unavailable or incomplete");}
        catch(...){job->error="Waiting: reserved publication retained; transport unavailable or incomplete";}
        try{cqs::storage::Directory directory(path(job->configuration.profile.transport));job->history=directory.scan(job->keys->sync);}catch(...){}
    },[this,job]{
        if(!runtimeCurrent(job)){finishRuntime(job,"Stopped: reserved publication retained");return;}
        if(job->history){
            // Delivery can discover an unaccepted branch even when it refuses
            // the reserved event. Retain that observation before presenting UI.
            try{cqs::native::observeHistory(job->configuration,job->keys,*job->history,job->session.get());storage_.refreshGenerations();}
            catch(const cqs::transaction::Error &e){finishRuntime(job,
                e.code()==cqs::transaction::ErrorCode::MissingHead&&job->error.startsWith("Waiting")?job->error:operationFailure());return;}
            catch(...){finishRuntime(job,operationFailure());return;}
            if(job->history->graph().hasConflict())conflictHistory_=job->history;
        }
        if(!job->error.isEmpty()){finishRuntime(job,job->error);return;}
        try{cqs::native::acceptPublication(job->configuration,job->keys,job->input,job->session.get());storage_.refreshGenerations();finishRuntime(job,job->reviewedContext?"Conflict: reserved event confirmed; review current versions":"Applied");}
        catch(...){finishRuntime(job,"Recovery: publication commit unconfirmed; encrypted journal retained");}
    });
}
QString SecureSyncPlugin::restoreArchive(const QVariantList &arguments){
    const auto decisionEpoch=settingsEpoch_,control=controlEpoch_;
    if(arguments.size()!=3||!qobject_cast<QApplication *>(QCoreApplication::instance()))return "Refused";
    const auto refusal=cqs::native::pluginRefusal(arguments[2].toString());if(!refusal.isEmpty())return refusal;
    storage_.setProtection(cqs::native::rowProtection(settingsFile_,arguments[2].toString()));
    auto keys=storage_.keys()?storage_.keys():automaticKeys_;if(!keys)return "Waiting: unlock Secure Sync";
    const auto c=cqs::native::storageConfiguration(profile_);storage_.useKeys(keys);storage_.checkpointModels();
    const auto before=cqs::native::readStorage(c,keys->local,keys->sync);
    if(before.pending||before.publication||before.resolution||!before.head)return "Recovery: finish the current operation first";
    if(before.archives.empty())return "No protected conflict backups";
    QStringList choices;for(std::size_t i=0;i<before.archives.size();++i)choices.append(tr("Backup %1 — %2 items").arg(i+1).arg(before.archives[i].size()));
    runtimeBusy_=true;bool ok=false;
    const auto choice=QInputDialog::getItem(nullptr,tr("Secure Sync — restore backup"),tr("Restore an earlier local version as a new synchronized revision. The current local version replaces this backup."),choices,0,false,&ok);
    if(!ok){runtimeBusy_=false;return "Cancelled";}
    const auto index=choices.indexOf(choice);if(index<0){runtimeBusy_=false;return "Cancelled";}
    if(*before.local==before.archives[std::size_t(index)]){runtimeBusy_=false;return "UpToDate";}
    if(QMessageBox::question(nullptr,tr("Secure Sync — confirm restore"),tr("Publish this backup as the new version while preserving current local data?"),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes){runtimeBusy_=false;return "Cancelled";}
    if(decisionEpoch!=settingsEpoch_||control!=controlEpoch_){runtimeBusy_=false;return "Cancelled: settings or scheduling changed";}
    storage_.protection().validate(*before.local,before.archives[std::size_t(index)]);
    auto job=std::make_shared<SecureSyncJob>();job->configuration=c;job->keys=keys;job->input=before;job->epoch=settingsEpoch_;job->restoredArchive=std::size_t(index);
    job->control=control;job->session=storage_.sharedSession();if(!job->session)job->session=cqs::native::acquireStorageSession(c);storage_.useSession(job->session);runtimeJob_=job;resolving_=true;automaticKeys_=keys;
    const auto selected=before.archives[std::size_t(index)];
    launchRuntimeWorker([job,selected]{try{cqs::storage::Directory directory(path(job->configuration.profile.transport));job->history=directory.scan(job->keys->sync);
        if(job->history->graph().hasConflict()){job->error="Conflict: review branches before restoring";return;}
        job->publication=cqs::native::prepareResolution(job->configuration,job->keys,job->input,*job->history,selected);
    }catch(...){job->error=operationFailure();}},[this,job]{
        if(!job->error.isEmpty()||!runtimeCurrent(job)){finishRuntime(job,job->error.isEmpty()?"Stopped: settings or scheduling changed":job->error);return;}
        try{job->input=cqs::native::reserveResolution(job->configuration,job->keys,job->input,*job->history,*job->publication,true,job->session.get(),job->restoredArchive);storage_.refreshGenerations();deliverRuntime(job);}
        catch(const cqs::transaction::Error &e){finishRuntime(job,e.code()==cqs::transaction::ErrorCode::LocalChanges?
            QStringLiteral("Conflict: local data changed; review the restore again"):operationFailure());}
        catch(...){finishRuntime(job,operationFailure());}
    });return "Working";
}
QString SecureSyncPlugin::discardArchive(const QVariantList &arguments){
    if(arguments.size()!=3||!copyqGuiServer())return "Refused";
    const auto refusal=cqs::native::pluginRefusal(arguments[2].toString());if(!refusal.isEmpty())return refusal;
    storage_.setProtection(cqs::native::rowProtection(settingsFile_,arguments[2].toString()));
    auto keys=storage_.keys()?storage_.keys():automaticKeys_;if(!keys)return "Waiting: unlock Secure Sync";
    const auto epoch=settingsEpoch_,control=controlEpoch_;const auto c=cqs::native::storageConfiguration(profile_);
    storage_.useKeys(keys);storage_.checkpointModels();const auto before=cqs::native::readStorage(c,keys->local,keys->sync);
    if(before.publication)return "Recovery: finish the current operation first";
    if(before.archives.empty())return "No protected conflict backups";
    const auto removable=before.archives.size()-(before.resolution?1:0);
    if(!removable)return "Refused: the active resolution backup must be retained";
    QStringList choices;for(std::size_t i=0;i<removable;++i)choices.append(tr("Backup %1 — %2 items").arg(i+1).arg(before.archives[i].size()));
    runtimeBusy_=true;bool ok=false;
    const auto choice=QInputDialog::getItem(nullptr,tr("Secure Sync — discard backup"),tr("Choose an encrypted local backup to remove. Keep an offline copy of the record and vault if this data is still needed."),choices,0,false,&ok);
    const auto index=choices.indexOf(choice);
    if(!ok||index<0||QMessageBox::question(nullptr,tr("Secure Sync — confirm backup removal"),tr("Permanently remove this local backup? Current tab contents and published history remain available, but this backup cannot be restored afterward."),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes){runtimeBusy_=false;return "Cancelled";}
    if(epoch!=settingsEpoch_||control!=controlEpoch_){runtimeBusy_=false;return "Cancelled: settings or scheduling changed";}
    auto session=storage_.sharedSession();if(!session)session=cqs::native::acquireStorageSession(c);
    cqs::native::discardArchive(c,keys,before,std::size_t(index),session.get());storage_.refreshGenerations();runtimeBusy_=false;return "BackupRemoved";
}
QString SecureSyncPlugin::resolveConflict(const QVariantList &arguments){
    const auto decisionEpoch=settingsEpoch_,control=controlEpoch_;
    if(arguments.size()!=3||!qobject_cast<QApplication *>(QCoreApplication::instance()))return "Refused";
    const auto refusal=cqs::native::pluginRefusal(arguments[2].toString());if(!refusal.isEmpty())return refusal;
    storage_.setProtection(cqs::native::rowProtection(settingsFile_,arguments[2].toString()));
    auto keys=storage_.keys()?storage_.keys():automaticKeys_;if(!keys||!conflictHistory_)return "Waiting: unlock and inspect the conflict first";
    const auto c=cqs::native::storageConfiguration(profile_);storage_.useKeys(keys);storage_.checkpointModels();
    const auto before=cqs::native::readStorage(c,keys->local,keys->sync);if(before.pending)return "Recovery: finish the pending import first";
    if(before.publication){
        runtimeBusy_=true;
        if(QMessageBox::question(nullptr,tr("Secure Sync — reconcile publication"),tr("Finish the exact reserved encrypted event before reviewing the new branches? This preserves every version and never reuses its sequence."),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes){runtimeBusy_=false;return "Cancelled";}
        if(decisionEpoch!=settingsEpoch_||control!=controlEpoch_){runtimeBusy_=false;return "Cancelled: settings or scheduling changed";}
        auto job=std::make_shared<SecureSyncJob>();job->configuration=c;job->keys=keys;job->input=before;job->epoch=settingsEpoch_;job->reviewedContext=true;
        job->control=control;job->session=storage_.sharedSession();if(!job->session)job->session=cqs::native::acquireStorageSession(c);storage_.useSession(job->session);runtimeJob_=job;deliverRuntime(job);return "Working";
    }
    if(!before.head)return "Waiting: Seed or Join required";
    QStringList choices{"Keep local version","Keep both versions"};for(const auto &id:conflictHistory_->graph().tips())choices.append("Use "+QString::fromStdString(id));
    runtimeBusy_=true;bool ok=false;
    const auto choice=QInputDialog::getItem(nullptr,tr("Secure Sync — conflict"),tr("Choose the resulting version. Existing history remains immutable; current local data receive an encrypted backup."),choices,0,false,&ok);
    if(!ok){runtimeBusy_=false;return "Cancelled";}
    auto chosen=*before.local;
    const auto previousHistory=*conflictHistory_;
    // Bound the union before appending, rather than discovering an oversized
    // result after quadratic duplicate scans and unbounded intermediate copies.
    const auto limits=cqs::native::storageLimits();std::set<cqs::transaction::Item> seen(chosen.begin(),chosen.end());
    std::size_t combinedBytes=0;
    const auto accountItem=[&](const cqs::transaction::Item &item){for(const auto &field:item){
        if(field.first.size()>limits.snapshotBytes-combinedBytes)throw cqs::packed::Error();combinedBytes+=field.first.size();
        if(field.second.size()>limits.snapshotBytes-combinedBytes)throw cqs::packed::Error();combinedBytes+=field.second.size();}};
    for(const auto &item:chosen)accountItem(item);
    for(const auto &event:previousHistory.events())if(std::find(previousHistory.graph().tips().begin(),previousHistory.graph().tips().end(),event.revision.id)!=previousHistory.graph().tips().end()){
        if(choice=="Keep both versions"||choice=="Use "+QString::fromStdString(event.revision.id)){
            const auto snapshot=cqs::packed::decode(event.items,cqs::native::storageLimits());
            if(choice.startsWith("Use "))chosen=snapshot;
            else for(const auto &item:snapshot)if(seen.find(item)==seen.end()){
                if(chosen.size()==limits.items)throw cqs::packed::Error();accountItem(item);seen.insert(item);chosen.push_back(item);}
        }
    }
    storage_.protection().validate(*before.local,chosen);
    if(QMessageBox::question(nullptr,tr("Secure Sync — confirm resolution"),tr("Publish the selected result (%1 items) and retain the current local version as an encrypted backup?").arg(chosen.size()),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes){runtimeBusy_=false;return "Cancelled";}
    if(decisionEpoch!=settingsEpoch_||control!=controlEpoch_){runtimeBusy_=false;return "Cancelled: settings or scheduling changed";}
    auto job=std::make_shared<SecureSyncJob>();job->configuration=c;job->keys=keys;job->input=before;job->epoch=settingsEpoch_;
    job->control=control;job->session=storage_.sharedSession();if(!job->session)job->session=cqs::native::acquireStorageSession(c);storage_.useSession(job->session);runtimeJob_=job;resolving_=true;automaticKeys_=keys;
    const auto tips=previousHistory.graph().tips();const auto fingerprints=previousHistory.fingerprints();
    launchRuntimeWorker([job,chosen,tips,fingerprints]{try{cqs::storage::Directory directory(path(job->configuration.profile.transport));job->history=directory.scan(job->keys->sync);
        if(job->history->graph().tips()!=tips||job->history->fingerprints()!=fingerprints){job->error="Conflict: history changed during the decision";return;}
        job->publication=cqs::native::prepareResolution(job->configuration,job->keys,job->input,*job->history,chosen);
    }catch(...){job->error=operationFailure();}},[this,job]{
        if(!job->error.isEmpty()||!runtimeCurrent(job)){finishRuntime(job,job->error.isEmpty()?"Stopped: settings or scheduling changed":job->error);return;}
        try{job->input=cqs::native::reserveResolution(job->configuration,job->keys,job->input,*job->history,*job->publication,true,job->session.get());storage_.refreshGenerations();deliverRuntime(job);}
        catch(const cqs::transaction::Error &e){finishRuntime(job,e.code()==cqs::transaction::ErrorCode::LocalChanges?
            QStringLiteral("Conflict: local data changed during the decision; compare again"):operationFailure());}
        catch(...){finishRuntime(job,operationFailure());}
    });return "Working";
}
QString SecureSyncPlugin::beginRuntime(const QString &token){
    if(runtimeBusy_)return "Working";
    auto keys=storage_.keys()?storage_.keys():automaticKeys_;
    if(!keys){automaticStatus_="Waiting: unlock Secure Sync";return automaticStatus_;}
    if(keys->suspended){automaticStatus_="Recovery: finish recorded history/key transition";return automaticStatus_;}
    if(keys->initializing||keys->retiring||!keys->pending.empty()){automaticStatus_="Waiting: finish setup/key lifecycle";return automaticStatus_;}
    auto job=std::make_shared<SecureSyncJob>();job->configuration=cqs::native::storageConfiguration(profile_);job->keys=keys;job->token=token;job->epoch=settingsEpoch_;job->control=controlEpoch_;
    automaticKeys_=keys;storage_.useKeys(keys);
    job->session=storage_.sharedSession();if(!job->session)job->session=cqs::native::acquireStorageSession(job->configuration);
    storage_.useSession(job->session);storage_.checkpointModels();job->input=cqs::native::readStorage(job->configuration,keys->local,keys->sync);
    if(job->input.pending){
        if(!job->input.resolution){storage_.releaseIdleSession();automaticStatus_="Recovery: finish pending import";return automaticStatus_;}
        runtimeBusy_=true;runtimeJob_=job;resolving_=true;
        if(storage_.hasModels()&&!storage_.liveWritable()){finishRuntime(job,"Waiting: active editor");return automaticStatus_;}
        const auto recovery=job->input.pending->phase==cqs::transaction::Phase::Restore?cqs::transaction::Recovery::RestoreOriginal:cqs::transaction::Recovery::RetryImport;
        importRuntime(job,true,recovery);
        return automaticStatus_;
    }
    if(!job->input.head&&!job->input.publication){storage_.releaseIdleSession();automaticStatus_="Waiting: explicit Seed or Join required";return automaticStatus_;}
    runtimeBusy_=true;runtimeJob_=job;automaticStatus_="Working";
    if(job->input.publication){deliverRuntime(job);return "Working";}
    launchRuntimeWorker([job]{try{
        cqs::storage::Directory directory(path(job->configuration.profile.transport));job->history=directory.scan(job->keys->sync);
        cqs::native::verifyAcceptedHead(job->input,*job->history);
        if(job->input.resolution){
            if(job->history->graph().tips()==job->input.resolution->tips&&job->input.resolution->tips.size()>1)
                job->publication=cqs::native::prepareResolution(job->configuration,job->keys,job->input,*job->history,job->input.head->snapshot);
        }else if(!job->history->graph().hasConflict()&&job->history->graph().tips()==std::vector<std::string>{job->input.head->event.revision.id})
            job->publication=cqs::native::preparePublication(job->configuration,job->keys,job->input,*job->history);
    }catch(const cqs::history::Error &e){job->error=e.code()==cqs::history::ErrorCode::MissingParent?"Waiting: referenced events not yet delivered":"Recovery: invalid history";}
     catch(const cqs::transaction::Error &e){job->error=e.code()==cqs::transaction::ErrorCode::PublicationStaging?
        "Waiting: choose a private publication staging folder on the transport's fixed NTFS volume":operationFailure();}
     catch(const cqs::events::Error &e){job->error=e.code()==cqs::events::ErrorCode::SizeLimit?"Recovery: history/event byte limit reached; retain files and export before creating a new history":"Recovery: event authentication failed; trusted history must be restored";}
     catch(const cqs::storage::Error &e){job->error=e.code()==cqs::storage::ErrorCode::ScanLimit?"Recovery: transport history scan limit reached; retain files and export before creating a new history":"Waiting: transport unavailable, unsafe or incomplete";}
     catch(...){job->error="Waiting: transport unavailable, unsafe or incomplete";}},[this,job]{
        if(!runtimeCurrent(job)||!heartbeat_.isValid()||heartbeat_.elapsed()>15000){finishRuntime(job,"Stopped");return;}
        if(!job->error.isEmpty()){finishRuntime(job,job->error);return;}
        try{
            storage_.checkpointModels();const auto &h=*job->history;
            const auto current=cqs::native::observeHistory(job->configuration,job->keys,h,job->session.get());
            storage_.refreshGenerations();
            job->input.schema=current.schema;job->input.witnessed=current.witnessed;
            if(current.resolution){
                if(current.resolution->tips!=h.graph().tips()||*current.local!=current.archives.back()){
                    conflictHistory_=h;finishRuntime(job,"Conflict: new data require another decision");return;
                }
                if(job->publication){job->input=cqs::native::reserveResolution(job->configuration,job->keys,current,h,*job->publication,false,job->session.get());storage_.refreshGenerations();deliverRuntime(job);return;}
                if(storage_.hasModels()&&*current.local!=current.head->snapshot&&!storage_.liveWritable()){finishRuntime(job,"Waiting: active editor");return;}
                storage_.protection().validate(*current.local,current.head->snapshot);
                importRuntime(job,true,cqs::transaction::Recovery::RetryImport,true);return;
            }
            if(h.graph().hasConflict()||(*current.local!=current.head->snapshot&&h.graph().tips()!=std::vector<std::string>{current.head->event.revision.id})){
                conflictHistory_=h;finishRuntime(job,"Conflict: compare versions before continuing");return;
            }
            if(job->publication){job->input=cqs::native::reservePublication(job->configuration,job->keys,job->input,*job->publication,job->session.get());storage_.refreshGenerations();deliverRuntime(job);return;}
            if(h.graph().tips()==std::vector<std::string>{current.head->event.revision.id}){finishRuntime(job,"UpToDate");return;}
            if(storage_.hasModels()){
                if(!storage_.liveWritable()){finishRuntime(job,"Waiting: active editor or unverified view");return;}
            }
            conflictHistory_.reset();importRuntime(job);
        }catch(const cqs::native::ModelError &e){finishRuntime(job,e.code()==cqs::native::ModelErrorCode::ProtectedItems?"Waiting: pinned or locked tagged items must be released before applying this version":"Recovery: model verification failed; encrypted data retained");}
        catch(...){finishRuntime(job,operationFailure());}
    });return "Working";
}
bool SecureSyncPlugin::canSaveItems(const QString &tab) const { return isEnabled() && storage_.canSave(tab); }
bool SecureSyncPlugin::canLoadItems(QIODevice *file) const {
    const_cast<cqs::native::StandaloneStorage &>(storage_).inspectNativeCache(file);
    return cqs::native::StandaloneStorage::recognizes(file);
}
ItemSaverPtr SecureSyncPlugin::initializeTab(const QString &tab, QAbstractItemModel *model, int maximum) {
    return isEnabled() ? storage_.initialize(tab, model, maximum) : ItemSaverPtr{};
}
ItemSaverPtr SecureSyncPlugin::loadItems(const QString &tab, QAbstractItemModel *model, QIODevice *file, int maximum) {
    return isEnabled() ? storage_.load(tab, model, file, maximum) : ItemSaverPtr{};
}
ItemScriptable *SecureSyncPlugin::scriptableObject() { return new Script; }
QVariant SecureSyncPlugin::scriptCallback(const QVariantList &arguments) {
    const auto result=scriptCallbackImpl(arguments);
    const auto action=arguments.value(0).toString();
    if(cqs::native::uiAction(action)||QStringList{"initializeStorage","unlockStorage","changeStoragePassword","rotateLocalKey","backupVault","restoreMissingVault","repairMissingVault","exportSyncKey","importSyncKey","resumeStorageSetup","migrateLegacyStorage","prepareDetach","finishDetach","cancelDetach"}.contains(action)){
        uiResult_=result.toString();refreshPanel();
    }
    return result;
}
QVariant SecureSyncPlugin::scriptCallbackImpl(const QVariantList &arguments) {
    if(closing_||!isEnabled()||arguments.isEmpty()||arguments.size()>4)return QStringLiteral("Refused");
    const auto action=arguments.front().toString();const auto configuration=cqs::native::storageConfiguration(profile_);
    const auto epoch=settingsEpoch_,authorizationControl=controlEpoch_;
    try {
        if(action=="diagnostics")return uiStatus().diagnostic(uiContext());
        if(action=="userStatus")return uiStatus().text();
        if(action=="showStatus"){
            if(copyqGuiServer())QMessageBox::information(nullptr,tr("Secure Sync — status"),uiStatus().text());
            return uiStatus().text();
        }
        if(action=="userActionResult"&&arguments.size()==3&&cqs::native::uiAction(arguments[1].toString())){
            // Classification never echoes this caller-provided text, even on
            // an error. Keep the retained value bounded as well.
            uiResult_=arguments[2].toString().left(2048);refreshPanel();return QStringLiteral("Reported");
        }
        if(action=="setNativeRoot"&&arguments.size()==2){storage_.setNativeRoot(arguments[1].toString());return QStringLiteral("Configured");}
        if(action=="beginNativeCapture"&&(arguments.size()==3||arguments.size()==4))
            return storage_.beginNativeCapture(arguments[1].toString(),arguments[2].toInt(),arguments.value(3).toString())?QStringLiteral("Started"):QStringLiteral("Refused");
        if(action=="finishNativeCapture"&&arguments.size()==2)return storage_.finishNativeCapture(arguments[1].toString());
        if(action=="automaticSyncStatus"){
            if(arguments.size()>1&&arguments[1].toString()!=automaticToken_)return QStringLiteral("Stopped");
            if(arguments.size()>1)heartbeat_.restart();
            return runtimeBusy_?QStringLiteral("Working"):automaticStatus_;
        }
        if(action=="automaticCycleDelay"&&arguments.size()==2){
            if(arguments[1].toString()!=automaticToken_)return 1000;
            return int(std::min<std::int64_t>(1000,schedule_.delay(scheduleClock_.elapsed())));
        }
        if(action=="operationStatus"&&arguments.size()==2){
            if(arguments[1].toString()!=manualToken_||manualToken_.isEmpty())return QStringLiteral("Refused: stale operation token");
            return manualStatus_;
        }
        if(action=="enableAutomaticSync"){clientFailures_=0;clientRetryAt_=0;saveAutomaticPreference(true);superviseRuntime();return QStringLiteral("Enabled");}
        if(action=="stopAutomaticSync"){
            ++controlEpoch_;
            if(runtimeJob_)runtimeJob_->operation->cancel();
            saveAutomaticPreference(false);resolving_=false;automaticToken_.clear();automaticKeys_.reset();automaticStatus_="Stopped";
            stopRuntimeClient();if(!runtimeBusy_&&!storage_.hasModels())storage_.releaseKeys();
            return runtimeBusy_?QStringLiteral("Stopping: encrypted recovery state retained"):QStringLiteral("Stopped");
        }
        if(runtimeBusy_)return QStringLiteral("Working");
        if(QStringList{"rotateSyncKey","compactHistory","joinSuccessor","resumeHistoryTransition","cancelHistoryTransition","finishHistoryTransition"}.contains(action))return transitionHistory(arguments);
        if(action=="restoreArchive"){try{return restoreArchive(arguments);}catch(...){runtimeBusy_=false;runtimeJob_.reset();storage_.releaseIdleSession();return QStringLiteral("Refused: backup restore could not be verified");}}
        if(action=="discardArchive"){try{return discardArchive(arguments);}catch(...){runtimeBusy_=false;storage_.releaseIdleSession();return QStringLiteral("Refused: backup removal changed; encrypted data retained");}}
        if(action=="resolveConflict"){try{return resolveConflict(arguments);}catch(...){runtimeBusy_=false;runtimeJob_.reset();storage_.releaseIdleSession();return QStringLiteral("Refused: decision invalid or exceeds limits; encrypted data retained");}}
        if(action=="startAutomaticSync"){
            if(arguments.size()!=3||arguments[1].toString().size()!=36||!automaticToken_.isEmpty())return QStringLiteral("Refused: automatic sync already running or invalid request.");
            const auto refusal=cqs::native::pluginRefusal(arguments[2].toString());if(!refusal.isEmpty())return refusal;
            storage_.setProtection(cqs::native::rowProtection(settingsFile_,arguments[2].toString()));
            if(!profile_.standaloneStorage)return QStringLiteral("Refused");
            saveAutomaticPreference(true);automaticToken_=arguments[1].toString();heartbeat_.restart();automaticKeys_=storage_.keys();automaticStatus_="Waiting";return QStringLiteral("Started");
        }
        if(action=="automaticCycle"){
            if((arguments.size()!=3&&arguments.size()!=4)||automaticToken_.isEmpty()||arguments[1].toString()!=automaticToken_)return QStringLiteral("Refused");
            heartbeat_.restart();if(!schedule_.begin(scheduleClock_.elapsed()))return automaticStatus_;
            const auto incompatible=cqs::native::incompatiblePlugin(arguments[2].toString());
            if(!incompatible.isEmpty()){automaticStatus_="Waiting: incompatible active plugin or inventory: "+incompatible;recordRuntimeResult(automaticStatus_);return automaticStatus_;}
            if(arguments.size()==4&&!arguments[3].toStringList().contains(QStringLiteral("synced_tray"))){automaticStatus_="Waiting: configured tab was removed";recordRuntimeResult(automaticStatus_);return automaticStatus_;}
            storage_.setProtection(cqs::native::rowProtection(settingsFile_,arguments[2].toString()));
            try{const auto result=beginRuntime(automaticToken_);if(!runtimeBusy_)recordRuntimeResult(result);return result;}
            catch(...){runtimeBusy_=false;runtimeJob_.reset();storage_.releaseIdleSession();automaticStatus_="Recovery: private profile unavailable or invalid";recordRuntimeResult(automaticStatus_);return automaticStatus_;}
        }
        if(action=="status")return storage_.locked()?QStringLiteral("Locked"):QStringLiteral("Unlocked");
        if(action=="nativeMigrationStatus"){QSettings settings(settingsFile_,QSettings::IniFormat);
            if(arguments.size()<3)return QStringLiteral("Refused");
            const auto refusal=cqs::native::pluginRefusal(arguments[2].toString());if(!refusal.isEmpty())return refusal;
            storage_.setProtection(cqs::native::rowProtection(settingsFile_,arguments[2].toString()));
            return !profile_.standaloneStorage&&!storage_.hasModels()&&settings.value("Options/encrypt_tabs",false).toBool()?QStringLiteral("NativeStorage"):QStringLiteral("Refused");}
        if(action=="checkpointStorage"){
            if(!storage_.hasModels()&&!storage_.keys()&&automaticKeys_)storage_.useKeys(automaticKeys_);
            storage_.checkpointModels();return QStringLiteral("Checkpointed");}
        if(action=="syncState"||action=="syncRevision"){
            const auto keys=storage_.keys();if(!keys)return QStringLiteral("Locked");
            const auto r=cqs::native::readStorage(configuration,keys->local,keys->sync);
            if(action=="syncRevision")return r.head?QString::fromStdString(r.head->event.revision.id):QStringLiteral("Unjoined");
            if(r.publication)return r.head?QStringLiteral("PendingPublication"):QStringLiteral("PendingSeed");
            if(r.pending)return QStringLiteral("PendingRecovery");
            if(!r.head)return QStringLiteral("Unjoined");
            return *r.local==r.head->snapshot?QStringLiteral("Joined"):QStringLiteral("LocalChanges");
        }
        if(action=="lockStorage"){automaticToken_.clear();automaticKeys_.reset();}
        if(action=="lockStorage")return storage_.releaseKeys()?QStringLiteral("Locked"):QStringLiteral("Refused: loaded model retained; use unload without forcing editors.");
        if(action=="finishDetach"){
            if(!storage_.converted())return QStringLiteral("Pending");
            auto next=profile_;next.standaloneStorage=false;
            QSettings settings(settingsFile_,QSettings::IniFormat);settings.beginGroup("Plugins/securesync");cqs::native::saveProfile(settings,next);
            settings.endGroup();settings.sync();if(settings.status()!=QSettings::NoError)return QStringLiteral("Pending");
            profile_=next;storage_.configure(profile_);if(panel_)panel_->setProfile(profile_);return QStringLiteral("Detached");
        }
        const QStringList stateOperations{"migrateUnifiedState","joinHistory","fastForward","acceptPendingTarget","retryPendingImport","restorePendingOriginal","preserveAndRetry","preserveAndRestore",
            "seedHistory","retrySeed","joinPreservingLocal","restorePreserved","adoptSnapshot","publishChanges","retryPublication","syncNow"};
        const bool stateOperation=stateOperations.contains(action);
        const QStringList operations{"initializeStorage","unlockStorage","changeStoragePassword","rotateLocalKey","backupVault","restoreMissingVault",
            "exportSyncKey","importSyncKey","resumeStorageSetup","migrateLegacyStorage","prepareDetach","cancelDetach","repairMissingVault"};
        if(!operations.contains(action)&&!stateOperation)return QStringLiteral("Refused");
        if(stateOperation&&(storage_.hasModels()||!profile_.standaloneStorage))return QStringLiteral("Refused: checkpoint and ordinarily unload synced_tray first.");
        if(action=="prepareDetach"||stateOperation){
            if(arguments.size()<3)return QStringLiteral("Refused: run Secure Sync: finish encrypted removal; it checks the active plugin inventory.");
            const auto refusal=cqs::native::pluginRefusal(arguments[2].toString());if(!refusal.isEmpty())return refusal;
            storage_.setProtection(cqs::native::rowProtection(settingsFile_,arguments[2].toString()));
        }
        automaticToken_.clear();automaticKeys_.reset();
        // Password dialogs run a nested event loop. Reserve admission before
        // opening one, so the supervisor cannot start another job underneath it.
        runtimeBusy_=true;
        const auto authorization=qScopeGuard([this]{if(!runtimeJob_)runtimeBusy_=false;});
        const Password pass{password(arguments,1,tr("Secure Sync password"),action=="initializeStorage"||action=="repairMissingVault"||action=="importSyncKey")};if(pass.bytes.empty())return QStringLiteral("Refused");
        if(epoch!=settingsEpoch_||authorizationControl!=controlEpoch_||configuration.profile!=profile_)return QStringLiteral("Refused: profile or scheduling changed during authorization.");
        if(stateOperation){
            std::vector<std::string> packed;
            if(action=="adoptSnapshot"){
                if(arguments.size()!=4||arguments[3].metaType().id()!=QMetaType::QVariantList)return QStringLiteral("Refused: use the preserved-tab adoption command.");
                const auto items=arguments[3].toList();if(items.size()>10000)return QStringLiteral("Refused");
                std::size_t total=0;for(const auto &v:items){if(v.metaType().id()!=QMetaType::QByteArray)return QStringLiteral("Refused");
                    const auto encoded=v.toByteArray().toBase64().toStdString();if(encoded.size()>cqs::events::Limits{}.plaintextBytes-total)return QStringLiteral("Refused");
                    total+=encoded.size();packed.push_back(encoded);}
            }
            auto secret=std::make_shared<Password>();secret->bytes=pass.bytes;
            auto job=std::make_shared<SecureSyncJob>();job->configuration=configuration;job->epoch=settingsEpoch_;job->control=controlEpoch_;
            job->session=storage_.sharedSession();
            const auto protection=storage_.protection();
            storage_.beginAsyncImport(this,job->operation);
            runtimeJob_=job;runtimeBusy_=true;manualToken_=QUuid::createUuid().toString(QUuid::WithoutBraces);manualStatus_="Working";
            launchRuntimeWorker([job,secret,action,protection,packed=std::move(packed)]{
                const auto wipe=qScopeGuard([secret]{cqs::crypto::wipe(secret->bytes);});
                try{
                    job->operation->check();
                    if(!job->session)job->session=cqs::native::acquireStorageSession(job->configuration);
                    job->keys=cqs::native::unlockVault(job->configuration,secret->bytes);
                    cqs::crypto::wipe(secret->bytes);job->operation->check();
                    if(job->keys->initializing||job->keys->retiring||!job->keys->pending.empty())throw cqs::crypto::Error("Finish key lifecycle first");
                    using cqs::native::StateAction;
                    if(action=="migrateUnifiedState"){
                        cqs::native::migrateStorageState(job->configuration,job->keys->local,job->keys->sync,job->session.get());job->error="MigratedUnifiedState";return;
                    }
                    if(action=="adoptSnapshot"){
                        const auto result=cqs::native::adoptPackedSnapshot(job->configuration,job->keys,packed,job->session.get());
                        job->error=result==cqs::transaction::Result::Applied?"AdoptedPreservedTab":"UpToDate";return;
                    }
                    const auto chosen=action=="joinHistory"?StateAction::Join:action=="fastForward"?StateAction::FastForward:
                        action=="acceptPendingTarget"?StateAction::AcceptTarget:action=="retryPendingImport"?StateAction::RetryImport:
                        action=="preserveAndRetry"?StateAction::PreserveAndRetry:action=="preserveAndRestore"?StateAction::PreserveAndRestore:
                        action=="seedHistory"?StateAction::Seed:action=="retrySeed"?StateAction::RetrySeed:
                        action=="publishChanges"?StateAction::Publish:action=="retryPublication"?StateAction::RetryPublication:action=="syncNow"?StateAction::Sync:
                        action=="joinPreservingLocal"?StateAction::JoinPreserve:action=="restorePreserved"?StateAction::RestorePreserved:StateAction::RestoreOriginal;
                    const auto result=cqs::native::runStateAction(job->configuration,job->keys,chosen,job->session.get(),protection,[control=job->operation]{control->check();});
                    job->error=result==cqs::transaction::Result::Applied?"Applied":result==cqs::transaction::Result::Restored?"Restored":"UpToDate";
                }catch(...){
                    job->error=operationFailure();
                    if(job->keys&&job->error.contains("multiple authenticated tips"))try{
                        cqs::storage::Directory directory(path(job->configuration.profile.transport));job->history=directory.scan(job->keys->sync);
                    }catch(...){} // Preserve the original refusal; never invent a decision snapshot.
                }
            },[this,job]{
                const bool current=runtimeCurrent(job);
                try{storage_.finishAsyncImport();}catch(...){job->error="Unconfirmed: reload durable state; encrypted record retained";}
                manualStatus_=current?job->error:QStringLiteral("Cancelled: reload durable state; encrypted recovery retained.");
                finishRuntime(job,manualStatus_);
                if(current&&job->keys)storage_.useKeys(job->keys);
            });
            return QStringLiteral("Working:")+manualToken_;
        }
        if(action=="initializeStorage"){
            const auto ownership=std::async(std::launch::async,[configuration]{return cqs::native::acquireStorageSession(configuration);}).get();
            // Refuse existing data before generating another local key/vault.
            {cqs::state::FileStore preflight(path(profile_.stateDirectory),configuration.binding.toStdString(),cqs::crypto::Bytes(32));
             const auto lease=preflight.lock();if(!lease)throw cqs::crypto::Error("Busy setup");preflight.checkInitializable();}
            cqs::native::createVault(configuration,pass.bytes,{},true);
            auto keys=cqs::native::finishStorageSetup(configuration,pass.bytes,ownership.get());
            storage_.useKeys(std::move(keys));return QStringLiteral("Initialized");
        }
        if(action=="repairMissingVault"){
            QSettings saved(settingsFile_,QSettings::IniFormat);const auto journal=saved.value("Plugins/securesync/history_transition_journal").toString();
            const auto archived=[&]{return std::async(std::launch::async,[configuration,journal,&pass]{
                return cqs::native::historyTransitionSourceConfiguration(configuration,pass.bytes,path(journal)).binding;
            }).get();};
            // Suspended preparations must retain the journal's original password.
            QString alternate;if(storage_.keys()&&storage_.keys()->suspended)alternate=archived();
            try{cqs::native::repairMissingVault(configuration,storage_.keys(),pass.bytes,alternate);}
            catch(const cqs::state::Error &e){if(e.code()!=cqs::state::ErrorCode::AuthenticationFailed||!alternate.isEmpty())throw;
                cqs::native::repairMissingVault(configuration,storage_.keys(),pass.bytes,archived());}
            return QStringLiteral("VaultRepaired");}
        if(action=="unlockStorage")return storage_.unlock(pass.bytes)?QStringLiteral("Unlocked"):QStringLiteral("Refused");
        if(action=="resumeStorageSetup"){
            auto keys=cqs::native::finishStorageSetup(configuration,pass.bytes);
            storage_.useKeys(std::move(keys));return QStringLiteral("Initialized");
        }
        if(action=="migrateLegacyStorage"){storage_.useKeys(cqs::native::migrateLegacyStorage(configuration,pass.bytes));return QStringLiteral("MigratedLegacyStorage");}
        if(action=="changeStoragePassword"){
            const Password next{password(arguments,2,tr("New Secure Sync password (at least 12 bytes)"),true)};
            if(epoch!=settingsEpoch_||authorizationControl!=controlEpoch_||configuration.profile!=profile_)return QStringLiteral("Refused: profile changed during authorization.");
            cqs::native::changeVaultPassword(configuration,pass.bytes,next.bytes);return QStringLiteral("PasswordChanged");
        }
        if(action=="rotateLocalKey"){
            if(storage_.hasModels())storage_.checkpointModels();
            storage_.refreshedKeys(cqs::native::rotateStorageKey(configuration,pass.bytes,storage_.session()));return QStringLiteral("KeyRotated");
        }
        if(action=="prepareDetach"){
            QSettings global(settingsFile_,QSettings::IniFormat);
            if(!global.value("Options/encrypt_tabs",false).toBool())return QStringLiteral("Refused: enable CopyQ Encrypt Tabs before removal.");
            storage_.unlock(pass.bytes);storage_.checkpointModels();storage_.useKeys(cqs::native::setVaultRetirement(configuration,pass.bytes,true,storage_.session()));
            handoffEpoch_=settingsEpoch_;storage_.beginDetach();return QStringLiteral("DetachPrepared");
        }
        if(action=="cancelDetach"){
            if(storage_.converted())return QStringLiteral("Refused: native handoff already committed.");
            storage_.useKeys(cqs::native::setVaultRetirement(configuration,pass.bytes,false,storage_.session()));storage_.configure(profile_);return QStringLiteral("DetachCancelled");
        }
        if(action=="exportSyncKey"||action=="importSyncKey"){
            const Password peer{password(arguments,2,tr("Separate transfer password (at least 12 bytes)"),action=="exportSyncKey")};
            const auto folder=arguments.size()>3?arguments[3].toString():QFileDialog::getExistingDirectory(nullptr,tr("Choose private key transfer directory"));
            if(folder.isEmpty())return QStringLiteral("Refused");
            if(epoch!=settingsEpoch_||authorizationControl!=controlEpoch_||configuration.profile!=profile_)return QStringLiteral("Refused: profile changed during authorization.");
            if(action=="exportSyncKey"){cqs::native::exportSyncKey(configuration,pass.bytes,peer.bytes,path(folder));return QStringLiteral("SyncKeyExported");}
            const auto ownership=std::async(std::launch::async,[configuration]{return cqs::native::acquireStorageSession(configuration);}).get();
            {cqs::state::FileStore preflight(path(profile_.stateDirectory),configuration.binding.toStdString(),cqs::crypto::Bytes(32));
             const auto lease=preflight.lock();if(!lease)throw cqs::crypto::Error("Busy setup");preflight.checkInitializable();}
            cqs::native::importSyncVault(configuration,pass.bytes,peer.bytes,path(folder));
            auto keys=cqs::native::finishStorageSetup(configuration,pass.bytes,ownership.get());
            storage_.useKeys(std::move(keys));return QStringLiteral("InitializedFromSharedKey");
        }
        const auto folder=arguments.size()>2?arguments[2].toString():QFileDialog::getExistingDirectory(nullptr,tr("Choose private vault backup directory"));
        if(folder.isEmpty())return QStringLiteral("Refused");
        if(epoch!=settingsEpoch_||authorizationControl!=controlEpoch_||configuration.profile!=profile_)return QStringLiteral("Refused: profile changed during authorization.");
        if(action=="backupVault"){cqs::native::backupVault(configuration,pass.bytes,path(folder));return QStringLiteral("VaultBackedUp");}
        try{cqs::native::restoreMissingVault(configuration,pass.bytes,path(folder));}
        catch(const cqs::state::Error &e){if(e.code()!=cqs::state::ErrorCode::AuthenticationFailed)throw;
            QSettings saved(settingsFile_,QSettings::IniFormat);const auto journal=saved.value("Plugins/securesync/history_transition_journal").toString();
            const auto alternate=std::async(std::launch::async,[configuration,journal,&pass]{
                return cqs::native::historyTransitionSourceConfiguration(configuration,pass.bytes,path(journal)).binding;
            }).get();
            cqs::native::restoreMissingVault(configuration,pass.bytes,path(folder),alternate);
        }return QStringLiteral("VaultRestored");
    } catch(...) {return operationFailure();}
}

QString SecureSyncPlugin::transitionHistory(const QVariantList &arguments){
    using namespace cqs::native;
    if(arguments.size()<3||storage_.hasModels()||!profile_.standaloneStorage)return "Refused: checkpoint and ordinarily unload synced_tray first.";
    const auto refusal=pluginRefusal(arguments[2].toString());if(!refusal.isEmpty())return refusal;
    runtimeBusy_=true;const auto admission=qScopeGuard([this]{if(!runtimeJob_)runtimeBusy_=false;});
    const auto epoch=settingsEpoch_,control=controlEpoch_;const auto source=storageConfiguration(profile_);
    const auto action=arguments[0].toString();const auto request=arguments.value(3).toMap();
    const Password pass{password(arguments,1,tr("Secure Sync password"))};if(pass.bytes.empty())return "Refused";
    QSettings previous(settingsFile_,QSettings::IniFormat);
    const auto choose=[&](const char *key,const QString &title){return request.contains(key)?request.value(key).toString():QFileDialog::getExistingDirectory(nullptr,title,
        QLatin1String(key)=="journal"?previous.value("Plugins/securesync/history_transition_journal").toString():QString{});};
    const auto journal=choose("journal",tr("Choose private transition journal folder (keep for recovery)"));if(journal.isEmpty())return "Cancelled";
    const bool resume=action=="resumeHistoryTransition",cancel=action=="cancelHistoryTransition",finish=action=="finishHistoryTransition";
    auto journalSecret=std::make_shared<Password>();journalSecret->bytes=pass.bytes;
    if(finish){const auto raw=request.value("journalPassword").toByteArray();journalSecret->bytes=request.contains("journalPassword")?
        cqs::crypto::Bytes(raw.begin(),raw.end()):password({},0,tr("Password used when creating the transition journal"));if(journalSecret->bytes.empty())return "Cancelled";}
    Profile target=profile_;target.keyFile.clear();target.predecessorBinding=source.binding.right(64);target.publicationStaging.clear();
    const auto mode=action=="compactHistory"?HistoryTransitionMode::Compact:action=="joinSuccessor"?HistoryTransitionMode::Join:HistoryTransitionMode::Rekey;
    auto sharedKey=std::make_shared<Password>();auto transferSecret=std::make_shared<Password>();QString transferDirectory;
    if(!resume&&!cancel&&!finish){
        target.transport=choose("transport",tr("Choose successor synchronization folder (must contain events/)"));if(target.transport.isEmpty())return "Cancelled";
        target.stateDirectory=choose("state",tr("Choose NEW private state folder"));if(target.stateDirectory.isEmpty())return "Cancelled";
        target.vaultDirectory=choose("vault",tr("Choose NEW private vault folder"));if(target.vaultDirectory.isEmpty())return "Cancelled";
#ifdef Q_OS_WIN
        target.publicationStaging=choose("staging",tr("Choose private staging folder on successor transport's NTFS volume"));if(target.publicationStaging.isEmpty())return "Cancelled";
#endif
        if(mode==HistoryTransitionMode::Join){
            const auto transfer=choose("transfer",tr("Choose encrypted NEW synchronization-key transfer folder"));if(transfer.isEmpty())return "Cancelled";
            const Password transferPass{request.contains("transferPassword")?cqs::crypto::Bytes{}:password({},0,tr("Separate transfer password"))};
            // Programmatic callers supply bytes, never interpolated script text.
            const auto raw=request.value("transferPassword").toByteArray();
            const Password selected{request.contains("transferPassword")?cqs::crypto::Bytes(raw.begin(),raw.end()):transferPass.bytes};
            transferDirectory=transfer;transferSecret->bytes=selected.bytes;
        }
    }
    if(epoch!=settingsEpoch_||control!=controlEpoch_||source.profile!=profile_)return "Refused: profile or scheduling changed during authorization.";
    if(cancel){QSettings saved(settingsFile_,QSettings::IniFormat);saved.beginGroup("Plugins/securesync");
        if(loadProfile(saved)!=source.profile)return "Refused: restart and inspect the active profile before cancellation.";}
    automaticToken_.clear();automaticKeys_.reset();saveAutomaticPreference(false);resolving_=false;
    storage_.releaseIdleSession();if(!storage_.releaseKeys())return "Refused: loaded model retained.";
    // The path is recovery guidance only; credentials and journal contents never
    // enter CopyQ settings. The encrypted journal owns the transition identity.
    QSettings settings(settingsFile_,QSettings::IniFormat);settings.setValue("Plugins/securesync/history_transition_journal",journal);settings.sync();
    if(settings.status()!=QSettings::NoError)return "Refused: could not retain recovery journal location.";
    auto secret=std::make_shared<Password>();secret->bytes=pass.bytes;
    auto result=std::make_shared<std::optional<HistoryTransitionResult>>();
    auto job=std::make_shared<SecureSyncJob>();job->configuration=source;job->epoch=epoch;job->control=control;
    const auto protection=rowProtection(settingsFile_,arguments[2].toString());
    storage_.beginAsyncImport(this,job->operation);runtimeJob_=job;manualToken_=QUuid::createUuid().toString(QUuid::WithoutBraces);manualStatus_="Working";
    launchRuntimeWorker([job,secret,journalSecret,sharedKey,transferSecret,transferDirectory,result,target,journal,resume,cancel,finish,mode,protection]{
        const auto wipe=qScopeGuard([&]{cqs::crypto::wipe(sharedKey->bytes);cqs::crypto::wipe(transferSecret->bytes);});
        try{
            job->operation->check();
            if(cancel){cancelHistoryTransition(job->configuration,secret->bytes,path(journal),true);job->error="HistoryTransitionCancelled";}
            else if(finish){finishHistoryTransition(job->configuration,secret->bytes,journalSecret->bytes,path(journal));job->error="HistoryTransitionFinalized";}
            else {
                const auto check=[operation=job->operation]{operation->check();};
                if(!resume&&mode==HistoryTransitionMode::Join)sharedKey->bytes=readTransferredSyncKey(job->configuration,transferSecret->bytes,path(transferDirectory));
                *result=resume?resumeHistoryTransition(job->configuration,secret->bytes,path(journal),protection,check):
                    startHistoryTransition(job->configuration,target,secret->bytes,path(journal),mode,sharedKey->bytes,protection,check);
            }
        }catch(const cqs::native::ModelError &e){job->error=e.code()==cqs::native::ModelErrorCode::ProtectedItems?
            "Waiting: pinned or locked tagged items must be released before joining the successor; local data retained":
            "Recovery: history/key transition refused; keep both profiles and the journal.";}
        catch(...){job->error="Recovery: history/key transition refused or interrupted. Check the password and selected paths. If the journal exists, Resume or Cancel; otherwise repeat the original action. Local data retained.";}
    },[this,job,result,secret,journalSecret,journal]{
        const bool current=runtimeCurrent(job);
        manualStatus_=job->error;
        if(current&&*result){
            try{
                QSettings settings(settingsFile_,QSettings::IniFormat);settings.beginGroup("Plugins/securesync");activateProfile(settings,(*result)->profile);
                profile_=(*result)->profile;++settingsEpoch_;storage_.configure(profile_);conflictHistory_.reset();
                transportWatch_.setFolder({});if(panel_)panel_->setProfile(profile_);
                // Redact the journal only after the single-value activation.
                // An exit before this step retains a resumable encrypted key backup.
                manualStatus_="Working";
                launchRuntimeWorker([job,result,secret,journalSecret,journal]{
                    const auto wipe=qScopeGuard([&]{cqs::crypto::wipe(secret->bytes);cqs::crypto::wipe(journalSecret->bytes);});
                    try{cqs::native::finishHistoryTransition(cqs::native::storageConfiguration((*result)->profile),secret->bytes,secret->bytes,path(journal));
                        job->error="HistoryTransitioned: new key/history active; journal sealed without keys. Automatic sync is off. Back up new keys, share the NEW key separately, and Join successor on other devices. Keep the old archive.";
                    }catch(...){job->error="HistoryTransitioned: new profile active; journal still contains encrypted keys. Use Seal journal of active successor with its original password before discarding recovery material.";}
                },[this,job,result]{
                    storage_.finishAsyncImport();manualStatus_=job->error;finishRuntime(job,manualStatus_);
                    if(profile_==(*result)->profile)storage_.useKeys((*result)->keys);
                });
                return;
            }catch(...){manualStatus_="Unconfirmed: profile activation may have committed. Restart CopyQ, check the active profile, and resume only if it still selects the old profile. Keep both profiles and journal.";}
        }else if(!current)manualStatus_="Recovery: activation deferred after settings/shutdown. Keep both profiles and resume the recorded transition.";
        cqs::crypto::wipe(secret->bytes);cqs::crypto::wipe(journalSecret->bytes);storage_.finishAsyncImport();
        finishRuntime(job,manualStatus_);
    });
    return QStringLiteral("Working:")+manualToken_;
}

QString SecureSyncPlugin::description() const {
    return tr("Secure Sync %1: encrypted local storage and folder synchronization, Seed/Join, automatic synchronization, conflict recovery and key/history transitions.").arg(QStringLiteral(CQS_RELEASE_VERSION));
}
QVariant SecureSyncPlugin::icon() const { return QVariant::fromValue(QIcon::fromTheme(QStringLiteral("folder-sync"))); }
QVector<Command> SecureSyncPlugin::commands() const {
    QVector<Command> result;
    for(const auto &entry:QList<QPair<QString,QString>>{
        {tr("Secure Sync: status and next step"),QStringLiteral("plugins.securesync.showStatus()")},
        {tr("Secure Sync: rotate shared key retaining history"),QStringLiteral("plugins.securesync.rotateSyncKey()")},
        {tr("Secure Sync: compact history into a new generation"),QStringLiteral("plugins.securesync.compactHistory()")},
        {tr("Secure Sync: join successor and preserve local edits"),QStringLiteral("plugins.securesync.joinSuccessor()")},
        {tr("Secure Sync: resume interrupted history/key transition"),QStringLiteral("plugins.securesync.resumeHistoryTransition()")},
        {tr("Secure Sync: seal journal of active successor"),QStringLiteral("plugins.securesync.finishHistoryTransition()")},
        {tr("Secure Sync: cancel incomplete history/key transition"),QStringLiteral("plugins.securesync.cancelHistoryTransition()")},
        {tr("Secure Sync: restore a protected conflict backup"),QStringLiteral("plugins.securesync.restoreArchive()")},
        {tr("Secure Sync: compare and resolve conflicts"),QStringLiteral("plugins.securesync.resolveConflict()")},
        {tr("Secure Sync: remove a protected conflict backup"),QStringLiteral("plugins.securesync.discardArchive()")},
        {tr("Secure Sync: publish local changes"),QStringLiteral("plugins.securesync.publishChanges()")},
        {tr("Secure Sync: retry reserved publication"),QStringLiteral("plugins.securesync.retryPublication()")},
        {tr("Secure Sync: synchronize now"),QStringLiteral("plugins.securesync.syncNow()")},
        {tr("Secure Sync: start automatic synchronization"),QStringLiteral("plugins.securesync.enableAutomaticSync()")},
        {tr("Secure Sync: stop automatic synchronization"),QStringLiteral("plugins.securesync.stopAutomaticSync()")},
        {tr("Secure Sync: lock"),QStringLiteral("plugins.securesync.lockStorage()")},
        {tr("Secure Sync: finish encrypted removal"),QStringLiteral("plugins.securesync.detachStorage()")},
        {tr("Secure Sync: migrate local checkpoint to unified state"),QStringLiteral("plugins.securesync.migrateUnifiedState()")},
        {tr("Secure Sync: Join authenticated history (empty tab)"),QStringLiteral("plugins.securesync.joinHistory()")},
        {tr("Secure Sync: Seed first history from local data"),QStringLiteral("plugins.securesync.seedHistory()")},
        {tr("Secure Sync: retry reserved Seed"),QStringLiteral("plugins.securesync.retrySeed()")},
        {tr("Secure Sync: Join history and keep a local backup"),QStringLiteral("plugins.securesync.joinPreservingLocal()")},
        {tr("Secure Sync: restore preserved pre-Join data"),QStringLiteral("plugins.securesync.restorePreserved()")},
        {tr("Secure Sync: preserve ordinary CopyQ tab before setup"),QStringLiteral("plugins.securesync.preserveNativeTab()")},
        {tr("Secure Sync: import preserved CopyQ tab (keeps source)"),QStringLiteral("plugins.securesync.adoptFromTab()")},
        {tr("Secure Sync: import next history tip"),QStringLiteral("plugins.securesync.fastForward()")},
        {tr("Secure Sync: accept pending target"),QStringLiteral("plugins.securesync.acceptPendingTarget()")},
        {tr("Secure Sync: retry pending import"),QStringLiteral("plugins.securesync.retryPendingImport()")},
        {tr("Secure Sync: preserve new edits and retry pending import"),QStringLiteral("plugins.securesync.preserveAndRetry()")},
        {tr("Secure Sync: preserve new edits and restore pending original"),QStringLiteral("plugins.securesync.preserveAndRestore()")},
        {tr("Secure Sync: restore pending original"),QStringLiteral("plugins.securesync.restorePendingOriginal()")}}) {
        auto script=entry.second;
        const auto action=script.mid(QStringLiteral("plugins.securesync.").size()).chopped(2);
        if(cqs::native::uiAction(action))script=QStringLiteral("plugins.securesync.userAction('%1')").arg(action);
        Command command;command.name=entry.first;command.cmd=QStringLiteral("copyq: ")+script;
        command.inMenu=true;command.hideWindow=!(entry.second.contains("AutomaticSync")||entry.second.contains("resolveConflict")||entry.second.contains("restoreArchive")||entry.second.contains("discardArchive"));command.internalId=entry.second;result.append(command);
    }
    return result;
}
void SecureSyncPlugin::loadSettings(const QSettings &s) {
    ++settingsEpoch_;
    if(runtimeJob_)runtimeJob_->operation->cancel();
    if(runtimeBusy_){emit error(tr("Settings change deferred until synchronization finishes."));return;}
    automaticToken_.clear();automaticKeys_.reset();
    settingsFile_=s.fileName();automaticEnabled_=s.value("automatic_enabled",false).toBool();
    if(copyqGuiServer())supervisor_.start();
    const auto next=cqs::native::loadProfile(s);
    if(storage_.hasModels()&&next!=profile_){emit error(tr("Profile change deferred: close/unload the owned tab or use the explicit encrypted handoff."));return;}
    if(next!=profile_){uiResult_.clear();localSaveProblem_=false;}
    profile_ = next;
    storage_.configure(profile_);
    schedule_.reset(scheduleClock_.elapsed());
    transportWatch_.setFolder(automaticEnabled_&&cqs::native::validateProfile(profile_,false).isEmpty()?profile_.transport:QString{});
    storage_.setCacheFile(s.value("host_cache_file").toString());
    if (panel_) panel_->setProfile(profile_);
}
void SecureSyncPlugin::applySettings(QSettings &s) {
    if (!panel_) return;
    ++settingsEpoch_;saveAutomaticPreference(panel_->automaticEnabled());
    if(runtimeJob_)runtimeJob_->operation->cancel();
    if(runtimeBusy_)return;
    automaticToken_.clear();automaticKeys_.reset();
    const auto draft = panel_->profile();
    if((profile_.standaloneStorage&&!draft.standaloneStorage&&!storage_.converted())||(storage_.hasModels()&&draft!=profile_)){panel_->setStatus(tr("Unload synced_tray or prepare encrypted removal before changing the active profile."));panel_->setProfile(profile_);return;}
    const auto error = draft.isEmpty() ? QString() : cqs::native::validateProfile(draft, false);
    if (!error.isEmpty()) {
        QMessageBox::warning(panel_, tr("Secure Sync — settings not saved"), error);
        panel_->setProfile(profile_);
        return;
    }
    if(draft!=profile_){uiResult_.clear();localSaveProblem_=false;}
    profile_ = draft;
    storage_.configure(profile_);
    schedule_.reset(scheduleClock_.elapsed());
    transportWatch_.setFolder(automaticEnabled_?profile_.transport:QString{});
    cqs::native::saveProfile(s, profile_);
}
QWidget *SecureSyncPlugin::createSettingsWidget(QWidget *parent) {
    auto *widget = new cqs::native::SettingsWidget(profile_, parent);
    panel_ = widget;widget->setAutomaticEnabled(automaticEnabled_);
    widget->setBusy(inspector_.busy() || !isEnabled());
    auto *uiTimer=new QTimer(widget);uiTimer->setInterval(500);
    connect(uiTimer,&QTimer::timeout,this,&SecureSyncPlugin::refreshPanel);uiTimer->start();
    connect(widget,&cqs::native::SettingsWidget::operationRequested,this,&SecureSyncPlugin::runPanelAction);
    connect(widget, &cqs::native::SettingsWidget::inspectRequested, this,
            [this, widget](const cqs::native::Profile &p) {
        if (!isEnabled() || inspector_.busy() || runtimeBusy_ || panelClient_ || panel_ != widget) return;
        inspectionPanel_ = widget;
        inspectionProfile_ = p;
        widget->setBusy(true);
        widget->setStatus(tr("Inspecting the selected transport. No clipboard data or state will be changed."));
        if(!p.vaultDirectory.isEmpty()&&(!storage_.keys()||p!=profile_)){widget->setBusy(false);widget->setStatus(tr("Apply this profile and unlock Secure Sync before inspection."));return;}
        if (!inspector_.request(p,!p.vaultDirectory.isEmpty()&&p==profile_&&storage_.keys()
            ?storage_.keys()->sync:cqs::crypto::Bytes{})) widget->setBusy(false);
    });
    connect(widget, &cqs::native::SettingsWidget::initializeStorageRequested, this,
            [this, widget](const cqs::native::Profile &profile) {
        if (!isEnabled() || inspector_.busy() || runtimeBusy_ || panelClient_ || panel_ != widget) return;
        runtimeBusy_=true;const auto admission=qScopeGuard([this]{runtimeBusy_=false;refreshPanel();});
        const auto epoch=settingsEpoch_;const QPointer<cqs::native::SettingsWidget> guard(widget);
        if (QMessageBox::question(widget, tr("Initialize standalone storage"),
            tr("Create an empty encrypted record in the selected private folder? Existing records are never overwritten. "
               "This does not migrate a tab or start synchronization. Use disposable data until encryption/lifecycle compatibility is certified."),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
        try {
            const Password pass{password({},1,tr("Create Secure Sync password (at least 12 bytes)"),true)};
            if(!guard||panel_!=guard||guard->profile()!=profile||settingsEpoch_!=epoch)return;
            const auto configuration=cqs::native::storageConfiguration(profile);
            const auto ownership=std::async(std::launch::async,[configuration]{return cqs::native::acquireStorageSession(configuration);}).get();
            {cqs::state::FileStore preflight(path(profile.stateDirectory),configuration.binding.toStdString(),cqs::crypto::Bytes(32));
             const auto lease=preflight.lock();if(!lease)throw cqs::crypto::Error("Busy setup");preflight.checkInitializable();}
            cqs::native::createVault(configuration,pass.bytes,{},true);
            auto keys=cqs::native::finishStorageSetup(configuration,pass.bytes,ownership.get());
            if(profile==profile_)storage_.useKeys(std::move(keys));
            uiResult_="Initialized";
            widget->setStatus(tr("Empty standalone storage initialized. Apply settings before creating a new empty synced_tray tab."));
        } catch (...) {
            uiResult_="Unconfirmed: initialization requires review";
            if(guard)guard->setStatus(tr("Initialization refused or unconfirmed: retain the record and vault; finish interrupted setup if they were created. Existing state is never reset."));
        }
    });
    connect(widget,&cqs::native::SettingsWidget::vaultActionRequested,this,[this,widget](const QString &action){
        if(!isEnabled()||inspector_.busy()||runtimeBusy_||panelClient_||panel_!=widget)return;
        if(widget->profile()!=profile_){widget->setStatus(tr("Apply the profile before key operations."));return;}
        if(cqs::native::uiAction(action)){runPanelAction(action);return;}
        const QPointer<cqs::native::SettingsWidget> guard(widget);
        const auto result=scriptCallback({action}).toString();if(guard)guard->setStatus(cqs::native::presentStatus(uiContext(),result).text());
    });
    refreshPanel();
    return widget;
}
cqs::native::UiContext SecureSyncPlugin::uiContext() const {
    using Phase=cqs::native::StoragePhase;const auto phase=storage_.phase();
    return {profile_.standaloneStorage&&cqs::native::validateProfile(profile_,false).isEmpty(),isEnabled(),
        storage_.locked(),runtimeBusy_||!panelClient_.isNull(),automaticEnabled_,storage_.hasUnsavedChanges(),storage_.verifiedLocal(),localSaveProblem_,
        phase==Phase::Import,phase==Phase::Publication,phase==Phase::Resolution,phase==Phase::Unjoined,storage_.keys()&&storage_.keys()->suspended};
}
cqs::native::UiStatus SecureSyncPlugin::uiStatus() const {return cqs::native::presentStatus(uiContext(),uiResult_);}
void SecureSyncPlugin::refreshPanel(){
    if(!panel_)return;
    const auto context=uiContext();
    panel_->setBusy(!isEnabled()||inspector_.busy()||context.busy);
    panel_->setRuntimeStatus(context,uiStatus(),panel_->profile()==profile_,!inspector_.busy());
}
void SecureSyncPlugin::runPanelAction(const QString &id){
    const auto *entry=cqs::native::uiAction(id);
    if(!entry||!panel_||!isEnabled()||inspector_.busy()||panel_->profile()!=profile_)return;
    if(id=="stopAutomaticSync"&&(runtimeBusy_||panelClient_)){
        scriptCallback({QStringLiteral("stopAutomaticSync")});refreshPanel();return;
    }
    if(runtimeBusy_||panelClient_)return;
    const auto epoch=settingsEpoch_;const QPointer<cqs::native::SettingsWidget> guard(panel_);
    if(entry->confirmation&&QMessageBox::question(panel_,tr("Secure Sync — confirm action"),cqs::native::uiText(entry->confirmation),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    if(!guard||guard!=panel_||epoch!=settingsEpoch_||guard->profile()!=profile_||runtimeBusy_||panelClient_||!isEnabled())return;
    // Fixed allowlisted identifiers only; no shell, path, password or user text
    // is interpolated into the CopyQ script. The ordinary session API performs
    // checkpoint/unload/inventory checks just like menu commands.
    auto *client=new QProcess(this);panelClient_=client;uiResult_="Working";
    client->setStandardOutputFile(QProcess::nullDevice());client->setStandardErrorFile(QProcess::nullDevice());
    connect(client,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this,client](int code,QProcess::ExitStatus status){
        if(code!=0||status!=QProcess::NormalExit)uiResult_="Unconfirmed: action client interrupted";
        if(panelClient_==client)panelClient_=nullptr;client->deleteLater();refreshPanel();
    });
    connect(client,&QProcess::errorOccurred,this,[this,client](QProcess::ProcessError error){
        if(error!=QProcess::FailedToStart)return;
        uiResult_="Refused: action client unavailable";if(panelClient_==client)panelClient_=nullptr;client->deleteLater();refreshPanel();
    });
    client->start(QCoreApplication::applicationFilePath(),{"eval",QStringLiteral("plugins.securesync.userAction('%1');undefined;").arg(id)});
    refreshPanel();
}
void SecureSyncPlugin::setEnabled(bool enabled) {
    if(!enabled){++controlEpoch_;if(runtimeJob_)runtimeJob_->operation->cancel();saveAutomaticPreference(false);resolving_=false;automaticToken_.clear();automaticKeys_.reset();if(runtimeBusy_){emit error(tr("Synchronization is stopping; retain the plugin until encrypted recovery is checked."));return;}}
    if(!enabled&&profile_.standaloneStorage&&!storage_.converted()){
        try{if(storage_.hasModels())storage_.checkpointModels();}catch(...){emit error(tr("Disable refused: local checkpoint could not be confirmed."));return;}
        emit error(tr("Disable deferred: prepare encrypted CopyQ handoff before removing this plugin."));return;
    }
    ItemLoaderInterface::setEnabled(enabled);
    storage_.setEnabled(enabled);
    if (panel_) panel_->setBusy(!enabled || inspector_.busy());
}
#include "plugin.moc"
