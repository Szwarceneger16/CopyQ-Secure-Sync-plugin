// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_storage.h"
#include "unified_state.h"
#include <QApplication>
#include <QAbstractItemView>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QLineEdit>
#include "model_clipboard.h"
#include "native_blob.h"
#include "gui_clipboard.h"
#include "packed_items.h"
#include "state_record.h"
#include "sync_schedule.h"
#include "common/contenttype.h"
#include <QAbstractListModel>
#include <QCoreApplication>
#include <QDataStream>
#include <QIODevice>
#include <QThread>
#include <QBuffer>
#include <QFileDevice>
#include <QDir>
#include <future>
#include <QScopeGuard>

namespace cqs::native {
namespace {
const QByteArray Magic("CQSLOC01", 8);
constexpr int MarkerBytes = 8 + 64 + 8;
bool gui(const QAbstractItemModel *model) {
    const auto *app = QCoreApplication::instance();
    return model && app && model->thread() == app->thread() && QThread::currentThread() == app->thread();
}
QByteArray identity(const StorageConfiguration &c) { return c.binding.right(64).toLatin1(); }
class Saver final : public ItemSaverInterface {
public:
    Saver(StorageConfiguration configuration, QAbstractListModel *model, StandaloneStorage *owner)
        : configuration_(std::move(configuration)), model_(model), owner_(owner) {}
    bool canDropItem(const QModelIndex &) override { return false; } // Never silently crop durable data.
    bool saveItems(const QString &tab, const QAbstractItemModel &model, QIODevice *file) override {
        if (tab != QLatin1String("synced_tray") || model_ != &model || !gui(&model) ||
            !owner_ || !owner_->current(configuration_) || !file) return false;
        try {
            ModelAccess access;
            // Saving observes committed model data; it never modifies an editor
            // or imports data. Writable/replace capability is intentionally absent.
            access.readable = [] { return true; };
            ModelClipboard adapter(model_, std::move(access), storageLimits());
            const auto before = adapter.capture(storageLimits());
            const auto generation=owner_->generation(&model);if(!generation||!owner_->session())return false;
            const auto durable = saveStorage(configuration_, before.snapshot, owner_->keys()->local,owner_->keys()->sync,owner_->session(),generation);
            const auto after = adapter.capture(storageLimits());
            if (!owner_ || !owner_->current(configuration_) || after.epoch != before.epoch || after.snapshot != before.snapshot)
                return false;
            owner_->confirmedCheckpoint(&model,durable,*generation);
            if(auto *native=qobject_cast<QFileDevice *>(file)) {
                const auto filename=native->fileName();
                if(QDir::isAbsolutePath(filename))emit owner_->cacheFileObserved(filename);
            }
            QByteArray marker = Magic + identity(configuration_);
            QDataStream stream(&marker, QIODevice::Append); stream.setVersion(QDataStream::Qt_4_7);
            stream << quint64(durable.generation);
            // The borrowed device is only CopyQ's cache. Its final commit belongs to CopyQ.
            return stream.status() == QDataStream::Ok && file->write(marker) == marker.size();
        } catch (...) {
            if (owner_) emit owner_->error(QStringLiteral("Secure Sync local save refused or unconfirmed. Check the key, private state, supported MIME types and size limits; existing private data were not reset."));
            return false;
        }
    }
private:
    StorageConfiguration configuration_;
    QPointer<QAbstractListModel> model_;
    QPointer<StandaloneStorage> owner_;
};
// The ordinary host owns this saver. Delegate every public callback; only the
// explicitly scoped preserved-tab capture audits copyItem before the host's
// serializer can invoke a lazy file converter.
class CaptureSaver final : public ItemSaverInterface {
public:
    CaptureSaver(ItemSaverPtr saver, StandaloneStorage *owner):saver_(std::move(saver)),owner_(owner){}
    bool saveItems(const QString &tab,const QAbstractItemModel &model,QIODevice *file) override {return saver_->saveItems(tab,model,file);}
    bool canRemoveItems(const QList<QModelIndex> &indexes,QString *error) override {return saver_->canRemoveItems(indexes,error);}
    bool canDropItem(const QModelIndex &index) override {return saver_->canDropItem(index);}
    bool canMoveItems(const QList<QModelIndex> &indexes) override {return saver_->canMoveItems(indexes);}
    void itemsRemovedByUser(const QList<QPersistentModelIndex> &indexes) override {saver_->itemsRemovedByUser(indexes);}
    void setFocus(bool focus) override {saver_->setFocus(focus);}
    QVariantMap copyItem(const QAbstractItemModel &model,const QVariantMap &data) override {
        if(owner_&&owner_->capturingNative())return owner_->copyNativeItem(model,data);
        const auto result=saver_->copyItem(model,data);
        return owner_?owner_->copyNativeItem(model,result):result;
    }
private:
    ItemSaverPtr saver_;
    QPointer<StandaloneStorage> owner_;
};
} // namespace
StandaloneStorage::StandaloneStorage(QObject *parent):QObject(parent) {
    checkpointClock_.start();checkpointTimer_.setSingleShot(true);
    connect(&checkpointTimer_,&QTimer::timeout,this,&StandaloneStorage::scheduledCheckpoint);
    expiry_.setSingleShot(true);connect(&expiry_,&QTimer::timeout,this,[this]{if(models_.isEmpty())keys_.reset();});
}
void StandaloneStorage::modelChanged(QAbstractItemModel *model) {
    if(!models_.contains(model)||!enabled_||converted_||routing_)return;
    verifiedLocal_=false;
    dirtyModels_.insert(model);if(dirtySince_<0)dirtySince_=checkpointClock_.elapsed();
    // Import-generated changes are checkpointed by finishAsyncImport. User
    // edits during the transaction are retained by that same final checkpoint.
    if(!importing_){scheduleCheckpoint();emit modelEdited();}
}
void StandaloneStorage::scheduleCheckpoint() {
    if(dirtyModels_.isEmpty()||!keys_||!enabled_||importing_)return;
    const auto now=checkpointClock_.elapsed();
    const auto due=std::max(checkpointRetry_,std::min(now+250,dirtySince_+1000));
    checkpointTimer_.start(int(std::max<qint64>(0,due-now)));
}
void StandaloneStorage::scheduledCheckpoint() {
    if(dirtyModels_.isEmpty()||!enabled_||!keys_)return;
    if(importing_)return; // completion or explicit recovery owns the record
    try{checkpointModels();}
    catch(...){
        checkpointFailures_=std::min(7u,checkpointFailures_+1);
        checkpointRetry_=checkpointClock_.elapsed()+retryDelay(checkpointFailures_);
        if(checkpointFailures_==1)emit error(QStringLiteral("Secure Sync scheduled local checkpoint refused or unconfirmed; edits remain in memory. Check private storage and retain the application until saving succeeds."));
        scheduleCheckpoint();
    }
}
void StandaloneStorage::confirmedCheckpoint(const QAbstractItemModel *model,const transaction::Record &record,std::uint64_t previous) {
    confirmedGeneration(model,record.generation);dirtyModels_.remove(model);
    observeRecord(record);
    verifiedLocal_=true;emit checkpointVerified();
    if(dirtyModels_.isEmpty()){
        checkpointTimer_.stop();dirtySince_=-1;checkpointRetry_=0;checkpointFailures_=0;
    }
    // Import echo cannot schedule a new outgoing revision. The authenticated
    // accepted snapshot, not the origin of a Qt signal, determines dirtiness.
    if(record.generation!=previous&&record.head&&record.local&&*record.local!=record.head->snapshot)
        emit localCheckpointed();
}
bool StandaloneStorage::beginNativeCapture(const QString &token,int rows,const QString &root){
    if(!enabled_||!captureToken_.isEmpty()||token.size()!=36||rows<=0||rows>int(storageLimits().items))return false;
    nativeRoot_=root;captureToken_=token;captureRows_=rows;captureCopies_=0;captureError_.clear();captureModel_.clear();captureAdapter_.reset();captureView_.reset();
    QTimer::singleShot(60000,this,[this,token]{if(captureToken_==token){captureError_="capture expired";finishNativeCapture(token);}});
    return true;
}
bool StandaloneStorage::preflightNativeCopy(const QAbstractItemModel &model){
    if(captureToken_.isEmpty())return true;
    try {
        if(!captureError_.isEmpty()||!gui(&model)||captureCopies_>=captureRows_)throw ModelError(ModelErrorCode::AccessDenied);
        if(!captureAdapter_){
            auto *list=qobject_cast<QAbstractListModel *>(const_cast<QAbstractItemModel *>(&model));
            if(!list||list->rowCount()!=captureRows_)throw ModelError(ModelErrorCode::Changed);
            ModelAccess access;access.readable=[] {return true;};
            access.readSnapshot=[this,list](transaction::Limits limits){return materializeNativeModel(list,nativeRoot_,limits);};
            captureAdapter_=std::make_shared<ModelClipboard>(list,std::move(access),storageLimits());
            // Only audited DataFile values are materialized from a bounded,
            // content-addressed frozen copy. Other converters remain forbidden.
            captureView_=captureAdapter_->capture(storageLimits());captureModel_=list;
        }
        if(captureModel_!=&model)throw ModelError(ModelErrorCode::Changed);
        return true;
    }catch(...){captureError_="source changed or contains unsupported/file-backed data";return false;}
}
QVariantMap StandaloneStorage::copyNativeItem(const QAbstractItemModel &model,const QVariantMap &data){
    if(captureToken_.isEmpty())return data;
    try {
        if(!preflightNativeCopy(model))return {};
        const auto row=captureCopies_;
        if(model.data(model.index(row,0),contentType::data).toMap()!=data)throw ModelError(ModelErrorCode::Changed);
        QVariantMap result;for(const auto &field:captureView_->snapshot.at(std::size_t(row)))
            result.insert(QString::fromLatin1(field.first.data(),qsizetype(field.first.size())),QByteArray(reinterpret_cast<const char *>(field.second.data()),qsizetype(field.second.size())));
        ++captureCopies_;return result;
    }catch(...){captureError_="source changed or contains unsupported/file-backed data";return {};}
}
QString StandaloneStorage::finishNativeCapture(const QString &token){
    if(token!=captureToken_||token.isEmpty())return "Refused: invalid source capture";
    bool confirmed=captureError_.isEmpty()&&captureCopies_==captureRows_;
    if(confirmed&&captureRows_>0)try{
        const auto now=captureAdapter_->capture(storageLimits());confirmed=now.epoch==captureView_->epoch&&now.snapshot==captureView_->snapshot;
    }catch(...){confirmed=false;}
    captureToken_.clear();captureError_.clear();captureModel_.clear();captureAdapter_.reset();captureView_.reset();
    return confirmed?QStringLiteral("Captured"):QStringLiteral("Refused: source changed or contains unsupported/file-backed data; original tab retained.");
}
void StandaloneStorage::configure(const Profile &profile) {
    const auto next = storageConfiguration(profile);
    if(!(configuration_==next)&&!captureToken_.isEmpty()){captureError_="profile changed";finishNativeCapture(captureToken_);}
    if (configuration_.binding != next.binding || configuration_.profile.standaloneStorage != profile.standaloneStorage) {
        checkpointTimer_.stop();dirtyModels_.clear();dirtySince_=-1;checkpointRetry_=0;checkpointFailures_=0;
        verifiedLocal_=false;
        phase_=StoragePhase::Unknown;
        keys_.reset();session_.reset();generations_.clear(); detaching_ = routing_ = converted_ = false;
    }
    configuration_ = next;
}
void StandaloneStorage::useKeys(StorageKeysPtr keys) {
    const bool wasLocked=!keys_;
    // A completed unloaded-tab action may have changed the record using a
    // freshly unlocked key set. Do not present an older cached phase as current.
    if(models_.isEmpty()&&keys!=keys_)phase_=StoragePhase::Unknown;
    keys_ = std::move(keys); detaching_ = keys_ && keys_->retiring;
    if(!detaching_)routing_=false;
    if(keys_&&models_.isEmpty())expiry_.start(60000);else expiry_.stop();
    if(keys_&&wasLocked){scheduleCheckpoint();emit unlocked();}
}
bool StandaloneStorage::unlock(const crypto::Bytes &password) {
    auto keys = unlockVault(configuration_, password);
    if (!keys->pending.empty()) {
        try { readStorage(configuration_, keys->pending,keys->sync); keys->local.swap(keys->pending); }
        catch(const state::Error &e) { if(e.code()!=state::ErrorCode::AuthenticationFailed)throw; readStorage(configuration_,keys->local,keys->sync); }
    }
    useKeys(std::move(keys)); return true;
}
bool StandaloneStorage::releaseKeys() { if(hasModels())return false;keys_.reset();return true; }
std::optional<std::uint64_t> StandaloneStorage::generation(const QAbstractItemModel *model) const {
    const auto it=generations_.constFind(model);return it==generations_.cend()?std::nullopt:std::optional<std::uint64_t>(*it);
}
void StandaloneStorage::confirmedGeneration(const QAbstractItemModel *model,std::uint64_t generation) {
    if(generations_.contains(model))generations_[model]=generation;
}
void StandaloneStorage::refreshedKeys(StorageKeysPtr keys) {
    if(!models_.isEmpty()){
        const auto r=readStorage(configuration_,keys->local,keys->sync);
        for(auto *model:models_)confirmedGeneration(model,r.generation);
    }
    useKeys(std::move(keys));
}
void StandaloneStorage::checkpointModels() {
    if(!keys_||keys_->suspended||!enabled_||importing_)throw ModelError(ModelErrorCode::AccessDenied);
    for(auto *model:models_) {
        auto *list=qobject_cast<QAbstractListModel *>(model);if(!list)throw ModelError(ModelErrorCode::Unavailable);
        ModelAccess access;access.readable=[] {return true;};ModelClipboard adapter(list,std::move(access),storageLimits());
        const auto previous=generation(model);if(!previous||!session_)throw ModelError(ModelErrorCode::Unavailable);
        const auto view=adapter.capture(storageLimits());const auto record=saveStorage(configuration_,view.snapshot,keys_->local,keys_->sync,session_.get(),previous);
        const auto after=adapter.capture(storageLimits());
        if(after.epoch!=view.epoch||after.snapshot!=view.snapshot||!record.local||*record.local!=view.snapshot)
            throw ModelError(ModelErrorCode::Changed);
        confirmedCheckpoint(model,record,*previous);
    }
}
bool StandaloneStorage::liveWritable() const {
    if(!keys_||keys_->retiring||keys_->initializing||keys_->suspended||!enabled_||models_.size()!=1||
       !qobject_cast<QApplication *>(QCoreApplication::instance()))return false;
    // Bind through the public Qt view->model() identity supplied by CopyQ's loader.
    // Never inspect private CopyQ class names/properties or guess a tab widget.
    bool found=false;const auto widgets=QApplication::allWidgets();if(widgets.size()>16384)return false;
    for(auto *widget:widgets){auto *view=qobject_cast<QAbstractItemView *>(widget);
        if(!view||!models_.contains(view->model()))continue;found=true;
        QList<QObject *> pending{view};int visited=0;
        while(!pending.isEmpty()){
            auto *object=pending.takeLast();if(++visited>8192)return false;
            if(auto *edit=qobject_cast<QTextEdit *>(object)){if(!edit->isReadOnly())return false;}
            if(auto *edit=qobject_cast<QPlainTextEdit *>(object)){if(!edit->isReadOnly())return false;}
            if(auto *edit=qobject_cast<QLineEdit *>(object)){if(!edit->isReadOnly())return false;}
            // This signal/slot contract is documented by ItemLoaderInterface's
            // createExternalEditor(), including editors whose UI is elsewhere.
            const auto *meta=object->metaObject();
            if(meta->indexOfSignal("fileModified(QByteArray,QString,QModelIndex)")>=0&&
               meta->indexOfSignal("closed(QObject*,QModelIndex)")>=0&&meta->indexOfSlot("start()")>=0)return false;
            for(auto *child:object->children())pending.append(child);
        }
    }
    return found;
}
void StandaloneStorage::refreshGenerations(){
    if(!keys_)return;const auto r=readStorage(configuration_,keys_->local,keys_->sync);
    observeRecord(r);
    for(auto *model:models_)confirmedGeneration(model,r.generation);
}
void StandaloneStorage::observeRecord(const transaction::Record &r){
    phase_=r.pending?StoragePhase::Import:r.resolution?StoragePhase::Resolution:r.publication?StoragePhase::Publication:
        r.head?StoragePhase::Joined:StoragePhase::Unjoined;
}
std::shared_ptr<GuiClipboard> StandaloneStorage::beginAsyncImport(QObject *context,std::shared_ptr<OperationControl> control){
    if(importing_||!enabled_||(hasModels()&&!keys_))throw ModelError(ModelErrorCode::AccessDenied);
    std::shared_ptr<GuiClipboard> result;
    if(hasModels()){
        if(!liveWritable())throw ModelError(ModelErrorCode::AccessDenied);
        auto *model=qobject_cast<QAbstractListModel *>(*models_.begin());
        const auto configuration=configuration_;const auto keys=keys_;
        ModelAccess access;access.protection=protection_;
        access.readable=access.writable=[this,model,configuration,keys,control]{
            control->check();return configuration_==configuration&&keys_==keys&&models_.contains(model)&&liveWritable();
        };
        result=std::make_shared<GuiClipboard>(context,control,model,std::move(access));
        importDestroyed_=connect(model,&QObject::destroyed,context,[control]{control->cancel();});
    }
    // Native saver/loader callbacks must fail fast while the worker owns the
    // record. Live edits remain in the GUI model and are checkpointed on return.
    importing_=true;checkpointTimer_.stop();return result;
}
void StandaloneStorage::finishAsyncImport(){
    if(!importing_)return;
    importing_=false;disconnect(importDestroyed_);importDestroyed_={};
    const auto resumeCheckpoint=qScopeGuard([this]{scheduleCheckpoint();});
    // Reload after an ambiguous commit; retain edits or partial model writes
    // together with the worker's still-authoritative recovery journal.
    refreshGenerations();if(hasModels())checkpointModels();
}
void StandaloneStorage::inspectNativeCache(QIODevice *file) {
    nativeReadback_=false;
    const auto *native=qobject_cast<QFileDevice *>(file);
    if(!native||cacheFile_.isEmpty()||native->fileName()!=cacheFile_)return;
    const auto header=file->peek(8);QDataStream stream(header);stream.setVersion(QDataStream::Qt_4_7);
    qint32 rows=-1,version=0;stream>>rows;
    if(rows==0&&file->size()==4)nativeReadback_=true;
    else if(rows>0&&rows<=int(storageLimits().items)){stream>>version;nativeReadback_=stream.status()==QDataStream::Ok&&version==-3;}
}
ItemSaverPtr StandaloneStorage::observeSaver(const ItemSaverPtr &saver,QAbstractItemModel *model) {
    if(!saver)return saver;
    const auto observed=std::make_shared<CaptureSaver>(saver,this);
    if(!detaching_||!handoffGuard_||!handoffGuard_())return observed;
    bool confirmed=routing_&&models_.contains(model);
    if(!confirmed&&nativeReadback_&&keys_) {
        auto *list=qobject_cast<QAbstractListModel *>(model);
        if(list)try{ModelAccess a;a.readable=[]{return true;};a.readSnapshot=[this,list](transaction::Limits limits){return materializeNativeModel(list,nativeRoot_,limits);};ModelClipboard adapter(list,std::move(a),storageLimits());
            const auto local=readStorage(configuration_,keys_->local,keys_->sync);
            confirmed=adapter.capture(storageLimits()).snapshot==*local.local;
        }catch(...){confirmed=false;}
    }
    nativeReadback_=false;
    if(confirmed){converted_=true;routing_=false;models_.remove(model);generations_.remove(model);if(models_.isEmpty()){keys_.reset();session_.reset();}}
    return observed;
}
bool StandaloneStorage::canSave(const QString &tab) const {
    // Claim the configured tab even with an invalid profile, so initialize/load
    // can refuse instead of allowing CopyQ's default plaintext saver to take it.
    return enabled_ && configuration_.profile.standaloneStorage && !routing_ && !converted_ &&
        !(detaching_ && nativeReadback_) && tab == QLatin1String("synced_tray");
}
bool StandaloneStorage::current(const StorageConfiguration &configuration) const {
    return enabled_ && !importing_ && keys_ && !keys_->suspended && configuration_.profile.standaloneStorage && configuration_.binding == configuration.binding;
}
bool StandaloneStorage::recognizes(QIODevice *file) { return file && file->peek(Magic.size()) == Magic; }
ItemSaverPtr StandaloneStorage::restore(const QString &tab, QAbstractItemModel *model, int maximum, quint64 minimum) {
    // Loader callbacks supply the exact tab identity/model. No guessed QObject
    // properties, private browser API or patched-host endpoint is consulted.
    if (importing_ || !enabled_ || !configuration_.profile.standaloneStorage || tab != QLatin1String("synced_tray") || !gui(model) || model->rowCount() != 0 || maximum <= 0) return {};
    auto *list = qobject_cast<QAbstractListModel *>(model);
    if (!list) return {};
    try {
        if(!validateProfile(configuration_.profile,false).isEmpty())throw ModelError(ModelErrorCode::AccessDenied);
        if(!keys_&&(!unlocker_||!unlocker_()))return {};
        if(keys_->initializing||keys_->suspended)throw ModelError(ModelErrorCode::AccessDenied);
        if(!session_)session_=std::async(std::launch::async,[c=configuration_]{return acquireStorageSession(c);}).get();
        if(detaching_&&(!handoffGuard_||!handoffGuard_()))throw ModelError(ModelErrorCode::AccessDenied);
        const auto record = readStorage(configuration_,keys_->local,keys_->sync); // Never provisions after failed/missing reads.
        if (record.generation < minimum) throw ModelError(ModelErrorCode::Changed);
        if(detaching_&&(record.pending||record.publication||record.resolution))throw ModelError(ModelErrorCode::AccessDenied);
        const auto snapshot = *record.local;
        if (snapshot.size() > std::size_t(maximum)) throw ModelError(ModelErrorCode::Changed);
        QList<QVariantMap> maps;
        for (const auto &item : snapshot) {
            QVariantMap map;
            for (const auto &field : item)
                map.insert(QString::fromLatin1(field.first.data(), qsizetype(field.first.size())),
                    QByteArray(reinterpret_cast<const char *>(field.second.data()), qsizetype(field.second.size())));
            maps.append(std::move(map));
        }
        if (!maps.isEmpty() && !list->insertRows(0, int(maps.size()))) throw ModelError(ModelErrorCode::WriteFailed);
        for (int row = 0; row < maps.size(); ++row)
            if (!maps[row].isEmpty() && !list->setData(list->index(row, 0), maps[row], contentType::data)) throw ModelError(ModelErrorCode::WriteFailed);
        ModelAccess access; access.readable = [] { return true; };
        ModelClipboard adapter(list, std::move(access), storageLimits());
        if (adapter.capture(storageLimits()).snapshot != snapshot) throw ModelError(ModelErrorCode::Changed);
        observeRecord(record);verifiedLocal_=true;emit checkpointVerified();
        if(!models_.contains(list)) {
            models_.insert(list);generations_.insert(list,record.generation);expiry_.stop();
            const auto edited=[this,list]{modelChanged(list);};
            connect(list,&QAbstractItemModel::dataChanged,this,edited);
            connect(list,&QAbstractItemModel::rowsInserted,this,edited);
            connect(list,&QAbstractItemModel::rowsRemoved,this,edited);
            connect(list,&QAbstractItemModel::rowsMoved,this,edited);
            connect(list,&QAbstractItemModel::modelReset,this,edited);
            connect(list,&QAbstractItemModel::layoutChanged,this,edited);
            connect(list,&QObject::destroyed,this,[this,list]{
                dirtyModels_.remove(list);generations_.remove(list);
                if(dirtyModels_.isEmpty()){checkpointTimer_.stop();dirtySince_=-1;}
                if(models_.remove(list)&&models_.isEmpty()){keys_.reset();session_.reset();}
            });
        }
        return std::make_shared<Saver>(configuration_, list, this);
    } catch (...) {
        if(models_.isEmpty())session_.reset();
        emit error(QStringLiteral("Secure Sync cannot authenticate or restore local storage. No empty replacement was created; check the profile, key, private state and capacity."));
        return {};
    }
}
ItemSaverPtr StandaloneStorage::initialize(const QString &tab, QAbstractItemModel *model, int maximum) {
    return restore(tab, model, maximum, 0);
}
ItemSaverPtr StandaloneStorage::load(const QString &tab, QAbstractItemModel *model, QIODevice *file, int maximum) {
    if (!file || file->size() != MarkerBytes || file->read(8) != Magic) return {};
    const auto cached = file->read(64);
    auto legacy=configuration_.profile;legacy.schema=2;legacy.vaultDirectory.clear();
    if(cached!=identity(configuration_)&&cached!=identity(storageConfiguration(legacy))&&cached!=configuration_.profile.predecessorBinding.toLatin1())return {};
    QDataStream stream(file); stream.setVersion(QDataStream::Qt_4_7); quint64 generation = 0;
    stream >> generation;
    if(stream.status()!=QDataStream::Ok||!file->atEnd())return {};
    auto saver=restore(tab,model,maximum,generation);
    if(saver)if(auto *native=qobject_cast<QFileDevice *>(file))if(QDir::isAbsolutePath(native->fileName()))emit cacheFileObserved(native->fileName());
    if(saver&&detaching_)routing_=true;
    return saver;
}
} // namespace cqs::native
