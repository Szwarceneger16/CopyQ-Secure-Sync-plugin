// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "item/itemwidget.h"
#include "import_transaction.h"
#include "profile.h"
#include "key_vault.h"
#include "row_protection.h"
#include <QSet>
#include <QTimer>
#include <functional>
#include <QObject>
#include <QPointer>
#include <QHash>
#include <QElapsedTimer>

namespace cqs::native {
class ModelClipboard;
class GuiClipboard;
class OperationControl;
// Namespace identifies the device/tab and selected private/transport paths.
// Schema-2 records additionally authenticate the actual K-SYNC identity.
struct StorageConfiguration {
    Profile profile;
    QString binding;
    bool operator==(const StorageConfiguration &other) const { return profile == other.profile && binding == other.binding; }
};
StorageConfiguration storageConfiguration(const Profile &profile);
transaction::Limits storageLimits();
std::string syncKeyIdentity(const crypto::Bytes &syncKey);
std::unique_ptr<transaction::Store::Lease> acquireStorageSession(const StorageConfiguration &);
transaction::Record readStorage(const StorageConfiguration &, const crypto::Bytes &localKey, const crypto::Bytes &syncKey);
transaction::Record saveStorage(const StorageConfiguration &, const transaction::Snapshot &, const crypto::Bytes &localKey, const crypto::Bytes &syncKey,
    const transaction::Store::Lease *ownedSession = nullptr, std::optional<std::uint64_t> generation = {});
void initializeStorage(const StorageConfiguration &, const crypto::Bytes &localKey, const crypto::Bytes &syncKey,const transaction::Store::Lease *ownedSession = nullptr);
void migrateStorageState(const StorageConfiguration &, const crypto::Bytes &localKey, const crypto::Bytes &syncKey,const transaction::Store::Lease *ownedSession = nullptr);
transaction::Record checkpointRecord(const std::string &binding, const std::string &device,
    const transaction::Snapshot &snapshot, std::uint64_t generation, const std::vector<std::string> &parents = {});
void validateStorageRecord(const transaction::Record &, const StorageConfiguration &, const crypto::Bytes &syncKey = {});

enum class StoragePhase { Unknown, Unjoined, Joined, Import, Publication, Resolution };
class StandaloneStorage final : public QObject {
    Q_OBJECT
public:
    explicit StandaloneStorage(QObject *parent = nullptr);
    void configure(const Profile &profile);
    void setProtection(RowProtection p) { protection_=std::move(p); }
    const RowProtection &protection() const { return protection_; }
    bool canSave(const QString &tab) const;
    static bool recognizes(QIODevice *file);
    ItemSaverPtr initialize(const QString &tab, QAbstractItemModel *model, int maximum);
    ItemSaverPtr load(const QString &tab, QAbstractItemModel *model, QIODevice *file, int maximum);
    bool current(const StorageConfiguration &configuration) const;
    bool unlock(const crypto::Bytes &password);
    void useKeys(StorageKeysPtr keys);
    StorageKeysPtr keys() const { return keys_; }
    const transaction::Store::Lease *session() const { return session_.get(); }
    std::shared_ptr<transaction::Store::Lease> sharedSession() const { return session_; }
    void useSession(std::shared_ptr<transaction::Store::Lease> lease) { if(!session_)session_=std::move(lease); }
    void releaseIdleSession() { if(!hasModels())session_.reset(); }
    bool liveWritable() const;
    std::shared_ptr<GuiClipboard> beginAsyncImport(QObject *,std::shared_ptr<OperationControl>);
    void finishAsyncImport();
    void refreshGenerations();
    std::optional<std::uint64_t> generation(const QAbstractItemModel *model) const;
    void confirmedGeneration(const QAbstractItemModel *model,std::uint64_t generation);
    void confirmedCheckpoint(const QAbstractItemModel *,const transaction::Record &,std::uint64_t previous);
    void refreshedKeys(StorageKeysPtr keys);
    void setUnlocker(std::function<bool()> callback) { unlocker_ = std::move(callback); }
    void setHandoffGuard(std::function<bool()> callback) { handoffGuard_ = std::move(callback); }
    void setCacheFile(QString value) { cacheFile_ = std::move(value); }
    void inspectNativeCache(QIODevice *file);
    bool locked() const { return !keys_; }
    bool hasUnsavedChanges() const { return !dirtyModels_.isEmpty(); }
    bool verifiedLocal() const { return verifiedLocal_; }
    StoragePhase phase() const { return phase_; }
    bool releaseKeys();
    bool hasModels() const { return !models_.isEmpty(); }
    void checkpointModels();
    void beginDetach() { detaching_ = true; }
    bool converted() const { return converted_; }
    ItemSaverPtr observeSaver(const ItemSaverPtr &, QAbstractItemModel *);
    bool beginNativeCapture(const QString &token, int rows,const QString &root={});
    void setNativeRoot(QString root) { nativeRoot_=std::move(root); }
    bool capturingNative() const { return !captureToken_.isEmpty(); }
    QString finishNativeCapture(const QString &token);
    bool preflightNativeCopy(const QAbstractItemModel &);
    QVariantMap copyNativeItem(const QAbstractItemModel &, const QVariantMap &);
    void setEnabled(bool enabled) { enabled_ = enabled; if(!enabled&&!captureToken_.isEmpty()){captureError_="disabled";finishNativeCapture(captureToken_);} }
signals:
    void error(QString message);
    void cacheFileObserved(QString file);
    void modelEdited();
    void localCheckpointed();
    void unlocked();
    void checkpointVerified();
private:
    void modelChanged(QAbstractItemModel *);
    void scheduleCheckpoint();
    void scheduledCheckpoint();
    void observeRecord(const transaction::Record &);
    ItemSaverPtr restore(const QString &, QAbstractItemModel *, int, quint64 minimum);
    RowProtection protection_;
    StorageConfiguration configuration_;
    bool enabled_ = true;
    QTimer expiry_;
    QTimer checkpointTimer_;
    QElapsedTimer checkpointClock_;
    QSet<const QAbstractItemModel *> dirtyModels_;
    qint64 dirtySince_=-1,checkpointRetry_=0;
    unsigned checkpointFailures_=0;
    StorageKeysPtr keys_;
    QSet<QAbstractItemModel *> models_;
    QHash<const QAbstractItemModel *,std::uint64_t> generations_;
    std::shared_ptr<transaction::Store::Lease> session_;
    std::function<bool()> unlocker_;
    std::function<bool()> handoffGuard_;
    QString cacheFile_,nativeRoot_;
    bool nativeReadback_ = false;
    bool detaching_ = false, routing_ = false, converted_ = false;
    bool importing_ = false;
    bool verifiedLocal_ = false;
    StoragePhase phase_ = StoragePhase::Unknown;
    QMetaObject::Connection importDestroyed_;
    QString captureToken_, captureError_;
    int captureRows_ = 0, captureCopies_ = 0;
    QPointer<QAbstractItemModel> captureModel_;
    std::shared_ptr<ModelClipboard> captureAdapter_;
    std::optional<transaction::View> captureView_;
};
} // namespace cqs::native
