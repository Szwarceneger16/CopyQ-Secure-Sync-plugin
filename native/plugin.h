// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "item/itemwidget.h"
#include "profile.h"
#include "inspector.h"
#include "settings_widget.h"
#include "standalone_storage.h"
#include "gui_dispatch.h"
#include "sync_schedule.h"
#include "transport_watch.h"
#include <QPointer>
#include <QVariant>
#include <QThread>
#include <QProcess>
#include <QElapsedTimer>
struct SecureSyncJob;

class SecureSyncPlugin final : public QObject, public ItemLoaderInterface {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID COPYQ_PLUGIN_ITEM_LOADER_ID FILE "cqs-plugin.json")
    Q_INTERFACES(ItemLoaderInterface)
public:
    SecureSyncPlugin();
    ~SecureSyncPlugin() override;
    QString id() const override { return QStringLiteral("securesync"); }
    QString name() const override { return QStringLiteral("Secure Sync"); }
    QString author() const override { return QStringLiteral("CopyQ Secure Sync contributors"); }
    QString description() const override;
    QVariant icon() const override;
    void loadSettings(const QSettings &) override;
    void applySettings(QSettings &) override;
    QWidget *createSettingsWidget(QWidget *parent) override;
    void setEnabled(bool enabled) override;
    bool supportsEncryption() const override { return true; } // Independent password vault survives CopyQ re-encryption.
    bool canSaveItems(const QString &tab) const override;
    bool canLoadItems(QIODevice *file) const override;
    ItemSaverPtr initializeTab(const QString &, QAbstractItemModel *, int) override;
    ItemSaverPtr loadItems(const QString &, QAbstractItemModel *, QIODevice *, int) override;
    ItemScriptable *scriptableObject() override;
    QVariant scriptCallback(const QVariantList &) override;
    QVector<Command> commands() const override;
    const QObject *signaler() const override { return this; }
    ItemSaverPtr transformSaver(const ItemSaverPtr &saver, QAbstractItemModel *model) override { return isEnabled() ? storage_.observeSaver(saver, model) : saver; }
signals:
    void error(QString message);
private:
    cqs::native::Profile profile_;
    cqs::native::Inspector inspector_;
    QPointer<cqs::native::SettingsWidget> panel_;
    QPointer<cqs::native::SettingsWidget> inspectionPanel_;
    cqs::native::Profile inspectionProfile_;
    cqs::native::StandaloneStorage storage_;
    QString settingsFile_;
    bool automaticEnabled_ = false, runtimeBusy_ = false, resolving_ = false;
    bool closing_ = false;
    QTimer supervisor_;
    QElapsedTimer heartbeat_;
    QElapsedTimer scheduleClock_;
    cqs::native::SyncSchedule schedule_;
    cqs::native::TransportWatch transportWatch_;
    qint64 clientRetryAt_=0,clientLaunchedAt_=0;
    unsigned clientFailures_=0;
    bool clientStopping_=false;
    QProcess *runtimeClient_ = nullptr;
    std::shared_ptr<SecureSyncJob> runtimeJob_;
    std::optional<cqs::events::AuthenticatedHistory> conflictHistory_;
    void saveAutomaticPreference(bool);
    QString transitionHistory(const QVariantList &);
    void superviseRuntime();
    void recordRuntimeResult(const QString &);
    void stopRuntimeClient();
    void launchRuntimeWorker(std::function<void()>,std::function<void()>);
    void finishRuntime(const std::shared_ptr<SecureSyncJob> &,const QString &);
    void deliverRuntime(const std::shared_ptr<SecureSyncJob> &);
    bool runtimeCurrent(const std::shared_ptr<SecureSyncJob> &) const;
    void importRuntime(const std::shared_ptr<SecureSyncJob> &,bool recovery=false,
        cqs::transaction::Recovery=cqs::transaction::Recovery::RetryImport,bool projection=false);
    QString beginRuntime(const QString &);
    QString resolveConflict(const QVariantList &);
    QString restoreArchive(const QVariantList &);
    QString discardArchive(const QVariantList &);
    QVariant scriptCallbackImpl(const QVariantList &);
    cqs::native::UiContext uiContext() const;
    cqs::native::UiStatus uiStatus() const;
    void refreshPanel();
    void runPanelAction(const QString &);
    QString uiResult_;
    bool localSaveProblem_=false;
    QPointer<QProcess> panelClient_;

    cqs::native::StorageKeysPtr automaticKeys_;
    QThread *syncThread_ = nullptr;
    QString automaticToken_, automaticStatus_ = QStringLiteral("Stopped");
    QString manualToken_,manualStatus_;
    quint64 settingsEpoch_ = 0, handoffEpoch_ = 0, controlEpoch_ = 0;
};
