// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "item/itemwidget.h"
#include "import_transaction.h"
#include <QObject>
#include <QString>
#include <QVariant>

namespace cqs::lab {
inline constexpr auto Tab = "cqs-standalone-lab";
inline constexpr auto Binding = "CqsStandaloneLabV1";
struct Configuration {
    QString directory, keyFile;
    bool enabled = false, create = false;
};
// Disposable laboratory checkpoints, not the production synchronization record.
transaction::Record read(const Configuration &configuration);
transaction::Record save(const Configuration &configuration, const transaction::Snapshot &snapshot);
transaction::Limits limits();

class Plugin final : public QObject, public ItemLoaderInterface {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID COPYQ_PLUGIN_ITEM_LOADER_ID)
    Q_INTERFACES(ItemLoaderInterface)
public:
    Plugin();
    QString id() const override { return QStringLiteral("securesynclab"); }
    QString name() const override { return QStringLiteral("Secure Sync standalone storage laboratory"); }
    QString author() const override { return QStringLiteral("CopyQ Secure Sync contributors"); }
    QString description() const override;
    QVariant icon() const override { return {}; }
    bool canSaveItems(const QString &tab) const override;
    bool canLoadItems(QIODevice *file) const override;
    ItemSaverPtr initializeTab(const QString &, QAbstractItemModel *, int) override;
    ItemSaverPtr loadItems(const QString &, QAbstractItemModel *, QIODevice *, int) override;
    ItemScriptable *scriptableObject() override;
    const QObject *signaler() const override { return this; }
    // Independent encrypted storage is NOT yet certified with global Encrypt Tabs.
    bool supportsEncryption() const override { return false; }
signals:
    void error(const QString &message);
private:
    ItemSaverPtr restore(const QString &, QAbstractItemModel *, int, quint64 minimumGeneration, bool initialize);
    Configuration configuration_;
};
} // namespace cqs::lab
