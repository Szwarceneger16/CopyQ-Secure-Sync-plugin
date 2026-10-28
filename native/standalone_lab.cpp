// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_lab.h"
#include "model_clipboard.h"
#include "common/contenttype.h"
#include <QAbstractListModel>
#include <QCoreApplication>
#include <QDataStream>
#include <QIODevice>
#include <QPointer>
#include <QThread>

namespace cqs::lab {
namespace {
const QByteArray Magic("CQSLAB01", 8);
bool gui(const QAbstractItemModel *model) {
    const auto *app = QCoreApplication::instance();
    return model && app && model->thread() == app->thread() && QThread::currentThread() == app->thread();
}
class Saver final : public ItemSaverInterface {
public:
    Saver(Configuration configuration, QAbstractListModel *model, Plugin *owner)
        : configuration_(std::move(configuration)), model_(model), owner_(owner) {
        configuration_.create = false; // Provisioning is never retried by save.
    }
    bool saveItems(const QString &tab, const QAbstractItemModel &model, QIODevice *file) override {
        if (tab != QLatin1String(Tab) || model_ != &model || !gui(&model) || !owner_ || !owner_->isEnabled() || !file)
            return false;
        try {
            native::ModelAccess access; access.readable = [] { return true; };
            native::ModelClipboard adapter(model_, std::move(access), limits());
            const auto before = adapter.capture(limits());
            const auto durable = save(configuration_, before.snapshot);
            const auto after = adapter.capture(limits());
            if (after.epoch != before.epoch || after.snapshot != before.snapshot) return false;
            // This is a cache locator, not a second authoritative snapshot.
            // CopyQ owns this device's later flush/commit; we never commit it.
            QByteArray marker = Magic;
            QDataStream stream(&marker, QIODevice::Append);
            stream.setVersion(QDataStream::Qt_4_7); stream << quint64(durable.generation);
            return stream.status() == QDataStream::Ok && file->write(marker) == marker.size();
        } catch (...) {
            emit owner_->error(QStringLiteral("Standalone storage laboratory save refused or unconfirmed; private state was not reset."));
            return false;
        }
    }
private:
    Configuration configuration_;
    QPointer<QAbstractListModel> model_;
    QPointer<Plugin> owner_;
};
class Script final : public ItemScriptable {
    Q_OBJECT
    Q_PROPERTY(QString capability READ capability)
public:
    QString capability() const { return QStringLiteral("standalone-storage-lab/1"); }
};
} // namespace
Plugin::Plugin() {
    configuration_ = {qEnvironmentVariable("CQS_LAB_STATE_DIR"), qEnvironmentVariable("CQS_LAB_KEY_FILE"),
                      qEnvironmentVariable("CQS_STANDALONE_LAB") == QLatin1String("1"),
                      qEnvironmentVariable("CQS_LAB_CREATE") == QLatin1String("1")};
}
QString Plugin::description() const {
    return QStringLiteral("Opt-in standalone storage experiment for the disposable cqs-standalone-lab tab. No sync, host patch or plaintext disk snapshot. Not certified with Encrypt Tabs.");
}
bool Plugin::canSaveItems(const QString &tab) const {
    return isEnabled() && configuration_.enabled && !configuration_.directory.isEmpty() &&
        !configuration_.keyFile.isEmpty() && tab == QLatin1String(Tab);
}
bool Plugin::canLoadItems(QIODevice *file) const { return file && file->peek(Magic.size()) == Magic; }
ItemSaverPtr Plugin::restore(const QString &tab, QAbstractItemModel *model, int maximum, quint64 minimum, bool initialize) {
    if (!canSaveItems(tab) || !gui(model) || model->rowCount() != 0 || maximum <= 0) return {};
    auto *list = qobject_cast<QAbstractListModel *>(model);
    if (!list) return {};
    try {
        auto configuration = configuration_;
        if (!initialize) configuration.create = false;
        const auto record = read(configuration);
        if (record.generation < minimum) return {}; // A newer cache cannot bless rolled-back private state.
        const auto snapshot = record.head ? record.head->snapshot : transaction::Snapshot{};
        if (snapshot.size() > std::size_t(maximum)) return {}; // Never crop durable data on load.
        QList<QVariantMap> maps;
        for (const auto &item : snapshot) {
            QVariantMap map;
            for (const auto &field : item)
                map.insert(QString::fromLatin1(field.first.data(), qsizetype(field.first.size())),
                           QByteArray(reinterpret_cast<const char *>(field.second.data()), qsizetype(field.second.size())));
            maps.append(std::move(map));
        }
        if (!maps.isEmpty() && !list->insertRows(0, int(maps.size()))) return {};
        for (int row = 0; row < maps.size(); ++row)
            if (!maps[row].isEmpty() && !list->setData(list->index(row, 0), maps[row], contentType::data)) return {};
        return std::make_shared<Saver>(configuration_, list, this);
    } catch (...) {
        emit error(QStringLiteral("Standalone storage laboratory cannot authenticate or load private state; no empty replacement was created."));
        return {};
    }
}
ItemSaverPtr Plugin::initializeTab(const QString &tab, QAbstractItemModel *model, int maximum) {
    return restore(tab, model, maximum, 0, true);
}
ItemSaverPtr Plugin::loadItems(const QString &tab, QAbstractItemModel *model, QIODevice *file, int maximum) {
    if (!file || file->size() != 16 || file->read(8) != Magic) return {};
    QDataStream stream(file); stream.setVersion(QDataStream::Qt_4_7); quint64 generation = 0;
    stream >> generation;
    return stream.status() == QDataStream::Ok && file->atEnd() ? restore(tab, model, maximum, generation, false) : ItemSaverPtr{};
}
ItemScriptable *Plugin::scriptableObject() { return new Script; }
} // namespace cqs::lab
#include "standalone_lab.moc"
