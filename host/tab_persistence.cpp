// SPDX-License-Identifier: GPL-3.0-or-later
#include "tab_persistence.h"
#include "verified_save_file.h"
#include "common/contenttype.h"
#include "item/serialize.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QThread>
#include <limits>
#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace copyq::sync {
#ifdef CQS_HOST_TESTING
std::function<bool(Stage)> testHook;
#define CQS_STAGE(name) (!testHook || testHook(Stage::name))
#else
#define CQS_STAGE(name) true
#endif
namespace {
bool validLimits(Limits l) {
    return l.items > 0 && l.items <= 10000 && l.formats > 0 && l.formats <= 256 &&
        l.mimeBytes > 0 && l.mimeBytes <= 1024 && l.snapshotBytes > 0 && l.snapshotBytes <= 32 * 1024 * 1024;
}
bool namesValid(const QVariantMap &map, Limits l) {
    if (map.size() > l.formats) return false;
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        if (it.key().isEmpty() || it.key().size() > l.mimeBytes || it.key().startsWith("FILE:")) return false;
        for (const auto c : it.key()) if (c.unicode() < 0x21 || c.unicode() > 0x7e) return false;
    }
    return true;
}
bool account(const QVariantMap &map, Limits l, qint64 *total) {
    if (!namesValid(map, l)) return false;
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        if (it.value().metaType().id() != QMetaType::QByteArray) return false;
        const auto size = it.key().size() + it.value().toByteArray().size();
        if (size > l.snapshotBytes - *total) return false;
        *total += size;
    }
    return true;
}
bool capture(QAbstractListModel *model, Limits l, Items *items) {
    if (!model || model->rowCount() < 0 || model->rowCount() > l.items ||
        static_cast<QAbstractItemModel *>(model)->columnCount() != 1) return false;
    qint64 total = 0;
    for (int i = 0; i < model->rowCount(); ++i) {
        const auto value = model->data(model->index(i, 0), contentType::data);
        if (value.metaType().id() != QMetaType::QVariantMap) return false;
        auto map = value.toMap();
        if (!namesValid(map, l) || !materializeDataForReadback(&map, l.snapshotBytes - total)) return false;
        if (!account(map, l, &total)) return false;
        items->append(map);
    }
    return true;
}
// No views, editors, factory transforms, crop, dialogs or automatic saves.
class SourceModel final : public QAbstractListModel {
public:
    explicit SourceModel(Items snapshot) : items(std::move(snapshot)) {}
    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : int(items.size()); }
    QVariant data(const QModelIndex &index, int role) const override {
        return role == contentType::data && index.isValid() && index.row() < items.size()
            ? QVariant(items[index.row()]) : QVariant();
    }
    const Items items;
};
class DetachedModel final : public QAbstractListModel {
public:
    explicit DetachedModel(Limits l) : limits(l) {}
    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : int(items.size()); }
    QVariant data(const QModelIndex &index, int role) const override {
        return role == contentType::data && index.isValid() && index.row() < items.size()
            ? QVariant(items[index.row()]) : QVariant();
    }
    bool insertRows(int row, int count, const QModelIndex &parent = {}) override {
        if (parent.isValid() || row != 0 || !items.isEmpty() || count < 0 || count > limits.items) return false;
        for (int i = 0; i < count; ++i) items.append(QVariantMap{});
        return true;
    }
    bool removeRows(int, int, const QModelIndex & = {}) override { return false; }
    bool setData(const QModelIndex &index, const QVariant &value, int role) override {
        if (role != contentType::data || !index.isValid() || index.row() >= items.size() ||
            value.metaType().id() != QMetaType::QVariantMap) return false;
        auto map = value.toMap();
        if (!namesValid(map, limits) || !materializeDataForReadback(&map, limits.snapshotBytes - total, true) ||
            !account(map, limits, &total)) return false;
        items[index.row()] = std::move(map);
        return true;
    }
    Items items;
    Limits limits;
    qint64 total = 0;
};
class HashingWriter final : public QIODevice {
public:
    HashingWriter(QFileDevice *file, qint64 limit) : file(file), limit(limit), hash(QCryptographicHash::Sha256) { open(WriteOnly); }
    bool isSequential() const override { return true; }
    QByteArray digest() { return hash.result(); }
    qint64 readData(char *, qint64) override { return -1; }
    qint64 writeData(const char *bytes, qint64 size) override {
        if (size < 0 || size > limit - written || !CQS_STAGE(Write)) return -1;
        const auto result = file->write(bytes, size);
        if (result != size) return -1;
        hash.addData(QByteArrayView(bytes, size)); written += size;
        return result;
    }
    QFileDevice *file;
    qint64 limit, written = 0;
    QCryptographicHash hash;
};
bool syncDirectory(const QString &path) {
#ifdef Q_OS_WIN
    // Windows has no unprivileged POSIX directory-fsync equivalent. Confirm the
    // installed file via its actual handle, not a privileged volume flush.
    QFile installed(path);
    return installed.open(QIODevice::ReadWrite) && flushFileToDisk(installed);
#else
    const auto encoded = QFile::encodeName(QFileInfo(path).absolutePath());
    const int fd = ::open(encoded.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd == -1) return false;
    int result;
    do { result = ::fsync(fd); } while (result == -1 && errno == EINTR);
    ::close(fd);
    return result == 0;
#endif
}
} // namespace
bool NativeTabSaver::saveItems(const QString &, const QAbstractItemModel &model, QIODevice *file) {
    return shared_ && serializeData(model, file, threshold_, &shared_->encryptionKey);
}
bool NativeTabSaver::canReadback() const {
    return shared_ && shared_->tabsEncrypted && shared_->encryptionKey.isValid();
}
bool NativeTabSaver::readback(QIODevice *file, QAbstractItemModel *model) const {
    return canReadback() && deserializeData(model, file, &shared_->encryptionKey) && file->atEnd();
}
PersistentTab::PersistentTab(QString id, QAbstractListModel *model, int maximumItems, Access access, QObject *parent)
    : QObject(parent), identity_(std::move(id)), model_(model), access_(std::move(access)), maximumItems_(maximumItems) {
    if (!model || model->thread() != thread()) { invalid_ = true; return; }
    const auto begin = [this] { ++transitions_; changed(); };
    const auto end = [this] { if (transitions_) --transitions_; else invalid_ = true; changed(); };
    connect(model, &QAbstractItemModel::rowsAboutToBeInserted, this, begin, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::rowsInserted, this, end, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::rowsAboutToBeRemoved, this, begin, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::rowsRemoved, this, end, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::rowsAboutToBeMoved, this, begin, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::rowsMoved, this, end, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::modelAboutToBeReset, this, begin, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::modelReset, this, end, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::layoutAboutToBeChanged, this, begin, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::layoutChanged, this, end, Qt::DirectConnection);
    connect(model, &QAbstractItemModel::dataChanged, this, [this] { changed(); }, Qt::DirectConnection);
    connect(model, &QObject::destroyed, this, [this] { invalidate(); }, Qt::DirectConnection);
    model->setProperty(bridgeProperty, QVariant::fromValue(QPointer<QObject>(this)));
}
void PersistentTab::changed() {
    if (revision_ == std::numeric_limits<quint64>::max()) invalid_ = true;
    else ++revision_;
}
bool PersistentTab::available() const {
    const auto *app = QCoreApplication::instance();
    return !invalid_ && !transitions_ && model_ && app && !identity_.isEmpty() && maximumItems_ > 0 &&
        QThread::currentThread() == thread() && model_->thread() == thread() && app->thread() == thread() &&
        model_->property(bridgeProperty).value<QPointer<QObject>>() == this;
}
bool PersistentTab::readable() const {
    if (!available() || !access_.readable || !access_.saver) return false;
    const auto revision = revision_;
    const bool allowed = access_.readable();
    const auto saver = access_.saver();
    const auto *native = dynamic_cast<NativeTabSaver *>(saver.get());
    return allowed && native && native->canReadback() && available() && revision == revision_;
}
bool PersistentTab::writable() const {
    if (!readable() || !access_.writable || !access_.fileName) return false;
    const auto revision = revision_;
    const bool allowed = access_.writable();
    const auto file = QFileInfo(access_.fileName());
    return allowed && file.isFile() && !file.isSymLink() && available() && revision == revision_;
}
Readback PersistentTab::captureSnapshot(Limits limits) const {
    if (!validLimits(limits) || !readable()) return {Status::AccessDenied, {}};
    const auto revision = revision_;
    Items items;
    if (!capture(model_, limits, &items) || !readable() || revision != revision_) return {Status::Changed, {}};
    return {Status::Confirmed, std::move(items)};
}
Readback PersistentTab::persistAndReadback(const Items &expected, Limits limits) {
    if (active_ || !validLimits(limits) || expected.size() > maximumItems_ ||
        !writable() || !access_.fileName) return {Status::AccessDenied, {}};
    active_ = true;
    struct Release { bool &flag; ~Release() { flag = false; } } release{active_};
    bool attempted = false;
    try {
        const auto revision = revision_;
        const auto saver = access_.saver();
        const auto native = std::dynamic_pointer_cast<NativeTabSaver>(saver);
        const auto same = [&] {
            Items actual;
            return writable() && revision == revision_ && access_.saver() == saver &&
                capture(model_, limits, &actual) && actual == expected && revision == revision_;
        };
        if (!native || !same()) return {Status::Changed, {}};
        const auto path = access_.fileName();
        if (path.isEmpty() || !same()) return {Status::Changed, {}};
        // Missing authoritative storage is never initialized by a readback.
        if (!QFileInfo(path).isFile() || QFileInfo(path).isSymLink()) return {Status::SaveFailed, {}};
        VerifiedSaveFile file(path);
        if (!file.open()) return {Status::SaveFailed, {}};
        const qint64 maxFileBytes = limits.snapshotBytes * 2 + limits.items * 256 + 4;
        HashingWriter writer(&file.device(), maxFileBytes);
        // Normalize the already-checked effective MIME data before serialization.
        // A live lazy DataFile must not trigger the ordinary converter's readAll
        // between our bounded checks; the actual host saver receives bytes only.
        const SourceModel source(expected);
        if (!native->saveItems(identity_, source, &writer) || !CQS_STAGE(Flush) || !file.device().flush() ||
            !CQS_STAGE(Sync) || !flushFileToDisk(file.device())) {
            file.cancelWriting(); return {Status::SaveFailed, {}};
        }
        if (!CQS_STAGE(BeforeCommit) || !same()) {
            file.cancelWriting(); return {Status::Changed, {}};
        }
        const auto digest = writer.digest();
        attempted = true;
        if (!CQS_STAGE(CommitAttempt) || !file.commit() || !CQS_STAGE(AfterCommit) || !CQS_STAGE(DirectorySync) || !syncDirectory(path) ||
            !CQS_STAGE(Readback) || !same()) return {Status::CommitUnconfirmed, {}};
        QFile installed(path);
        if (!installed.open(QIODevice::ReadOnly) || installed.size() != writer.written || installed.size() > maxFileBytes)
            return {Status::CommitUnconfirmed, {}};
        QCryptographicHash actualHash(QCryptographicHash::Sha256);
        while (!installed.atEnd()) {
            const auto chunk = installed.read(64 * 1024);
            if (chunk.isEmpty()) return {Status::CommitUnconfirmed, {}};
            actualHash.addData(chunk);
        }
        // Only deserialize bytes generated by the checked saver in this call.
        // This also bounds Qt's legacy decoder against malicious length fields.
        if (actualHash.result() != digest || !installed.seek(0)) return {Status::CommitUnconfirmed, {}};
        DetachedModel detached(limits);
        if (!native->readback(&installed, &detached) || detached.items != expected || !same())
            return {Status::CommitUnconfirmed, {}};
        return {Status::Confirmed, std::move(detached.items)};
    } catch (...) {
        return {attempted ? Status::CommitUnconfirmed : Status::SaveFailed, {}};
    }
}
} // namespace copyq::sync
