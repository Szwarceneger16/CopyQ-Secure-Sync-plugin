// SPDX-License-Identifier: GPL-3.0-or-later
#include "common/contenttype.h"
#include "packed_items.h"
#include "signed_join_checkpoint.h"
#include "signed_tab_marker.h"
#include "signed_tab_storage.h"
#include "test_check.h"
#include <QAbstractListModel>
#include <QBuffer>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtEndian>

#ifdef Q_OS_WIN
#include "windows_test_acl.h"
#else
#include <sys/stat.h>
#endif

namespace {

using cqs::native::SignedTabStorage;
using cqs::trust::JoinActivation;
using cqs::trust::SignedJoinCheckpoint;
using cqs::trust::Token;

const QString Tab = QStringLiteral("signed_sync");
const QString Text = QStringLiteral("text/plain");
const std::string PackedItem = "/////gAAAAEAAAACADQAAAAAA2FiYw==";
const cqs::crypto::Bytes Key(32, 0x45); // Public fixture key.

class Model final : public QAbstractListModel {
public:
    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : int(rows_.size()); }
    QVariant data(const QModelIndex &index, int role) const override {
        return index.isValid() && role == contentType::data ? QVariant(rows_.at(index.row())) : QVariant{};
    }
    bool setData(const QModelIndex &index, const QVariant &value, int role) override {
        if (!index.isValid() || role != contentType::data || index.row() == failRow) return false;
        rows_[index.row()] = value.toMap();
        emit dataChanged(index, index);
        return true;
    }
    bool insertRows(int row, int count, const QModelIndex &parent = {}) override {
        if (count <= 0 || row < 0 || row > rowCount() || parent.isValid()) return false;
        beginInsertRows({}, row, row + count - 1);
        rows_.insert(row, count, QVariantMap{});
        endInsertRows();
        return true;
    }
    bool removeRows(int row, int count, const QModelIndex &parent = {}) override {
        if (count <= 0 || row < 0 || row + count > rowCount() || parent.isValid()) return false;
        beginRemoveRows({}, row, row + count - 1);
        rows_.remove(row, count);
        endRemoveRows();
        return true;
    }
    QByteArray text(int row) const { return rows_.at(row).value(Text).toByteArray(); }
    int failRow = -1;

private:
    QList<QVariantMap> rows_;
};

std::filesystem::path path(const QString &value) {
#ifdef Q_OS_WIN
    return std::filesystem::path(value.toStdWString());
#else
    return std::filesystem::u8path(value.toUtf8().toStdString());
#endif
}

void directory(const QString &name) {
#ifdef Q_OS_WIN
    cqs::testing::directory(path(name));
#else
    CHECK(QDir().mkdir(name));
    CHECK(::chmod(QFile::encodeName(name).constData(), 0700) == 0);
#endif
}

void writeKey(const QString &name) {
#ifdef Q_OS_WIN
    cqs::testing::write(path(name), std::string(Key.begin(), Key.end()));
#else
    QFile file(name);
    CHECK(file.open(QIODevice::WriteOnly));
    CHECK(file.write(QByteArray(int(Key.size()), char(Key.front()))) == qint64(Key.size()));
    file.close();
    CHECK(::chmod(QFile::encodeName(name).constData(), 0600) == 0);
#endif
}

Token token(std::uint8_t value) {
    Token result{};
    result.back() = value;
    return result;
}

QByteArray save(const ItemSaverPtr &saver, const Model &model) {
    QByteArray result;
    QBuffer device(&result);
    CHECK(device.open(QIODevice::WriteOnly));
    CHECK(saver->saveItems(Tab, model, &device));
    return result;
}

ItemSaverPtr load(SignedTabStorage &storage, Model &model, const QByteArray &marker, int maximum = 5,
                  const QString &tab = Tab) {
    QBuffer file;
    file.setData(marker);
    CHECK(file.open(QIODevice::ReadOnly));
    CHECK(SignedTabStorage::recognizes(&file));
    CHECK(file.pos() == 0);
    return storage.load(tab, &model, &file, maximum);
}

} // namespace

int main(int argc, char **argv) {
    const QCoreApplication app(argc, argv);
    const QTemporaryDir temporary;
    CHECK(temporary.isValid());
    const auto checkpointDir = temporary.path() + QStringLiteral("/checkpoint");
    const auto keyDir = temporary.path() + QStringLiteral("/key-directory");
    const auto keyFile = keyDir + QStringLiteral("/local.key");
    directory(checkpointDir);
    directory(keyDir);
    writeKey(keyFile);

    const JoinActivation proof{"signed-native-test", token(1), token(2), token(3), token(4), token(5), 0,
                               "daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000000000001"};
    const cqs::events::Event tip{{proof.tipId, proof.tipId.substr(0, 32), 1, {}}, {PackedItem, PackedItem}, 0};
    const auto original = cqs::packed::decode(tip.items);
    SignedJoinCheckpoint checkpoint(path(checkpointDir), Key, proof.profileBinding);
    checkpoint.apply(proof, tip, original);

    SignedTabStorage storage;
    CHECK(!storage.canSave(Tab));
    storage.setConfiguration(cqs::native::SignedTabConfiguration{checkpointDir, keyFile, proof});
    bool allowed = false;
    storage.setGuard([&] { return allowed; });
    CHECK(storage.canSave(Tab));
    CHECK(!storage.canSave(QStringLiteral("synced_tray")));

    Model model;
    CHECK(!storage.initialize(Tab, &model, 5));
    CHECK(model.rowCount() == 0);
    allowed = true;
    CHECK(!storage.initialize(Tab, &model, 1));
    CHECK(model.rowCount() == 0);
    model.failRow = 1;
    CHECK(!storage.initialize(Tab, &model, 5));
    CHECK(model.rowCount() == 0);
    model.failRow = -1;

    // CopyQ drops the new saver if opening or committing its marker fails.
    {
        auto abandoned = storage.initialize(Tab, &model, 5);
        CHECK(abandoned && model.rowCount() == 2);
    }
    CHECK(!storage.hasModel());
    CHECK(model.rowCount() == 0);

    auto saver = storage.initialize(Tab, &model, 5);
    CHECK(saver && storage.hasModel());
    CHECK(model.rowCount() == 2 && model.text(0) == "abc");
    CHECK(!saver->canDropItem(model.index(0, 0)) && !saver->canMoveItems({model.index(0, 0)}));
    Model other;
    CHECK(!storage.initialize(Tab, &other, 5));
    try {
        (void)checkpoint.mount(proof);
        CHECK(false);
    } catch (const cqs::state::Error &error) {
        CHECK(error.code() == cqs::state::ErrorCode::Busy);
    }

    const auto firstMarker = save(saver, model);
    CHECK(firstMarker.size() == 56);
    CHECK(firstMarker.startsWith(cqs::native::SignedTabPreamble + QByteArrayLiteral("CQSSGN01")));
    CHECK(!firstMarker.contains("abc") && qFromBigEndian<quint64>(firstMarker.constData() + 48) == 1);
    QCoreApplication::processEvents();

    const QByteArray edited("sensitive fixture edit\0binary", 29);
    CHECK(model.setData(model.index(0, 0), QVariantMap{{Text, edited}}, contentType::data));
    QBuffer blocked;
    CHECK(blocked.open(QIODevice::WriteOnly));
    CHECK(!saver->saveItems(QStringLiteral("renamed"), model, &blocked));
    allowed = false;
    CHECK(saver->copyItem(model, QVariantMap{{Text, edited}}).isEmpty());
    CHECK(!saver->canRemoveItems({model.index(0, 0)}, nullptr));
    CHECK(storage.checkpoint());
    const auto currentMarker = save(saver, model);
    CHECK(!currentMarker.contains(edited) && qFromBigEndian<quint64>(currentMarker.constData() + 48) == 2);
    saver.reset();
    CHECK(!storage.hasModel() && checkpoint.read(proof) == original);
    allowed = true;

    CHECK(!load(storage, other, currentMarker, 5, QStringLiteral("renamed")));
    CHECK(!load(storage, other, currentMarker.left(cqs::native::SignedTabPreamble.size())));
    CHECK(!load(storage, other, currentMarker + QByteArrayLiteral("extra")));
    auto wrongBinding = currentMarker;
    wrongBinding[16] = char(wrongBinding[16] ^ 1);
    CHECK(!load(storage, other, wrongBinding));
    auto future = currentMarker;
    qToBigEndian<quint64>(3, future.data() + 48);
    CHECK(!load(storage, other, future));
    CHECK(other.rowCount() == 0);

    // A crash between encrypted commit and marker publication retains the edit.
    auto recovered = std::make_unique<Model>();
    saver = load(storage, *recovered, firstMarker);
    CHECK(saver && recovered->rowCount() == 2 && recovered->text(0) == edited);
    recovered.reset();
    CHECK(!storage.hasModel());
    CHECK(checkpoint.mount(proof)->generation() == 2);

    const auto successorDir = temporary.path() + QStringLiteral("/successor");
    directory(successorDir);
    auto successorProof = proof;
    successorProof.profileBinding = "signed-native-successor";
    successorProof.tipDigest = token(6);
    successorProof.generation = 1;
    SignedJoinCheckpoint successor(path(successorDir), Key, successorProof.profileBinding);
    successor.apply(successorProof, tip, original);
    cqs::native::SignedTabConfiguration successorConfiguration{successorDir, {}, successorProof, temporary.path()};
    successorConfiguration.predecessorMarker = cqs::native::signedTabMarkerIdentity(proof);
    successorConfiguration.predecessorMaximumGeneration = 2;
    storage.setConfiguration(successorConfiguration);
    storage.setKeyProvider([](const auto &) { return cqs::crypto::Bytes{}; });
    Model guidedModel;
    CHECK(!load(storage, guidedModel, firstMarker) && guidedModel.rowCount() == 0);
    storage.setKeyProvider([&](const auto &) {
        storage.setConfiguration({});
        return Key;
    });
    CHECK(!load(storage, guidedModel, firstMarker) && guidedModel.rowCount() == 0 && !storage.hasModel());
    storage.setConfiguration(successorConfiguration);
    storage.setKeyProvider([&](const auto &) {
        allowed = false;
        return Key;
    });
    CHECK(!load(storage, guidedModel, firstMarker) && guidedModel.rowCount() == 0 && !storage.hasModel());
    allowed = true;
    storage.setKeyProvider([&](const auto &) {
        auto changed = successorConfiguration;
        ++changed.predecessorMaximumGeneration;
        storage.setConfiguration(changed);
        return Key;
    });
    CHECK(!load(storage, guidedModel, firstMarker) && guidedModel.rowCount() == 0 && !storage.hasModel());
    storage.setConfiguration(successorConfiguration);
    auto removedOwner = std::make_unique<SignedTabStorage>();
    removedOwner->setConfiguration(successorConfiguration);
    removedOwner->setGuard([] { return true; });
    removedOwner->setKeyProvider([&](const auto &) {
        removedOwner.reset();
        return Key;
    });
    Model orphanedModel;
    CHECK(!load(*removedOwner, orphanedModel, firstMarker) && !removedOwner && orphanedModel.rowCount() == 0);
    storage.setKeyProvider([](const auto &) { return Key; });
    saver = load(storage, guidedModel, firstMarker);
    CHECK(saver && guidedModel.text(0) == "abc");
    const auto successorMarker = save(saver, guidedModel);
    CHECK(successorMarker.mid(16, 32) == cqs::native::signedTabMarkerIdentity(successorProof));
    QCoreApplication::processEvents();
    saver.reset();
    Model refused;
    CHECK(!load(storage, refused, future) && refused.rowCount() == 0);
    storage.setConfiguration(cqs::native::SignedTabConfiguration{successorDir, {}, successorProof, temporary.path()});
    CHECK(!load(storage, refused, firstMarker) && refused.rowCount() == 0);
}
