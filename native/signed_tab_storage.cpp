// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_tab_storage.h"

#include "common/contenttype.h"
#include "key_reader.h"
#include "model_clipboard.h"
#include "packed_items.h"
#include "signed_join_checkpoint.h"
#include "signed_tab_marker.h"
#include <QCoreApplication>
#include <QDir>
#include <QIODevice>
#include <QScopeGuard>
#include <QScopedValueRollback>
#include <QThread>
#include <QtEndian>
#include <algorithm>
#include <future>
#include <tuple>

namespace cqs::native {
namespace {

const QByteArray MarkerMagic = SignedTabPreamble + QByteArrayLiteral("CQSSGN01");
constexpr qsizetype IdentitySize = 32;
constexpr qsizetype MarkerSize = 16 + IdentitySize + sizeof(quint64);

bool signedTab(const QString &tab) { return tab == QLatin1String(SignedTabName); }

bool guiThread(const QObject *object) {
    const auto *app = QCoreApplication::instance();
    return object && app && object->thread() == app->thread() && QThread::currentThread() == app->thread();
}

auto proofFields(const trust::JoinActivation &proof) {
    return std::tie(proof.profileBinding, proof.group, proof.root, proof.head, proof.member,
                    proof.tipDigest, proof.generation, proof.tipId);
}

bool sameConfiguration(const SignedTabConfiguration &a, const SignedTabConfiguration &b) {
    return a.checkpointDirectory == b.checkpointDirectory && a.keyFile == b.keyFile &&
           a.setupRoot == b.setupRoot && a.predecessorMarker == b.predecessorMarker &&
           a.predecessorMaximumGeneration == b.predecessorMaximumGeneration &&
           proofFields(a.expected) == proofFields(b.expected);
}

[[noreturn]] void refuse(ModelErrorCode code) { throw ModelError(code); }

std::filesystem::path localPath(const QString &value) {
    if (value.isEmpty() || value.size() > 4096 || !QDir::isAbsolutePath(value) ||
        value.startsWith(QLatin1String("//")) || value != QDir::cleanPath(value) ||
        std::any_of(value.begin(), value.end(), [](QChar c) { return c.unicode() < 32 || c.unicode() == 127; }))
        refuse(ModelErrorCode::AccessDenied);
#ifdef Q_OS_WIN
    return std::filesystem::path(value.toStdWString());
#else
    return std::filesystem::u8path(value.toUtf8().toStdString());
#endif
}

QByteArray integer(quint64 value) {
    const auto encoded = qToBigEndian(value);
    return QByteArray(reinterpret_cast<const char *>(&encoded), sizeof(encoded));
}


struct LocalKey {
    crypto::Bytes bytes;
    ~LocalKey() { crypto::wipe(bytes); }
};

struct ClipboardView {
    transaction::View value;
    ~ClipboardView() {
        for (auto &item : value.snapshot)
            for (auto &field : item)
                crypto::wipe(field.second);
    }
};

ModelAccess readAccess() {
    ModelAccess access;
    access.readable = [] { return true; };
    return access;
}

void discardRows(const QPointer<QAbstractListModel> &model) {
    if (!model) return;
    const auto count = model->rowCount();
    if (!model || count <= 0 || model->removeRows(0, count)) return;
    // A conforming CopyQ model removes the rows. Also try to scrub them if an
    // adapter rejects the bulk removal after a partial write.
    for (int row = 0; model && row < count; ++row) {
        const auto index = model->index(row, 0);
        if (model && index.isValid()) model->setData(index, QVariantMap{}, contentType::data);
    }
}

} // namespace

class SignedTabStorage::Saver final : public ItemSaverInterface, public std::enable_shared_from_this<Saver> {
public:
    Saver(SignedTabStorage *owner, QAbstractListModel *model, SignedTabConfiguration configuration,
          QByteArray identity, std::unique_ptr<trust::SignedJoinCheckpoint::Mounted> mounted)
        : owner_(owner), model_(model), configuration_(std::move(configuration)), identity_(std::move(identity)),
          mounted_(std::move(mounted)), adapter_(model, readAccess()) {}

    ~Saver() override {
        if (initializing_ && guiThread(model_)) discardRows(model_);
    }

    bool hasModel() const { return model_ && mounted_; }
    void detach() { mounted_.reset(); }
    void awaitInitialMarker() { initializing_ = true; }

    bool saveItems(const QString &tab, const QAbstractItemModel &model, QIODevice *file) override {
        if (!signedTab(tab) || model_ != &model || !file || !file->isWritable() || file->pos() != 0 || file->size() != 0)
            return false;
        const auto generation = persist();
        if (!generation) return false;
        const QByteArray marker = MarkerMagic + identity_ + integer(*generation);
        // CopyQ owns this device and its final commit. Its file never receives a snapshot.
        if (file->write(marker) != marker.size()) return false;
        if (initializing_ && owner_) {
            // CopyQ drops this saver synchronously if creating the host file
            // fails. Retention past that call confirms model ownership.
            QMetaObject::invokeMethod(owner_.data(), [weak = weak_from_this()] {
                if (const auto saver = weak.lock()) saver->initializing_ = false;
            }, Qt::QueuedConnection);
        }
        return true;
    }

    bool canDropItem(const QModelIndex &) override { return false; }
    bool canMoveItems(const QList<QModelIndex> &) override { return false; }

    bool canRemoveItems(const QList<QModelIndex> &, QString *error) override {
        if (allowed()) return true;
        if (error) *error = QStringLiteral("Signed Sync tab access is unavailable.");
        return false;
    }

    QVariantMap copyItem(const QAbstractItemModel &model, const QVariantMap &data) override {
        return model_ == &model && allowed() ? data : QVariantMap{};
    }

    void restoreRows(int maximum) {
        const auto mounted = mounted_;
        const auto &snapshot = mounted->snapshot();
        if (snapshot.size() > std::size_t(maximum)) refuse(ModelErrorCode::Changed);
        packed::validateSnapshot(snapshot, {});
        if (owner_ && owner_->validateSnapshot_) owner_->validateSnapshot_(snapshot);
        std::vector<QVariantMap> rows;
        rows.reserve(snapshot.size());
        for (const auto &item : snapshot) {
            QVariantMap row;
            for (const auto &field : item) {
                row.insert(QString::fromLatin1(field.first.data(), qsizetype(field.first.size())),
                           QByteArray(reinterpret_cast<const char *>(field.second.data()), qsizetype(field.second.size())));
            }
            rows.push_back(std::move(row));
        }
        if (!allowed() || model_->rowCount() != 0 || !model_) refuse(ModelErrorCode::AccessDenied);
        auto rollback = qScopeGuard([this] { discardRows(model_); });
        const auto count = int(rows.size());
        if (count && (!model_->insertRows(0, count) || !model_ || model_->rowCount() != count))
            refuse(ModelErrorCode::WriteFailed);
        for (int row = 0; row < count; ++row) {
            if (!model_ || model_->rowCount() != count || !model_) refuse(ModelErrorCode::Changed);
            const auto index = model_->index(row, 0);
            if (!model_ || !index.isValid() || (!rows[row].isEmpty() && !model_->setData(index, rows[row], contentType::data)))
                refuse(ModelErrorCode::WriteFailed);
        }
        if (!allowed()) refuse(ModelErrorCode::AccessDenied);
        const ClipboardView actual{adapter_.capture({})};
        if (actual.value.snapshot != snapshot) refuse(ModelErrorCode::Changed);
        rollback.dismiss();
    }

    std::optional<quint64> persist() {
        if (saving_ || !mountedAccess()) return {};
        const QScopedValueRollback<bool> saving(saving_, true);
        try {
            const auto mounted = mounted_;
            const ClipboardView before{adapter_.capture({})};
            if (!mountedAccess()) refuse(ModelErrorCode::AccessDenied);
            // Readiness can change while this model is live. Its existing
            // encrypted mount still needs to checkpoint edits through shutdown.
            std::async(std::launch::async, [&] {
                mounted->save(before.value.snapshot, mounted->generation());
            }).get();
            if (!mountedAccess()) refuse(ModelErrorCode::AccessDenied);
            const ClipboardView after{adapter_.capture({})};
            if (after.value.epoch != before.value.epoch || after.value.snapshot != before.value.snapshot)
                refuse(ModelErrorCode::Changed);
            return mounted->generation();
        } catch (...) {
            if (owner_) emit owner_->error(QStringLiteral("Signed Sync could not confirm encrypted tab storage."));
            return {};
        }
    }

private:
    bool mountedAccess() const { return guiThread(model_) && mounted_ && owner_; }

    bool allowed() const {
        return mountedAccess() && owner_->authorized(configuration_) && mountedAccess();
    }

    QPointer<SignedTabStorage> owner_;
    QPointer<QAbstractListModel> model_;
    SignedTabConfiguration configuration_;
    QByteArray identity_;
    std::shared_ptr<trust::SignedJoinCheckpoint::Mounted> mounted_;
    ModelClipboard adapter_;
    bool saving_ = false;
    bool initializing_ = false;
};

SignedTabStorage::SignedTabStorage(QObject *parent) : QObject(parent) {}

SignedTabStorage::~SignedTabStorage() {
    if (const auto saver = active_.lock()) saver->detach();
}

void SignedTabStorage::setConfiguration(std::optional<SignedTabConfiguration> configuration) {
    configuration_ = std::move(configuration);
}

void SignedTabStorage::setGuard(std::function<bool()> guard) { guard_ = std::move(guard); }
void SignedTabStorage::setSnapshotValidator(std::function<void(const transaction::Snapshot &)> validator) {
    validateSnapshot_ = std::move(validator);
}
void SignedTabStorage::setKeyProvider(std::function<crypto::Bytes(const SignedTabConfiguration &)> provider) {
    keyProvider_ = std::move(provider);
}

bool SignedTabStorage::authorized(const SignedTabConfiguration &configuration) const {
    if (!guiThread(this) || !configuration_ || !sameConfiguration(*configuration_, configuration) || !guard_)
        return false;
    try {
        const QPointer<const SignedTabStorage> owner(this);
        const auto guard = guard_;
        return guard() && owner && owner->configuration_ && sameConfiguration(*owner->configuration_, configuration);
    } catch (...) {
        return false;
    }
}

bool SignedTabStorage::canSave(const QString &tab) const {
    return signedTab(tab) && (configuration_ || hasModel());
}

bool SignedTabStorage::recognizes(QIODevice *file) { return recognizesSignedTabMarker(file); }

ItemSaverPtr SignedTabStorage::initialize(const QString &tab, QAbstractItemModel *model, int maximum) {
    return restore(tab, model, maximum, nullptr);
}

ItemSaverPtr SignedTabStorage::load(const QString &tab, QAbstractItemModel *model, QIODevice *file, int maximum) {
    return file ? restore(tab, model, maximum, file) : ItemSaverPtr{};
}

ItemSaverPtr SignedTabStorage::restore(const QString &tab, QAbstractItemModel *model, int maximum, QIODevice *marker) {
    if (!signedTab(tab) || !guiThread(model) || !guiThread(this) || maximum <= 0 || restoring_ || hasModel() || !configuration_)
        return {};
    const QPointer<QAbstractListModel> list(qobject_cast<QAbstractListModel *>(model));
    if (!list || list->rowCount() != 0) return {};

    const QPointer<SignedTabStorage> owner(this);
    restoring_ = true;
    const auto restoring = qScopeGuard([owner] { if (owner) owner->restoring_ = false; });
    try {
        const auto configuration = *configuration_;
        if (!authorized(configuration) || !owner || !list) refuse(ModelErrorCode::AccessDenied);
        const auto identity = signedTabMarkerIdentity(configuration.expected);
        quint64 minimum = 0;
        if (marker) {
            const auto bytes = marker->read(MarkerSize + 1);
            if (bytes.size() != MarkerSize || !marker->atEnd() || !bytes.startsWith(MarkerMagic))
                refuse(ModelErrorCode::Changed);
            minimum = qFromBigEndian<quint64>(bytes.constData() + MarkerMagic.size() + IdentitySize);
            if (!minimum) refuse(ModelErrorCode::Changed);
            const auto storedIdentity = bytes.mid(MarkerMagic.size(), IdentitySize);
            if (storedIdentity != identity) {
                if (configuration.predecessorMarker.size() != IdentitySize ||
                    storedIdentity != configuration.predecessorMarker ||
                    minimum > configuration.predecessorMaximumGeneration) refuse(ModelErrorCode::Changed);
                minimum = 0;
            }
        }

        const auto directory = localPath(configuration.checkpointDirectory);
        LocalKey provided{};
        if (!configuration.setupRoot.isEmpty()) {
            const auto provider = keyProvider_;
            if (!provider) refuse(ModelErrorCode::AccessDenied);
            provided.bytes = provider(configuration);
            if (!owner || provided.bytes.size() != 32 || !authorized(configuration) || !owner || !list)
                refuse(ModelErrorCode::AccessDenied);
        }
        auto mounted = std::async(std::launch::async, [&] {
            const LocalKey key{configuration.setupRoot.isEmpty()
                ? readKeyStrict(localPath(configuration.keyFile)) : std::move(provided.bytes)};
            trust::SignedJoinCheckpoint checkpoint(directory, key.bytes, configuration.expected.profileBinding);
            return checkpoint.mount(configuration.expected);
        }).get();
        if (!mounted || mounted->generation() < minimum || !list) refuse(ModelErrorCode::Changed);
        auto saver = std::make_shared<Saver>(this, list, configuration, identity, std::move(mounted));
        const std::weak_ptr<Saver> weakSaver = saver;
        connect(list, &QObject::destroyed, this, [weakSaver] {
            if (const auto live = weakSaver.lock()) live->detach();
        });
        saver->restoreRows(maximum);
        if (!owner) refuse(ModelErrorCode::AccessDenied);
        if (!marker) saver->awaitInitialMarker();
        active_ = saver;
        return saver;
    } catch (...) {
        if (owner) emit owner->error(QStringLiteral("Signed Sync could not authenticate and restore the encrypted tab."));
        return {};
    }
}

bool SignedTabStorage::hasModel() const {
    const auto saver = active_.lock();
    return saver && saver->hasModel();
}

bool SignedTabStorage::checkpoint() {
    const auto saver = active_.lock();
    return !saver || !saver->hasModel() || saver->persist().has_value();
}

} // namespace cqs::native
