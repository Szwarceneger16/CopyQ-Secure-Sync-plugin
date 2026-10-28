// SPDX-License-Identifier: GPL-3.0-or-later
#include "model_clipboard.h"
#include "packed_items.h"
#include "common/contenttype.h"
#include <QCoreApplication>
#include <QPersistentModelIndex>
#include <QThread>
#include <QVariantMap>
#include <atomic>
#include <limits>

namespace cqs::native {
namespace {
[[noreturn]] void fail(ModelErrorCode code) { throw ModelError(code); }
std::atomic<std::uint64_t> nextEpoch{1};
struct Operation {
    bool &active;
    explicit Operation(bool &a) : active(a) { if (a) fail(ModelErrorCode::Reentrant); a = true; }
    ~Operation() { active = false; }
};
std::string name(const QString &text, transaction::Limits limits) {
    if (text.isEmpty() || static_cast<std::size_t>(text.size()) > limits.mimeNameBytes) throw packed::Error();
    for (const auto c : text) if (c.unicode() < 0x21 || c.unicode() > 0x7e) throw packed::Error();
    const auto bytes = text.toLatin1();
    const auto result = std::string(bytes.constData(), static_cast<std::size_t>(bytes.size()));
    if (result.substr(0, 5) == "FILE:") throw packed::Error();
    return result;
}
} // namespace
ModelClipboard::ModelClipboard(QAbstractListModel *model, ModelAccess access, transaction::Limits limits)
    : model_(model), access_(std::move(access)), limits_(limits) {
    packed::validateLimits(limits_); requireModel(); changed();
    const auto begin = [this] { ++transitions_; changed(); };
    const auto end = [this] { if (transitions_) --transitions_; else exhausted_ = true; changed(); };
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
    connect(model, &QObject::destroyed, this, [this] { changed(); }, Qt::DirectConnection);
}
void ModelClipboard::changed() {
    // Process-wide epochs are not reused even when an adapter is reconstructed.
    // Signal callbacks never throw across Qt; exhaustion permanently poisons it.
    auto next = nextEpoch.load(std::memory_order_relaxed);
    for (;;) {
        if (next == std::numeric_limits<std::uint64_t>::max() || signals_ == std::numeric_limits<std::uint64_t>::max()) {
            exhausted_ = true; return;
        }
        if (nextEpoch.compare_exchange_weak(next, next + 1, std::memory_order_relaxed)) break;
    }
    epoch_ = next; ++signals_;
}
void ModelClipboard::requireModel() const {
    if (!model_) fail(ModelErrorCode::Unavailable);
    const auto *app = QCoreApplication::instance();
    if (!app || QThread::currentThread() != thread() || model_->thread() != thread() || app->thread() != thread())
        fail(ModelErrorCode::WrongThread);
    if (exhausted_ || transitions_) fail(ModelErrorCode::Changed);
}
void ModelClipboard::policy(bool write, bool durable) {
    requireModel();
    if (!access_.readable || (write && !access_.writable)) fail(ModelErrorCode::AccessDenied);
    if (durable && !access_.persistAndReadback) fail(ModelErrorCode::PersistenceUnavailable);
    const auto epoch = epoch_;
    if (!access_.readable()) fail(ModelErrorCode::AccessDenied);
    requireModel(); if (epoch != epoch_) fail(ModelErrorCode::Changed);
    if (write && !access_.writable()) fail(ModelErrorCode::AccessDenied);
    requireModel(); if (epoch != epoch_) fail(ModelErrorCode::Changed);
}
void ModelClipboard::limits(transaction::Limits requested) const {
    packed::validateLimits(requested);
    if (requested.items > limits_.items || requested.formatsPerItem > limits_.formatsPerItem ||
        requested.mimeNameBytes > limits_.mimeNameBytes || requested.snapshotBytes > limits_.snapshotBytes) throw packed::Error();
}
transaction::Snapshot ModelClipboard::decode(const std::vector<std::string> &items, transaction::Limits requested) {
    limits(requested); // Detached, thread-independent decode; no QObject/model access.
    return packed::decode(items, requested);
}
transaction::Snapshot ModelClipboard::read(transaction::Limits requested) {
    requireModel(); limits(requested);
    const auto epoch = epoch_;
    if (access_.readSnapshot) {
        auto result = access_.readSnapshot(requested);
        packed::validateSnapshot(result, requested);
        requireModel(); if (epoch_ != epoch) fail(ModelErrorCode::Changed);
        return result;
    }
    const auto rows = model_->rowCount(); requireModel();
    const auto columns = static_cast<QAbstractItemModel *>(model_.data())->columnCount(QModelIndex());
    requireModel();
    if (rows < 0 || static_cast<std::size_t>(rows) > requested.items || columns != 1) throw packed::Error();
    transaction::Snapshot result; result.reserve(static_cast<std::size_t>(rows));
    std::size_t total = 0;
    const auto account = [&](std::size_t size) {
        if (size > requested.snapshotBytes - total) throw packed::Error();
        total += size;
    };
    for (int row = 0; row < rows; ++row) {
        const auto index = model_->index(row, 0); requireModel();
        if (!index.isValid()) fail(ModelErrorCode::Changed);
        const auto data = model_->data(index, contentType::data); requireModel();
        if (data.metaType().id() != QMetaType::QVariantMap) throw packed::Error();
        const auto map = data.toMap();
        if (static_cast<std::size_t>(map.size()) > requested.formatsPerItem) throw packed::Error();
        transaction::Item item;
        for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
            auto mime = name(it.key(), requested); account(mime.size());
            // Never invoke a QVariant converter: CopyQ DataFile conversion can
            // read a local file. Strings/custom values must not be flattened.
            if (it.value().metaType().id() != QMetaType::QByteArray) throw packed::Error();
            const auto bytes = it.value().toByteArray(); account(static_cast<std::size_t>(bytes.size()));
            const auto *first = reinterpret_cast<const std::uint8_t *>(bytes.constData());
            item.emplace(std::move(mime), crypto::Bytes(first, first + bytes.size()));
        }
        result.push_back(std::move(item));
    }
    requireModel(); if (epoch_ != epoch) fail(ModelErrorCode::Changed);
    return result;
}
void ModelClipboard::match(const transaction::View &expected, transaction::Limits requested) {
    if (epoch_ != expected.epoch || read(requested) != expected.snapshot || epoch_ != expected.epoch)
        fail(ModelErrorCode::Changed);
}
transaction::View ModelClipboard::capture(transaction::Limits requested) {
    requireModel(); Operation operation(active_); policy(false, false);
    auto snapshot = read(requested); policy(false, false);
    return {std::move(snapshot), epoch_};
}
void ModelClipboard::preflight(const transaction::View &expected,const transaction::Snapshot &desired) {
    requireModel();Operation operation(active_);policy(true,true);
    packed::validateSnapshot(desired,limits_);match(expected,limits_);
    access_.protection.validate(expected.snapshot,desired);
    policy(true,true);match(expected,limits_);
}
transaction::View ModelClipboard::replace(const transaction::View &expected, const transaction::Snapshot &desired) {
    requireModel(); Operation operation(active_); policy(true, true);
    packed::validateSnapshot(desired, limits_); match(expected, limits_);
    const auto anchors=access_.protection.anchors(expected.snapshot,desired);
    if(expected.snapshot==desired)return expected;
    std::vector<QVariantMap> maps; maps.reserve(desired.size());
    for (const auto &item : desired) {
        QVariantMap map;
        for (const auto &field : item) map.insert(QString::fromLatin1(field.first.data(), static_cast<qsizetype>(field.first.size())),
            QByteArray(reinterpret_cast<const char *>(field.second.data()), static_cast<qsizetype>(field.second.size())));
        maps.push_back(std::move(map));
    }
    struct Gap {std::size_t oldAt,oldCount,newAt,newCount;};std::vector<Gap> gaps;
    std::vector<QPersistentModelIndex> protectedIndexes;
    std::size_t oldAt=0,newAt=0;
    auto gap=[&](std::size_t oldEnd,std::size_t newEnd){
        auto startOld=oldAt,startNew=newAt;
        while(startOld<oldEnd&&startNew<newEnd&&expected.snapshot[startOld]==desired[startNew]){++startOld;++startNew;}
        while(startOld<oldEnd&&startNew<newEnd&&expected.snapshot[oldEnd-1]==desired[newEnd-1]){--oldEnd;--newEnd;}
        if(startOld!=oldEnd||startNew!=newEnd)gaps.push_back({startOld,oldEnd-startOld,startNew,newEnd-startNew});
    };
    for(const auto &anchor:anchors){gap(anchor.first,anchor.second);protectedIndexes.emplace_back(model_->index(int(anchor.first),0));oldAt=anchor.first+1;newAt=anchor.second+1;}
    gap(expected.snapshot.size(),desired.size());
    policy(true,true);match(expected,limits_);
    auto count=expected.snapshot.size();
    const auto prefix=access_.protection.pinnedPrefix(expected.snapshot);
    std::vector<std::pair<QPersistentModelIndex,std::size_t>> deferredPins;
    // Work backwards: earlier row offsets remain stable. Protected anchors are
    // never removed/reinserted, so stock Pinned/Tags wrappers retain identity.
    for(auto it=gaps.rbegin();it!=gaps.rend();++it){
        policy(true,true);const auto at=int(it->oldAt);
        if(it->oldAt<prefix){
            // CopyQ allows pins at arbitrary fixed row positions. Changing
            // unprotected data above a pin must not remove/reinsert rows.
            if(it->oldCount!=it->newCount||it->oldAt+it->oldCount>prefix)fail(ModelErrorCode::ProtectedItems);
            for(std::size_t i=0;i<it->newCount;++i){
                policy(true,true);const QPersistentModelIndex index(model_->index(at+int(i),0));auto map=maps[it->newAt+i];
                if(access_.protection.pinned&&map.contains("application/x-copyq-item-pinned")){map.remove("application/x-copyq-item-pinned");deferredPins.emplace_back(index,it->newAt+i);}
                const auto serial=signals_;const auto data=model_->data(index,contentType::data);requireModel();
                if(signals_!=serial||data.metaType().id()!=QMetaType::QVariantMap)fail(ModelErrorCode::Changed);
                if(data.toMap()!=map){
                    if(!model_->setData(index,map,contentType::data))fail(ModelErrorCode::WriteFailed);
                    requireModel();if(signals_-serial!=1)fail(ModelErrorCode::Changed);
                }
            }
            continue;
        }
        if(it->oldCount){
            const auto serial=signals_;
            if(!model_->removeRows(at,int(it->oldCount)))fail(ModelErrorCode::WriteFailed);
            count-=it->oldCount;requireModel();
            if(signals_-serial!=2||model_->rowCount()!=int(count))fail(ModelErrorCode::Changed);
            for(const auto &index:protectedIndexes)if(!index.isValid())fail(ModelErrorCode::Changed);
        }
        if(it->newCount){
            policy(true,true);const auto serial=signals_;
            if(!model_->insertRows(at,int(it->newCount)))fail(ModelErrorCode::WriteFailed);
            count+=it->newCount;requireModel();
            if(signals_-serial!=2||model_->rowCount()!=int(count))fail(ModelErrorCode::Changed);
            std::vector<QPersistentModelIndex> indexes;indexes.reserve(it->newCount);
            for(std::size_t i=0;i<it->newCount;++i)indexes.emplace_back(model_->index(at+int(i),0));
            for(std::size_t i=0;i<it->newCount;++i){
                policy(true,true);const auto &index=indexes[i];
                if(!index.isValid()||index.row()!=at+int(i)||model_->rowCount()!=int(count))fail(ModelErrorCode::Changed);
                const auto epoch=epoch_;const auto data=model_->data(index,contentType::data);requireModel();
                if(epoch_!=epoch||data.metaType().id()!=QMetaType::QVariantMap||!data.toMap().isEmpty())fail(ModelErrorCode::Changed);
                auto map=maps[it->newAt+i];
                if(access_.protection.pinned&&map.contains("application/x-copyq-item-pinned")){map.remove("application/x-copyq-item-pinned");deferredPins.emplace_back(index,it->newAt+i);}
                if(map.isEmpty())continue;
                const auto serial=signals_;if(!model_->setData(index,map,contentType::data))fail(ModelErrorCode::WriteFailed);
                requireModel();if(signals_-serial!=1)fail(ModelErrorCode::Changed);
            }
        }
    }
    // Attach new pin metadata only after all structural changes, otherwise
    // stock Pinned would move a newly pinned row during an earlier gap edit.
    for(const auto &pin:deferredPins){
        policy(true,true);if(!pin.first.isValid()||pin.first.row()!=int(pin.second))fail(ModelErrorCode::Changed);
        const auto serial=signals_;if(!model_->setData(pin.first,maps[pin.second],contentType::data))fail(ModelErrorCode::WriteFailed);
        requireModel();if(signals_-serial!=1)fail(ModelErrorCode::Changed);
    }
    for(std::size_t i=0;i<anchors.size();++i)if(!protectedIndexes[i].isValid()||protectedIndexes[i].row()!=int(anchors[i].second))fail(ModelErrorCode::Changed);
    policy(true, true); auto actual = read(limits_);
    if (actual != desired) fail(ModelErrorCode::Changed);
    return {std::move(actual), epoch_};
}
transaction::Snapshot ModelClipboard::persist(const transaction::View &expected, transaction::Limits requested) {
    requireModel(); Operation operation(active_); limits(requested); policy(true, true); match(expected, requested);
    auto durable = access_.persistAndReadback(expected, requested);
    packed::validateSnapshot(durable, requested);
    policy(true, true); match(expected, requested);
    if (durable != expected.snapshot) fail(ModelErrorCode::Changed);
    return durable;
}
} // namespace cqs::native
