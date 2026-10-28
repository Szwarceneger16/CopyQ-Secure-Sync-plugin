// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_clipboard.h"
#include "packed_items.h"
#include <QCoreApplication>
#include <QThread>
#include <algorithm>

namespace cqs::native {
namespace {
copyq::sync::Limits hostLimits(transaction::Limits l) {
    packed::validateLimits(l);
    return {static_cast<int>(l.items), static_cast<int>(l.formatsPerItem), static_cast<int>(l.mimeNameBytes),
            static_cast<qint64>(l.snapshotBytes)};
}
copyq::sync::Items toHost(const transaction::Snapshot &snapshot, transaction::Limits limits) {
    packed::validateSnapshot(snapshot, limits);
    copyq::sync::Items result;
    for (const auto &item : snapshot) {
        QVariantMap map;
        for (const auto &field : item)
            map.insert(QString::fromLatin1(field.first.data(), qsizetype(field.first.size())),
                       QByteArray(reinterpret_cast<const char *>(field.second.data()), qsizetype(field.second.size())));
        result.append(map);
    }
    return result;
}
transaction::Snapshot fromHost(const copyq::sync::Items &items, transaction::Limits limits) {
    if (static_cast<std::size_t>(items.size()) > limits.items) throw packed::Error();
    transaction::Snapshot result;
    std::size_t total = 0;
    for (const auto &map : items) {
        if (static_cast<std::size_t>(map.size()) > limits.formatsPerItem) throw packed::Error();
        transaction::Item item;
        for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
            if (it.key().isEmpty() || static_cast<std::size_t>(it.key().size()) > limits.mimeNameBytes ||
                it.value().metaType().id() != QMetaType::QByteArray) throw packed::Error();
            for (const auto c : it.key()) if (c.unicode() < 0x21 || c.unicode() > 0x7e) throw packed::Error();
            const auto name = it.key().toLatin1();
            const auto bytes = it.value().toByteArray();
            const auto size = static_cast<std::size_t>(name.size() + bytes.size());
            if (size > limits.snapshotBytes - total) throw packed::Error();
            total += size;
            const auto *first = reinterpret_cast<const std::uint8_t *>(bytes.constData());
            item.emplace(std::string(name.constData(), std::size_t(name.size())), crypto::Bytes(first, first + bytes.size()));
        }
        result.push_back(std::move(item));
    }
    packed::validateSnapshot(result, limits);
    return result;
}
} // namespace
std::unique_ptr<HostClipboard> HostClipboard::bind(QAbstractItemModel *model, const QString &identity, transaction::Limits limits) {
    const auto *app = QCoreApplication::instance();
    if (!model || !app || model->thread() != QThread::currentThread() || app->thread() != QThread::currentThread()) return {};
    auto *list = qobject_cast<QAbstractListModel *>(model);
    const auto endpoint = model->property(copyq::sync::bridgeProperty).value<QPointer<QObject>>();
    if (!list || !endpoint || endpoint->thread() != model->thread()) return {};
    auto *bridge = qobject_cast<copyq::sync::TabBridge *>(endpoint);
    if (!bridge || bridge->boundModel() != list || bridge->tabId() != identity || bridge->maximumItems() <= 0) return {};
    packed::validateLimits(limits);
    limits.items = std::min(limits.items, std::size_t(bridge->maximumItems()));
    return std::unique_ptr<HostClipboard>(new HostClipboard(list, endpoint, identity, limits));
}
HostClipboard::HostClipboard(QAbstractListModel *model, QPointer<QObject> endpoint, QString id, transaction::Limits limits)
    : model_(model), endpoint_(endpoint), identity_(std::move(id)), limits_(limits), adapter_(model, {
        [this] { const auto *p = peer(); return p && p->readable(); },
        [this] { const auto *p = peer(); return p && p->writable(); },
        [this](const transaction::View &view, transaction::Limits requested) {
            auto *p = peer();
            if (!p) throw ModelError(ModelErrorCode::Unavailable);
            const auto result = p->persistAndReadback(toHost(view.snapshot, requested), hostLimits(requested));
            if (result.status != copyq::sync::Status::Confirmed) {
                if (result.status == copyq::sync::Status::Changed) throw ModelError(ModelErrorCode::Changed);
                if (result.status == copyq::sync::Status::AccessDenied) throw ModelError(ModelErrorCode::AccessDenied);
                throw ModelError(ModelErrorCode::WriteFailed);
            }
            if (peer() != p) throw ModelError(ModelErrorCode::Changed);
            return fromHost(result.items, requested);
        },
        [this](transaction::Limits requested) {
            auto *p = peer();
            if (!p) throw ModelError(ModelErrorCode::Unavailable);
            const auto result = p->captureSnapshot(hostLimits(requested));
            if (result.status != copyq::sync::Status::Confirmed || peer() != p)
                throw ModelError(ModelErrorCode::Changed);
            return fromHost(result.items, requested);
        }}, limits_) {}
copyq::sync::TabBridge *HostClipboard::peer() const {
    const auto *app = QCoreApplication::instance();
    if (!model_ || !endpoint_ || !app || QThread::currentThread() != model_->thread() ||
        model_->thread() != app->thread() || endpoint_->thread() != model_->thread() ||
        model_->property(copyq::sync::bridgeProperty).value<QPointer<QObject>>() != endpoint_) return nullptr;
    auto *p = qobject_cast<copyq::sync::TabBridge *>(endpoint_);
    return p && p->boundModel() == model_ && p->tabId() == identity_ &&
        p->maximumItems() >= static_cast<int>(limits_.items) ? p : nullptr;
}
transaction::Snapshot HostClipboard::decode(const std::vector<std::string> &items, transaction::Limits l) {
    l.items = std::min(l.items, limits_.items); return adapter_.decode(items, l);
}
transaction::View HostClipboard::capture(transaction::Limits l) {
    l.items = std::min(l.items, limits_.items); return adapter_.capture(l);
}
transaction::View HostClipboard::replace(const transaction::View &view, const transaction::Snapshot &desired) { return adapter_.replace(view, desired); }
transaction::Snapshot HostClipboard::persist(const transaction::View &view, transaction::Limits l) {
    l.items = std::min(l.items, limits_.items); return adapter_.persist(view, l);
}
} // namespace cqs::native
