// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "model_clipboard.h"
#include "tab_bridge.h"
#include <memory>

namespace cqs::native {
// Binds only a host-published endpoint on the precise model supplied by CopyQ.
// No top-level widget search, window-title matching, path guessing or unload.
class HostClipboard final : public transaction::Clipboard {
public:
    static std::unique_ptr<HostClipboard> bind(QAbstractItemModel *model, const QString &identity,
                                              transaction::Limits limits = {});
    transaction::Snapshot decode(const std::vector<std::string> &, transaction::Limits) override;
    transaction::View capture(transaction::Limits) override;
    transaction::View replace(const transaction::View &, const transaction::Snapshot &) override;
    transaction::Snapshot persist(const transaction::View &, transaction::Limits) override;
private:
    HostClipboard(QAbstractListModel *, QPointer<QObject>, QString, transaction::Limits);
    copyq::sync::TabBridge *peer() const;
    QPointer<QAbstractListModel> model_;
    QPointer<QObject> endpoint_;
    QString identity_;
    transaction::Limits limits_;
    ModelClipboard adapter_;
};
} // namespace cqs::native
