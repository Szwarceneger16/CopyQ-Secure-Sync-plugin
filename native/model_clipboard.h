// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "import_transaction.h"
#include "row_protection.h"
#include <QAbstractListModel>
#include <QObject>
#include <QPointer>
#include <functional>

namespace cqs::native {
enum class ModelErrorCode { Unavailable, WrongThread, AccessDenied, PersistenceUnavailable, Changed, Reentrant, WriteFailed, ProtectedItems };
class ModelError final : public std::runtime_error {
public:
    explicit ModelError(ModelErrorCode code) : std::runtime_error("CopyQ model operation refused or unconfirmed"), code_(code) {}
    ModelErrorCode code() const noexcept { return code_; }
private:
    ModelErrorCode code_;
};
struct ModelAccess {
    // Installed by an explicitly bound runtime. The legacy HostClipboard is test-only. Guards must
    // refuse unavailable/locked tabs and, for writes, open editors.
    std::function<bool()> readable;
    std::function<bool()> writable;
    // REQUIRED before the first replacement write. Persist via verified authoritative
    // encrypted storage and decode a detached readback from that storage.
    // capture(), unload(), a timer or a success boolean cannot implement it.
    std::function<transaction::Snapshot(const transaction::View &, transaction::Limits)> persistAndReadback;
    // Optional trusted host materialization for native CopyQ DataFile values.
    // Standalone adoption uses bounded native_blob materialization; normal
    // storage captures remain strict byte-only.
    std::function<transaction::Snapshot(transaction::Limits)> readSnapshot;
    RowProtection protection;
};
class ModelClipboard final : public QObject, public transaction::Clipboard {
public:
    ModelClipboard(QAbstractListModel *model, ModelAccess access, transaction::Limits limits = {});
    transaction::Snapshot decode(const std::vector<std::string> &packed, transaction::Limits limits) override;
    transaction::View capture(transaction::Limits limits) override;
    transaction::View replace(const transaction::View &expected, const transaction::Snapshot &desired) override;
    void preflight(const transaction::View &,const transaction::Snapshot &) override;
    transaction::Snapshot persist(const transaction::View &expected, transaction::Limits limits) override;
private:
    void changed();
    void requireModel() const;
    void policy(bool write, bool durable);
    void limits(transaction::Limits limits) const;
    transaction::Snapshot read(transaction::Limits limits);
    void match(const transaction::View &expected, transaction::Limits limits);
    QPointer<QAbstractListModel> model_;
    ModelAccess access_;
    transaction::Limits limits_;
    std::uint64_t epoch_ = 0, signals_ = 0;
    unsigned transitions_ = 0;
    bool active_ = false, exhausted_ = false;
};
} // namespace cqs::native
