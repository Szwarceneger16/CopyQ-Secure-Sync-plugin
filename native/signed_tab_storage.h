// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "device_trust_journal.h"
#include "item/itemwidget.h"
#include <QObject>
#include <functional>
#include <optional>

namespace cqs::native {

struct SignedTabConfiguration {
    QString checkpointDirectory;
    QString keyFile;
    trust::JoinActivation expected;
};

// The host's tab file is a routing marker. The signed Join checkpoint remains
// authoritative, and the host-owned saver holds its exclusive session.
class SignedTabStorage final : public QObject {
    Q_OBJECT
public:
    explicit SignedTabStorage(QObject *parent = nullptr);
    ~SignedTabStorage() override;

    void setConfiguration(std::optional<SignedTabConfiguration> configuration);
    void setGuard(std::function<bool()> guard);
    void setSnapshotValidator(std::function<void(const transaction::Snapshot &)> validator);
    bool canSave(const QString &tab) const;
    static bool recognizes(QIODevice *file);
    ItemSaverPtr initialize(const QString &tab, QAbstractItemModel *model, int maximum);
    ItemSaverPtr load(const QString &tab, QAbstractItemModel *model, QIODevice *file, int maximum);
    bool hasModel() const;
    bool checkpoint();

signals:
    void error(QString message);

private:
    class Saver;
    bool authorized(const SignedTabConfiguration &configuration) const;
    ItemSaverPtr restore(const QString &tab, QAbstractItemModel *model, int maximum, QIODevice *marker);

    std::optional<SignedTabConfiguration> configuration_;
    std::function<bool()> guard_;
    std::function<void(const transaction::Snapshot &)> validateSnapshot_;
    std::weak_ptr<Saver> active_;
    bool restoring_ = false;
};

} // namespace cqs::native
