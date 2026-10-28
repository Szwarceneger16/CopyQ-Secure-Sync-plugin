// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QObject>
#include <QFileSystemWatcher>
#include <QTimer>

namespace cqs::native {
// Notifications are hints only. Every actual read/write still uses the
// authenticated, handle-pinned storage backend and its own budgets.
class TransportWatch final : public QObject {
    Q_OBJECT
public:
    explicit TransportWatch(QObject *parent=nullptr);
    void setFolder(const QString &);
    void refresh();
signals:
    void changed();
private:
    QString folder_;
    QFileSystemWatcher watcher_;
    QTimer refresh_;
};
} // namespace cqs::native
