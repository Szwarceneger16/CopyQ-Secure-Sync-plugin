// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tab_bridge.h"
#include "item/itemwidget.h"
#include "gui/clipboardbrowsershared.h"
#include <QPointer>
#include <functional>

namespace copyq::sync {
// The native default saver also supplies a quiet, detached readback path. Other
// storage plugins/wrappers are refused until they implement a reviewed barrier.
class NativeTabSaver final : public ItemSaverInterface {
public:
    NativeTabSaver(int threshold, ClipboardBrowserSharedPtr shared)
        : threshold_(threshold), shared_(std::move(shared)) {}
    bool saveItems(const QString &, const QAbstractItemModel &, QIODevice *) override;
    bool canReadback() const;
    bool readback(QIODevice *, QAbstractItemModel *) const;
private:
    int threshold_;
    ClipboardBrowserSharedPtr shared_;
};
struct Access {
    std::function<bool()> readable;
    std::function<bool()> writable;
    std::function<ItemSaverPtr()> saver;
    // Only the host's itemstore supplies its authoritative path.
    std::function<QString()> fileName;
};
class PersistentTab final : public QObject, public TabBridge {
    Q_OBJECT
    Q_INTERFACES(copyq::sync::TabBridge)
public:
    PersistentTab(QString identity, QAbstractListModel *model, int maximumItems, Access access, QObject *parent);
    QString tabId() const override { return identity_; }
    QAbstractListModel *boundModel() const override { return model_; }
    int maximumItems() const override { return maximumItems_; }
    bool readable() const override;
    bool writable() const override;
    Readback captureSnapshot(Limits limits) const override;
    Readback persistAndReadback(const Items &expected, Limits limits) override;
    void invalidate() { invalid_ = true; }
private:
    bool available() const;
    void changed();
    QString identity_;
    QPointer<QAbstractListModel> model_;
    Access access_;
    int maximumItems_;
    quint64 revision_ = 0;
    unsigned transitions_ = 0;
    bool invalid_ = false, active_ = false;
};
#ifdef CQS_HOST_TESTING
enum class Stage { Write, Flush, Sync, BeforeCommit, CommitAttempt, AfterCommit, Readback, DirectorySync };
extern std::function<bool(Stage)> testHook;
#endif
} // namespace copyq::sync
