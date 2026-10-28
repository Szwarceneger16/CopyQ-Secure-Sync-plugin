// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QAbstractListModel>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QVariantMap>

// Optional host extension. This does not change CopyQ's item-loader vtable/IID.
namespace copyq::sync {
inline constexpr auto bridgeProperty = "_copyq_verified_tab_bridge_v1";
struct Limits {
    int items = 10000;
    int formats = 256;
    int mimeBytes = 1024;
    qint64 snapshotBytes = 32 * 1024 * 1024;
};
using Items = QList<QVariantMap>;
enum class Status { Confirmed, Unavailable, AccessDenied, Changed, SaveFailed, CommitUnconfirmed };
struct Readback { Status status = Status::Unavailable; Items items; };
class TabBridge {
public:
    virtual ~TabBridge() = default;
    virtual QString tabId() const = 0;
    virtual QAbstractListModel *boundModel() const = 0;
    virtual int maximumItems() const = 0;
    virtual bool readable() const = 0;
    virtual bool writable() const = 0;
    virtual Readback captureSnapshot(Limits limits) const = 0;
    virtual Readback persistAndReadback(const Items &expected, Limits limits) = 0;
};
} // namespace copyq::sync
Q_DECLARE_INTERFACE(copyq::sync::TabBridge, "com.github.hluk.copyq.verified-tab/1.0")
