// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "profile.h"
#include "crypto.h"
#include <QObject>
#include <QPointer>
#include <QThread>

namespace cqs::native {
class Inspector final : public QObject {
    Q_OBJECT
public:
    explicit Inspector(QObject *parent = nullptr) : QObject(parent) {}
    ~Inspector() override;
    bool busy() const { return !thread_.isNull(); }
    bool request(const Profile &profile, crypto::Bytes unlockedSyncKey = {});
signals:
    void finished(QString status);
private:
    QPointer<QThread> thread_;
};
} // namespace cqs::native
