// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "import_transaction.h"
#include <QAbstractListModel>
#include <QByteArray>
#include <QString>
#include <functional>
namespace cqs::native {
QByteArray readNativeBlob(const QString &,std::size_t);
QByteArray withFrozenCiphertext(const QByteArray &,const std::function<QByteArray(const QString &)> &);
transaction::Snapshot materializeNativeModel(QAbstractListModel *,const QString &,transaction::Limits);
}
