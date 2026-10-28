// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "import_transaction.h"
#include <QSettings>
#include <QStringList>
#include <utility>

namespace cqs::native {
struct RowProtection {
    bool pinned=false, tags=false;
    // Raw public CopyQ itemtags settings, retaining order and regex rules.
    QStringList definitions;
    bool protects(const transaction::Item &) const;
    std::vector<std::pair<std::size_t,std::size_t>> anchors(const transaction::Snapshot &,const transaction::Snapshot &) const;
    void validate(const transaction::Snapshot &before,const transaction::Snapshot &after) const { anchors(before,after); }
    std::size_t pinnedPrefix(const transaction::Snapshot &) const;
};
RowProtection rowProtection(const QString &settingsFile,const QString &inventory);
}
