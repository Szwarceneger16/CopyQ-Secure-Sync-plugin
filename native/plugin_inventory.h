// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QSet>
#include <QString>

namespace cqs::native {
// Audited against the pinned CopyQ 17 sources. These loaders neither own a
// tab's storage. Pinned/Tags wrappers are integrated via protected model anchors. Storage loaders and unknown
// third-party loaders remain blocked until their semantics are integrated.
inline QString incompatiblePlugin(const QString &stats) {
    const QSet<QString> compatible{"securesync", "itemtext", "itemimage", "itemnotes", "itemfakevim", "itempinned", "itemtags"};
    QSet<QString> seen;
    bool ours = false;
    for (const auto &line : stats.split('\n')) {
        if (!line.startsWith("PLUGIN ")) continue;
        const auto colon = line.indexOf(": ", 7);
        if (colon < 8) return QStringLiteral("invalid plugin inventory");
        const auto id = line.mid(7, colon - 7), state = line.mid(colon + 2);
        if (seen.contains(id) || (state != "enabled" && state != "disabled"))
            return QStringLiteral("invalid plugin inventory");
        seen.insert(id);
        if (state == "disabled") continue;
        if (!compatible.contains(id)) return id;
        if (id == "securesync") ours = true;
    }
    return ours ? QString() : QStringLiteral("missing active securesync");
}
inline QString pluginRefusal(const QString &stats) {
    const auto id = incompatiblePlugin(stats);
    return id.isEmpty() ? QString() : QStringLiteral("Refused: incompatible active plugin or inventory: ") + id;
}
} // namespace cqs::native
