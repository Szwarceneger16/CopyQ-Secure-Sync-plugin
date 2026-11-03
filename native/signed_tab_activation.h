// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "signed_tab_marker.h"
#include "signed_tab_storage.h"

namespace cqs::native {
inline constexpr auto SignedTabSetting = "active_signed_tab";

std::string signedTabBinding(const QString &settingsFile, const QString &directory, const std::string &journalBinding);
QByteArray encodeSignedTab(const SignedTabConfiguration &configuration, const std::string &journalBinding);
std::optional<SignedTabConfiguration> decodeSignedTab(const QString &settingsFile, const QByteArray &encoded);
bool signedTabHostReady(const QString &settingsFile);
bool signedTabDestinationFree(const QString &settingsFile);
QString signedTabCachePath();
} // namespace cqs::native
