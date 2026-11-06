// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "signed_tab_marker.h"
#include "signed_tab_storage.h"

namespace cqs::native {
inline constexpr auto SignedTabSetting = "active_signed_tab";
inline constexpr auto SignedReplicaSourceSetting = "signed_replica_source";
struct SignedReplicaSource {
    QString transport;
    QString journal;
    QString setupRoot = {};
};

std::string signedTabBinding(const QString &settingsFile, const QString &directory, const std::string &journalBinding);
QByteArray signedReplicaSourcePin(const std::string &profileBinding, const SignedReplicaSource &source);
bool confirmSignedReplicaSource(const QString &settingsFile, const QByteArray &activation,
                                const QByteArray &pin, bool allowFirstPin);
QByteArray encodeSignedTab(const SignedTabConfiguration &configuration, const std::string &journalBinding);
std::optional<SignedTabConfiguration> decodeSignedTab(const QString &settingsFile, const QByteArray &encoded);
bool signedTabHostReady(const QString &settingsFile, QString *enabledInventory = nullptr);
int signedTabReplicaLimit(const QString &settingsFile);
bool signedTabDestinationFree(const QString &settingsFile);
QString signedTabCachePath();
void retainSignedPredecessorMarker(SignedTabConfiguration &successor, const SignedTabConfiguration &current,
                                  std::uint64_t reviewedGeneration);
bool persistSignedSuccessor(const QString &settingsFile, const SignedTabConfiguration &current,
                           const SignedTabConfiguration &successor, const std::string &journalBinding,
                           const SignedReplicaSource &source);
} // namespace cqs::native
