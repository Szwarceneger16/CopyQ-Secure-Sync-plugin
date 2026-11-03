// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust_journal.h"
#include <QString>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

class QWidget;

namespace cqs::storage { class Directory; }
namespace cqs::trust {
class Identity;
class SignedJoinCheckpoint;
class SyncKey;
class TrustJournal;
}

namespace cqs::native {
struct SignedReplicaRequest {
    trust::JoinActivation expected;
    int maximumItems;
    bool sourcePinned;
    std::function<bool()> confirmSource;
    std::function<bool(const transaction::Snapshot &, const transaction::Snapshot &)> preserveProtectedRows;
};
// The caller owns the locally provisioned backend for the lifetime of this
// modal wizard. The optional publishing key stays guarded outside the UI.
void runSignedJoinWizard(QWidget *parent, trust::TrustJournal &journal, const trust::Identity &identity,
                         const storage::Directory &transport, trust::SignedJoinCheckpoint &checkpoint,
                         const std::string &profileBinding, const trust::SyncKey *publishKey = nullptr,
                         const std::filesystem::path &privateStaging = {},
                         const std::function<bool()> &stillCurrent = {},
                         const std::function<bool(const trust::JoinActivation &)> &activate = {},
                         const QString &replicaSource = {},
                         const std::function<std::optional<SignedReplicaRequest>()> &prepareReplica = {});
} // namespace cqs::native
