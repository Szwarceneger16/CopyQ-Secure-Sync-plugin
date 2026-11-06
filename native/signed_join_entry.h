// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust_journal.h"
#include "profile.h"
#include "signed_join_wizard.h"
#include <functional>
#include <optional>
#include <string>

class QWidget;

namespace cqs::native {
struct SignedTabConfiguration;
struct SignedReplicaSource;
using ActivateSignedTab = std::function<bool(const SignedTabConfiguration &, const std::string &, const SignedReplicaSource &)>;
using PrepareSignedReplica = std::function<std::optional<SignedReplicaRequest>(
    const QString &, const QString &, const std::string &, const SignedReplicaSource &)>;
using ArmSignedReplica = std::function<bool(
    const QString &, const QString &, const std::string &, const SignedReplicaSource &, SignedReplicaTask)>;
void openSignedJoinSetup(QWidget *parent, const QString &settingsFile, const Profile &legacy,
                         const std::function<bool()> &stillCurrent,
                         const ActivateSignedTab &activate,
                         const PrepareSignedReplica &prepareReplica,
                         const ArmSignedReplica &armReplica);
void openGuidedSignedJoinSetup(QWidget *parent, const QString &settingsFile, const Profile &legacy,
                         const std::function<bool()> &stillCurrent,
                         const ActivateSignedTab &activate,
                         const PrepareSignedReplica &prepareReplica,
                         const ArmSignedReplica &armReplica);
}
