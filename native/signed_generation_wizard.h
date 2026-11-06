// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "signed_join_wizard.h"
#include "signed_tab_activation.h"

namespace cqs::native {
bool runSignedGenerationWizard(QWidget *parent, trust::TrustJournal &, const trust::Identity &,
    const storage::Directory &, trust::SignedJoinCheckpoint &source, const crypto::Bytes &checkpointCredential,
    const QString &settingsFile, const std::string &journalBinding, const SignedReplicaSource &,
    const SignedReplicaRequest &, const std::filesystem::path &privateStaging,
    const std::function<bool()> &stillCurrent,
    const std::function<bool(const QString &)> &validateDestination = {});
}
