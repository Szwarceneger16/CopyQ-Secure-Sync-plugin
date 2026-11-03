// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust.h"
#include <functional>
#include <iosfwd>
#include <optional>

namespace cqs::trust {
class Identity;
class TrustJournal;

// Show the locally checked applicant comparisons before signatures exist.
// This takes no input and creates no approval or Join.
bool showJoinApplicantReview(TrustJournal &journal, const Proposal &proposal,
    const std::vector<Token> &intendedApprovers, std::ostream &output, std::uint64_t now);

// Laboratory adapter for trusted local input and display. Never connect the
// confirmation stream to transport data or automate the peer comparison.
// A rejected prompt returns nullopt without submitting an approval or Join.
std::optional<Approval> runJoinApprovalWizard(TrustJournal &journal, const Identity &identity,
    const Proposal &proposal, std::istream &input, std::ostream &output,
    const std::function<std::uint64_t()> &now);
// A durably verified Join can retry its exact certificate without prompting.
std::optional<ObserveResult> runJoinApplicantWizard(TrustJournal &journal, const Certificate &certificate,
    std::istream &input, std::ostream &output, const std::function<std::uint64_t()> &now);
} // namespace cqs::trust
