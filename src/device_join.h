// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust.h"

namespace cqs::trust {
struct JoinRequest {
    Member applicant;
    Token request{};
};
struct JoinPeer {
    Member member;
    Token digest{};
};
struct JoinReview {
    Token group{}, root{};
    Member applicant;
    std::uint64_t expires = 0;
    std::vector<JoinPeer> approvers;
};
struct JoinConfirmation {
    Token approver{}, digest{};
};

// Preview only. Membership must come from independently pinned local state.
// The applicant's request must come from its private journal.
JoinReview reviewJoinProposal(const Membership &membership, const Proposal &proposal,
                              const JoinRequest &request, const std::vector<Token> &approvers,
                              std::uint64_t trustedNow);
JoinReview reviewJoinApproval(const Membership &membership, const Proposal &proposal,
                              const Member &local, std::uint64_t trustedNow);
// The trusted local caller supplies confirmations from an independent screen
// or authenticated channel. A received offer or certificate cannot supply them.
void verifyJoinConfirmations(const JoinReview &review, const std::vector<JoinConfirmation> &confirmations);
} // namespace cqs::trust
