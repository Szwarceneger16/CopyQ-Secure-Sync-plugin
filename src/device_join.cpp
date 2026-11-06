// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_join.h"
#include "device_identity.h"
#include "device_trust_journal.h"
#include <algorithm>
#include <sodium.h>

namespace cqs::trust {
namespace {
JoinReview reviewProposal(const Membership &membership, const Proposal &proposal,
                          std::vector<Token> approvers, std::uint64_t now) {
    if (membership.forked()) throw Error(ErrorCode::Forked);
    if (proposal.operation != Operation::Add || !SodiumVerifier::validMember(proposal.subject))
        throw Error(ErrorCode::Invalid);

    std::sort(approvers.begin(), approvers.end());
    if (std::adjacent_find(approvers.begin(), approvers.end()) != approvers.end())
        throw Error(ErrorCode::DuplicateApproval);
    const auto &parent = membership.current();
    auto preview = membership;
    JoinReview result{parent.group, parent.root, proposal.subject, proposal.expires, {}};
    result.approvers.reserve(approvers.size());
    for (const auto &id : approvers) {
        // Check freshness, parent, membership and sign-once eligibility without
        // creating an approval or changing the authenticated local membership.
        (void)preview.reserve(proposal, id, now);
        const auto peer = std::find_if(parent.members.begin(), parent.members.end(),
            [&](const Member &candidate) { return candidate.id == id; });
        if (peer == parent.members.end() || !SodiumVerifier::validMember(*peer))
            throw Error(ErrorCode::UnknownSigner);
        result.approvers.push_back({*peer, verificationDigest(proposal, *peer)});
    }
    return result;
}
} // namespace

JoinReview reviewJoinProposal(const Membership &membership, const Proposal &proposal,
                              const JoinRequest &request, const std::vector<Token> &approvers,
                              std::uint64_t trustedNow) {
    if (proposal.subject != request.applicant || proposal.request != request.request)
        throw Error(ErrorCode::Invalid);
    if (approvers.size() > MaxMembers) throw Error(ErrorCode::Limit);
    const auto &parent = membership.current();
    // Match certificate admission's one-time genesis exception for Add.
    const std::size_t quorum = parent.epoch == 0 && !parent.bootstrapConsumed && parent.members.size() == 1 ? 1 : 2;
    if (approvers.size() < quorum) throw Error(ErrorCode::NoQuorum);
    return reviewProposal(membership, proposal, approvers, trustedNow);
}

JoinReview reviewJoinApproval(const Membership &membership, const Proposal &proposal,
                              const Member &local, std::uint64_t trustedNow) {
    const auto &members = membership.current().members;
    if (std::find(members.begin(), members.end(), local) == members.end()) throw Error(ErrorCode::NotMember);
    return reviewProposal(membership, proposal, {local.id}, trustedNow);
}

void verifyJoinConfirmations(const JoinReview &review, const std::vector<JoinConfirmation> &confirmations) {
    if (confirmations.empty() || confirmations.size() > MaxMembers ||
        confirmations.size() != review.approvers.size())
        throw JournalError(JournalCode::Confirmation);
    auto ordered = confirmations;
    std::sort(ordered.begin(), ordered.end(),
              [](const JoinConfirmation &a, const JoinConfirmation &b) { return a.approver < b.approver; });
    bool matches = true;
    for (std::size_t i = 0; i < ordered.size(); ++i) {
        const auto &actual = ordered[i];
        const auto &expected = review.approvers[i];
        const bool digestMatches =
            sodium_memcmp(actual.digest.data(), expected.digest.data(), actual.digest.size()) == 0;
        matches = matches && digestMatches && actual.approver == expected.member.id &&
                  (i == 0 || ordered[i - 1].approver != actual.approver);
    }
    if (!matches) throw JournalError(JournalCode::Confirmation);
}
} // namespace cqs::trust
