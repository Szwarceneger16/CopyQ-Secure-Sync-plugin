// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_join_wizard.h"
#include "device_identity.h"
#include "device_join.h"
#include "device_trust_journal.h"
#include <istream>
#include <ostream>
#include <string>

namespace cqs::trust {
namespace {
constexpr std::size_t HexSize = 2 * Token{}.size();
constexpr std::size_t GroupSize = 8;
constexpr std::size_t GroupedSize = HexSize + HexSize / GroupSize - 1;

std::string display(const Token &value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(GroupedSize);
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i && (2 * i) % GroupSize == 0) result.push_back('-');
        result.push_back(digits[value[i] >> 4]);
        result.push_back(digits[value[i] & 15]);
    }
    return result;
}

int hexDigit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

std::optional<Token> readComparison(std::istream &input) {
    std::array<char, GroupedSize + 1> line{}; // Includes an optional CR.
    std::size_t size = 0;
    for (;;) {
        const auto next = input.get();
        if (next == std::char_traits<char>::eof()) return std::nullopt;
        if (next == '\n') break;
        if (size == line.size()) {
            input.setstate(std::ios::failbit);
            return std::nullopt;
        }
        line[size++] = static_cast<char>(next);
    }
    if (size && line[size - 1] == '\r') --size;
    const bool grouped = size == GroupedSize;
    if (!grouped && size != HexSize) return std::nullopt;

    Token result{};
    std::size_t offset = 0;
    for (std::size_t digit = 0; digit < HexSize; ++digit) {
        if (grouped && digit && digit % GroupSize == 0 && line[offset++] != '-') return std::nullopt;
        const auto value = hexDigit(line[offset++]);
        if (value < 0) return std::nullopt;
        const auto shift = digit % 2 ? 0 : 4;
        result[digit / 2] |= static_cast<std::uint8_t>(value << shift);
    }
    return result;
}

void showContext(std::ostream &output, const JoinReview &review) {
    output << "Device enrollment\n"
           << "Group " << display(review.group) << '\n'
           << "Genesis root " << display(review.root) << '\n'
           << "Applicant " << display(review.applicant.id) << '\n'
           << "Expires at Unix time " << review.expires << '\n'
           << "Enrollment grants access to synchronized clipboard history under the current group key.\n";
}

void showPeer(std::ostream &output, const JoinPeer &peer) {
    output << "Approver " << display(peer.member.id) << '\n'
           << "Local comparison " << display(peer.digest) << '\n'
           << "Compare all digits with the other device on a trusted screen or authenticated channel.\n";
}

std::optional<Token> confirmPeer(std::istream &input, std::ostream &output, const JoinPeer &peer) {
    showPeer(output, peer);
    output << "Enter the full value from that device (64 hex digits, with or without group separators).\n"
           << std::flush;
    if (!output) return std::nullopt;
    const auto entered = readComparison(input);
    if (!entered || *entered != peer.digest) return std::nullopt;
    return entered;
}
} // namespace

bool showJoinApplicantReview(TrustJournal &journal, const Proposal &proposal,
    const std::vector<Token> &intendedApprovers, std::ostream &output, std::uint64_t now) {
    const auto review = journal.reviewJoin(proposal, intendedApprovers, now);
    showContext(output, review);
    for (const auto &peer : review.approvers) showPeer(output, peer);
    return static_cast<bool>(output << std::flush);
}

std::optional<Approval> runJoinApprovalWizard(TrustJournal &journal, const Identity &identity,
    const Proposal &proposal, std::istream &input, std::ostream &output,
    const std::function<std::uint64_t()> &now) {
    const auto review = journal.reviewJoinApproval(proposal, now());
    if (review.approvers.size() != 1 || review.approvers.front().member != identity.member())
        throw JournalError(JournalCode::WrongPins);
    showContext(output, review);
    const auto confirmed = confirmPeer(input, output, review.approvers.front());
    if (!confirmed) return std::nullopt;
    return journal.approve(proposal, identity, *confirmed, now());
}

std::optional<ObserveResult> runJoinApplicantWizard(TrustJournal &journal, const Certificate &certificate,
    std::istream &input, std::ostream &output, const std::function<std::uint64_t()> &now) {
    if (certificate.approvals.empty() || certificate.approvals.size() > MaxMembers)
        throw JournalError(JournalCode::Enrollment);
    if (journal.inspect().verifiedJoin)
        return journal.acceptJoin(certificate, {}, now());
    std::vector<Token> approvers;
    approvers.reserve(certificate.approvals.size());
    for (const auto &approval : certificate.approvals) approvers.push_back(approval.signer);
    const auto review = journal.reviewJoin(certificate.proposal, approvers, now());
    showContext(output, review);
    std::vector<JoinConfirmation> confirmed;
    confirmed.reserve(review.approvers.size());
    for (const auto &peer : review.approvers) {
        const auto value = confirmPeer(input, output, peer);
        if (!value) return std::nullopt;
        confirmed.push_back({peer.member.id, *value});
    }
    return journal.acceptJoin(certificate, confirmed, now());
}
} // namespace cqs::trust
