// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_trust.h"
#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace cqs::trust {
namespace {
constexpr char IntentDomain[] = "CopyQ-Secure-Sync-membership-intent-model-v1";
constexpr char CertificateDomain[] = "CopyQ-Secure-Sync-membership-certificate-model-v1";
constexpr char ApprovalDomain[] = "CopyQ-Secure-Sync-membership-approval-model-v1";
constexpr char VerificationDomain[] = "CopyQ-Secure-Sync-membership-verification-model-v1";
constexpr char GenesisDomain[] = "CopyQ-Secure-Sync-membership-genesis-model-v1";
constexpr char StateDomain[] = "CopyQ-Secure-Sync-membership-state-model-v1";
constexpr std::size_t IntentSize = sizeof(IntentDomain) + 4 + 32 * 9 + 8 * 4 + 1;
constexpr std::size_t CertificateBase = sizeof(CertificateDomain) + IntentSize + 4;
constexpr std::size_t ApprovalSize = 32 + 64;

[[noreturn]] void fail(ErrorCode code) { throw Error(code); }
template<std::size_t N> bool zero(const std::array<std::uint8_t, N> &value) {
    return std::all_of(value.begin(), value.end(), [](auto b) { return b == 0; });
}
void append(crypto::Bytes &out, const Token &token) {
    out.insert(out.end(), token.begin(), token.end());
}
template<std::size_t N> void domain(crypto::Bytes &out, const char (&text)[N]) {
    // Include the terminating NUL; the domains are protocol bytes, not labels.
    out.insert(out.end(), text, text + N);
}
void u32(crypto::Bytes &out, std::uint32_t value) {
    for (unsigned shift = 32; shift; shift -= 8) out.push_back(static_cast<std::uint8_t>(value >> (shift - 8)));
}
void u64(crypto::Bytes &out, std::uint64_t value) {
    for (unsigned shift = 64; shift; shift -= 8) out.push_back(static_cast<std::uint8_t>(value >> (shift - 8)));
}
void memberBytes(crypto::Bytes &out, const Member &member) {
    append(out, member.id); append(out, member.signingKey); append(out, member.encryptionKey);
}
void validMember(const Member &member) {
    if (zero(member.id) || zero(member.signingKey) || zero(member.encryptionKey) ||
        member.signingKey == member.encryptionKey) fail(ErrorCode::Invalid);
    // This is structural validation only. The signature and encryption adapters
    // must also validate the chosen suite's actual public-key encodings.
}
void validIntrinsic(const Proposal &proposal) {
    if (proposal.version != Version || zero(proposal.group) || zero(proposal.root) ||
        zero(proposal.parent) || zero(proposal.request) || zero(proposal.nonce) ||
        zero(proposal.keyCommitment) ||
        (proposal.operation != Operation::Add && proposal.operation != Operation::Remove) ||
        proposal.created >= proposal.expires ||
        proposal.expires - proposal.created > MaxLifetime) fail(ErrorCode::Invalid);
    validMember(proposal.subject);
}
void validTime(const Proposal &proposal, std::uint64_t now) {
    if (now < proposal.created || now >= proposal.expires) fail(ErrorCode::Expired);
}
Token digest(const crypto::Bytes &bytes) {
    const auto hashed = crypto::sha256(bytes);
    if (hashed.size() != 32) fail(ErrorCode::Invalid);
    Token result{}; std::copy(hashed.begin(), hashed.end(), result.begin()); return result;
}
const Member *findMember(const State &state, const Token &id) {
    const auto it = std::find_if(state.members.begin(), state.members.end(),
        [&](const Member &member) { return member.id == id; });
    return it == state.members.end() ? nullptr : &*it;
}
bool collides(const Member &a, const Member &b) {
    return a.id == b.id || a.signingKey == b.signingKey ||
        a.encryptionKey == b.encryptionKey || a.signingKey == b.encryptionKey ||
        a.encryptionKey == b.signingKey;
}
void sortMembers(std::vector<Member> &members) {
    std::sort(members.begin(), members.end(), [](const Member &a, const Member &b) { return a.id < b.id; });
}
Token stateDigest(const State &state) {
    crypto::Bytes bytes; domain(bytes, StateDomain); u32(bytes, Version);
    append(bytes, state.group); append(bytes, state.root); append(bytes, state.parent);
    append(bytes, state.intent); append(bytes, state.recovery);
    u64(bytes, state.epoch); u64(bytes, state.keyGeneration);
    append(bytes, state.keyCommitment);
    bytes.push_back(state.bootstrapConsumed ? 1 : 0);
    u32(bytes, static_cast<std::uint32_t>(state.members.size()));
    for (const auto &member : state.members) memberBytes(bytes, member);
    u32(bytes, static_cast<std::uint32_t>(state.retired.size()));
    for (const auto &member : state.retired) memberBytes(bytes, member);
    return digest(bytes);
}
State successor(const State &parent, const Proposal &proposal) {
    validIntrinsic(proposal);
    if (proposal.group != parent.group || proposal.root != parent.root) fail(ErrorCode::WrongGroup);
    if (proposal.parent != parent.digest || proposal.parentEpoch != parent.epoch) fail(ErrorCode::Stale);
    if (parent.epoch == std::numeric_limits<std::uint64_t>::max()) fail(ErrorCode::Overflow);
    State result = parent;
    result.parent = parent.digest; result.intent = proposalDigest(proposal); ++result.epoch;
    if (proposal.operation == Operation::Add) {
        if (parent.members.size() >= MaxMembers) fail(ErrorCode::Limit);
        for (const auto &member : parent.members) if (collides(member, proposal.subject)) fail(ErrorCode::DuplicateIdentity);
        for (const auto &member : parent.retired) if (collides(member, proposal.subject)) fail(ErrorCode::DuplicateIdentity);
        if (proposal.keyGeneration != parent.keyGeneration || proposal.keyCommitment != parent.keyCommitment)
            fail(ErrorCode::Invalid);
        result.members.push_back(proposal.subject); sortMembers(result.members);
        result.bootstrapConsumed = true;
    } else {
        if (parent.members.size() < 3) fail(ErrorCode::NoQuorum);
        const auto *target = findMember(parent, proposal.subject.id);
        if (!target || *target != proposal.subject) fail(ErrorCode::NotMember);
        if (parent.keyGeneration == std::numeric_limits<std::uint64_t>::max()) fail(ErrorCode::Overflow);
        if (proposal.keyGeneration != parent.keyGeneration + 1 || proposal.keyCommitment == parent.keyCommitment)
            fail(ErrorCode::Invalid);
        result.keyGeneration = proposal.keyGeneration;
        result.keyCommitment = proposal.keyCommitment;
        result.members.erase(std::remove(result.members.begin(), result.members.end(), proposal.subject), result.members.end());
        result.retired.push_back(proposal.subject); sortMembers(result.retired);
    }
    result.digest = stateDigest(result);
    return result;
}
std::size_t requiredApprovals(const State &parent, const Proposal &proposal) {
    return !parent.bootstrapConsumed && parent.epoch == 0 && parent.members.size() == 1 &&
        proposal.operation == Operation::Add ? 1 : 2;
}
std::vector<Approval> sortedApprovals(const Certificate &certificate) {
    if (certificate.approvals.empty() || certificate.approvals.size() > MaxMembers) fail(ErrorCode::Limit);
    auto result = certificate.approvals;
    std::sort(result.begin(), result.end(), [](const Approval &a, const Approval &b) { return a.signer < b.signer; });
    Token previous{};
    for (const auto &approval : result) {
        if (zero(approval.signer) || zero(approval.signature)) fail(ErrorCode::Invalid);
        if (approval.signer == previous) fail(ErrorCode::DuplicateApproval);
        previous = approval.signer;
    }
    return result;
}
void authenticate(const State &parent, const Certificate &certificate, const SignatureVerifier &verifier) {
    if (certificate.approvals.empty()) fail(ErrorCode::NoQuorum);
    const auto approvals = sortedApprovals(certificate);
    if (approvals.size() < requiredApprovals(parent, certificate.proposal)) fail(ErrorCode::NoQuorum);
    for (const auto &approval : approvals) {
        const auto *signer = findMember(parent, approval.signer);
        if (!signer) fail(ErrorCode::UnknownSigner);
        if (certificate.proposal.operation == Operation::Remove && signer->id == certificate.proposal.subject.id)
            fail(ErrorCode::UnknownSigner);
        bool valid = false;
        try { valid = verifier.verify(signer->signingKey, approvalBytes(certificate.proposal, *signer), approval.signature); }
        catch (...) { fail(ErrorCode::BadSignature); }
        if (!valid) fail(ErrorCode::BadSignature);
    }
}
class Reader {
public:
    explicit Reader(const crypto::Bytes &bytes) : bytes_(bytes) {}
    template<std::size_t N> void expect(const char (&text)[N]) {
        need(N);
        if (!std::equal(text, text + N, bytes_.begin() + static_cast<std::ptrdiff_t>(position_))) fail(ErrorCode::Invalid);
        position_ += N;
    }
    std::uint8_t byte() { need(1); return bytes_[position_++]; }
    std::uint32_t number32() { std::uint32_t value = 0; for (unsigned i = 0; i < 4; ++i) value = (value << 8) | byte(); return value; }
    std::uint64_t number64() { std::uint64_t value = 0; for (unsigned i = 0; i < 8; ++i) value = (value << 8) | byte(); return value; }
    template<std::size_t N> std::array<std::uint8_t, N> fixed() {
        need(N); std::array<std::uint8_t, N> result{};
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(position_), N, result.begin()); position_ += N; return result;
    }
    Member member() { return {fixed<32>(), fixed<32>(), fixed<32>()}; }
    bool done() const { return position_ == bytes_.size(); }
private:
    void need(std::size_t n) { if (n > bytes_.size() - position_) fail(ErrorCode::Invalid); }
    const crypto::Bytes &bytes_; std::size_t position_ = 0;
};
Proposal readProposal(Reader &reader) {
    reader.expect(IntentDomain); Proposal result;
    result.version = reader.number32(); result.group = reader.fixed<32>();
    result.root = reader.fixed<32>(); result.parent = reader.fixed<32>();
    result.parentEpoch = reader.number64(); result.keyGeneration = reader.number64();
    result.keyCommitment = reader.fixed<32>();
    result.operation = static_cast<Operation>(reader.byte()); result.subject = reader.member();
    result.request = reader.fixed<32>(); result.nonce = reader.fixed<32>();
    result.created = reader.number64(); result.expires = reader.number64();
    validIntrinsic(result); return result;
}
} // namespace

Error::Error(ErrorCode code) : std::runtime_error("Device trust request refused"), code_(code) {}
bool Member::operator==(const Member &other) const {
    return id == other.id && signingKey == other.signingKey && encryptionKey == other.encryptionKey;
}
crypto::Bytes encodeProposal(const Proposal &proposal) {
    validIntrinsic(proposal); crypto::Bytes bytes; bytes.reserve(IntentSize);
    domain(bytes, IntentDomain); u32(bytes, proposal.version);
    append(bytes, proposal.group); append(bytes, proposal.root); append(bytes, proposal.parent);
    u64(bytes, proposal.parentEpoch); u64(bytes, proposal.keyGeneration);
    append(bytes, proposal.keyCommitment);
    bytes.push_back(static_cast<std::uint8_t>(proposal.operation)); memberBytes(bytes, proposal.subject);
    append(bytes, proposal.request); append(bytes, proposal.nonce);
    u64(bytes, proposal.created); u64(bytes, proposal.expires); return bytes;
}
Proposal decodeProposal(const crypto::Bytes &bytes) {
    if (bytes.size() != IntentSize) fail(ErrorCode::Invalid);
    Reader reader(bytes); auto result = readProposal(reader);
    if (!reader.done()) fail(ErrorCode::Invalid);
    return result;
}
crypto::Bytes encodeCertificate(const Certificate &certificate) {
    const auto approvals = sortedApprovals(certificate);
    crypto::Bytes bytes; bytes.reserve(CertificateBase + approvals.size() * ApprovalSize);
    domain(bytes, CertificateDomain); const auto proposal = encodeProposal(certificate.proposal);
    bytes.insert(bytes.end(), proposal.begin(), proposal.end()); u32(bytes, static_cast<std::uint32_t>(approvals.size()));
    for (const auto &approval : approvals) {
        append(bytes, approval.signer); bytes.insert(bytes.end(), approval.signature.begin(), approval.signature.end());
    }
    return bytes;
}
Certificate decodeCertificate(const crypto::Bytes &bytes) {
    if (bytes.size() < CertificateBase || bytes.size() > CertificateBase + MaxMembers * ApprovalSize) fail(ErrorCode::Limit);
    Reader reader(bytes); reader.expect(CertificateDomain); Certificate result;
    result.proposal = readProposal(reader); const auto count = reader.number32();
    if (!count || count > MaxMembers || bytes.size() != CertificateBase + count * ApprovalSize) fail(ErrorCode::Invalid);
    Token previous{}; result.approvals.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        Approval approval{reader.fixed<32>(), reader.fixed<64>()};
        if (zero(approval.signer) || zero(approval.signature) || !(previous < approval.signer)) fail(ErrorCode::Invalid);
        previous = approval.signer; result.approvals.push_back(approval);
    }
    if (!reader.done()) fail(ErrorCode::Invalid);
    return result;
}
Token proposalDigest(const Proposal &proposal) { return digest(encodeProposal(proposal)); }
Token verificationDigest(const Proposal &proposal, const Member &approver) {
    validMember(approver); crypto::Bytes bytes; domain(bytes, VerificationDomain);
    const auto intent = encodeProposal(proposal); bytes.insert(bytes.end(), intent.begin(), intent.end());
    memberBytes(bytes, approver); return digest(bytes);
}
crypto::Bytes approvalBytes(const Proposal &proposal, const Member &approver) {
    validMember(approver); crypto::Bytes bytes; domain(bytes, ApprovalDomain);
    const auto intent = encodeProposal(proposal); bytes.insert(bytes.end(), intent.begin(), intent.end());
    memberBytes(bytes, approver); append(bytes, verificationDigest(proposal, approver)); return bytes;
}

Membership::Membership(const Token &group, const Member &founder, const Token &recovery,
                       const Token &initialKeyCommitment) {
    validMember(founder);
    if (zero(group) || zero(recovery) || zero(initialKeyCommitment)) fail(ErrorCode::Invalid);
    State genesis; genesis.group = group; genesis.recovery = recovery;
    genesis.keyCommitment = initialKeyCommitment; genesis.members = {founder};
    crypto::Bytes root; domain(root, GenesisDomain); u32(root, Version);
    append(root, group); memberBytes(root, founder); append(root, recovery); append(root, initialKeyCommitment);
    genesis.root = digest(root); genesis.digest = stateDigest(genesis);
    states_.push_back(genesis); stateIndex_.emplace(genesis.digest, 0);
}
Proposal Membership::propose(Operation operation, const Member &subject, const Token &request,
                             const Token &nonce, std::uint64_t created, std::uint64_t expires,
                             const Token &rotatedKeyCommitment) const {
    if (forked_) fail(ErrorCode::Forked);
    if (states_.size() >= MaxStates) fail(ErrorCode::Limit);
    const auto &state = current(); Proposal proposal;
    proposal.group = state.group; proposal.root = state.root; proposal.parent = state.digest;
    proposal.parentEpoch = state.epoch; proposal.keyGeneration = state.keyGeneration;
    proposal.keyCommitment = state.keyCommitment;
    proposal.operation = operation; proposal.subject = subject; proposal.request = request;
    proposal.nonce = nonce; proposal.created = created; proposal.expires = expires;
    if (operation == Operation::Remove) {
        if (proposal.keyGeneration == std::numeric_limits<std::uint64_t>::max()) fail(ErrorCode::Overflow);
        ++proposal.keyGeneration;
        proposal.keyCommitment = rotatedKeyCommitment;
    } else if (!zero(rotatedKeyCommitment) && rotatedKeyCommitment != state.keyCommitment) {
        fail(ErrorCode::Invalid);
    }
    (void)successor(state, proposal); return proposal;
}
ReserveResult Membership::reserve(const Proposal &proposal, const Token &signer, std::uint64_t now) {
    if (forked_) fail(ErrorCode::Forked);
    if (states_.size() >= MaxStates) fail(ErrorCode::Limit);
    (void)successor(current(), proposal); validTime(proposal, now);
    if (!findMember(current(), signer) ||
        (proposal.operation == Operation::Remove && proposal.subject.id == signer)) fail(ErrorCode::UnknownSigner);
    const auto key = std::make_pair(proposal.parent, signer);
    const auto intent = proposalDigest(proposal);
    const auto previous = reservations_.find(key);
    if (previous != reservations_.end()) {
        if (previous->second != intent) fail(ErrorCode::Blocked);
        return ReserveResult::AlreadyReserved;
    }
    // At most MaxMembers reservations for each of MaxStates retained parents.
    if (reservations_.size() >= MaxMembers * MaxStates) fail(ErrorCode::Limit);
    reservations_.emplace(key, intent); return ReserveResult::Reserved;
}
ObserveResult Membership::observe(const Certificate &certificate, std::uint64_t now,
                                 const SignatureVerifier &verifier) {
    if (forked_) fail(ErrorCode::Forked);
    validIntrinsic(certificate.proposal);
    if (certificate.proposal.group != current().group || certificate.proposal.root != current().root) fail(ErrorCode::WrongGroup);
    const auto found = stateIndex_.find(certificate.proposal.parent);
    if (found == stateIndex_.end()) fail(ErrorCode::MissingParent);
    const auto &parent = states_[found->second];
    const auto child = successor(parent, certificate.proposal);
    authenticate(parent, certificate, verifier);
    const auto known = children_.find(parent.digest);
    if (known != children_.end()) {
        if (known->second == child.digest) return ObserveResult::AlreadyKnown;
        std::vector<Token> evidence{known->second, child.digest};
        forkEvidence_.swap(evidence); forked_ = true; return ObserveResult::ForkDetected;
    }
    if (parent.digest != current().digest) fail(ErrorCode::Stale);
    validTime(certificate.proposal, now);
    if (states_.size() >= MaxStates) fail(ErrorCode::Limit);
    // Commit only after all validation/allocation succeeds. In particular a
    // malformed additional signature or allocation failure cannot advance state.
    auto nextStates = states_; auto nextIndex = stateIndex_; auto nextChildren = children_;
    nextIndex.emplace(child.digest, nextStates.size()); nextChildren.emplace(parent.digest, child.digest);
    nextStates.push_back(child);
    states_.swap(nextStates); stateIndex_.swap(nextIndex); children_.swap(nextChildren);
    return ObserveResult::Applied;
}
} // namespace cqs::trust
