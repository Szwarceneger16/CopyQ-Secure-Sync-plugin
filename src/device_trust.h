// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "crypto.h"
#include <array>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <vector>

namespace cqs::trust {
// Isolated stage-2 policy model. No production signer, pairing UI, secret-key
// delivery, network or persistence adapter is supplied by this component.
using Token = std::array<std::uint8_t, 32>;
using Signature = std::array<std::uint8_t, 64>;
constexpr std::uint32_t Version = 1;
constexpr std::size_t MaxMembers = 32;
constexpr std::size_t MaxStates = 256;
constexpr std::uint64_t MaxLifetime = 86400;

struct Member {
    Token id{}, signingKey{}, encryptionKey{};
    bool operator==(const Member &other) const;
    bool operator!=(const Member &other) const { return !(*this == other); }
};
enum class Operation : std::uint8_t { Add = 1, Remove = 2 };
struct Proposal {
    std::uint32_t version = Version;
    Token group{}, root{}, parent{};
    std::uint64_t parentEpoch = 0, keyGeneration = 0;
    // Public commitment, never a key. The future envelope/vault adapter must
    // verify it against the actual context-bound secret before using that key.
    Token keyCommitment{};
    Operation operation = Operation::Add;
    Member subject;
    Token request{}, nonce{};
    std::uint64_t created = 0, expires = 0;
};
struct Approval { Token signer{}; Signature signature{}; };
struct Certificate { Proposal proposal; std::vector<Approval> approvals; };
struct State {
    Token group{}, root{}, digest{}, parent{}, intent{}, recovery{}, keyCommitment{};
    std::uint64_t epoch = 0, keyGeneration = 0;
    bool bootstrapConsumed = false;
    std::vector<Member> members, retired;
};
enum class ErrorCode {
    Invalid, WrongGroup, MissingParent, Stale, Expired, NoQuorum,
    BadSignature, UnknownSigner, DuplicateApproval, Limit, NotMember,
    DuplicateIdentity, Forked, Blocked, Overflow
};
class Error final : public std::runtime_error {
public:
    explicit Error(ErrorCode code);
    ErrorCode code() const noexcept { return code_; }
private:
    ErrorCode code_;
};
class SignatureVerifier {
public:
    virtual ~SignatureVerifier() = default;
    // Caller must supply a real reviewed signature adapter before production
    // use. A callback returning true indiscriminately defeats authentication.
    virtual bool verify(const Token &publicKey, const crypto::Bytes &message,
                        const Signature &signature) const = 0;
};

// Canonical fixed-width, domain-separated model encoding. Exact decoders reject
// unsupported version/op, trailing bytes, bounds and malformed intrinsic input.
crypto::Bytes encodeProposal(const Proposal &proposal);
Proposal decodeProposal(const crypto::Bytes &bytes);
crypto::Bytes encodeCertificate(const Certificate &certificate);
Certificate decodeCertificate(const crypto::Bytes &bytes);
Token proposalDigest(const Proposal &proposal);
// Full256 comparison value binds both endpoints and the exact proposed action.
// Obtaining this value from the transport alone is not peer verification.
Token verificationDigest(const Proposal &proposal, const Member &approver);
crypto::Bytes approvalBytes(const Proposal &proposal, const Member &approver);

enum class ObserveResult { Applied, AlreadyKnown, ForkDetected };
enum class ReserveResult { Reserved, AlreadyReserved };
class Membership {
public:
    Membership(const Token &group, const Member &founder, const Token &recovery,
               const Token &initialKeyCommitment);
    const State &current() const noexcept { return states_.back(); }
    const State *acceptedState(const Token &digest) const {
        const auto found = stateIndex_.find(digest);
        return found == stateIndex_.end() ? nullptr : &states_[found->second];
    }
    bool forked() const noexcept { return forked_; }
    std::size_t stateCount() const noexcept { return states_.size(); }
    std::size_t reservationCount() const noexcept { return reservations_.size(); }
    const std::vector<Token> &forkEvidence() const noexcept { return forkEvidence_; }

    Proposal propose(Operation operation, const Member &subject,
                     const Token &request, const Token &nonce,
                     std::uint64_t created, std::uint64_t expires,
                     const Token &rotatedKeyCommitment = Token{}) const;
    // Only call after independent peer verification. This is an in-memory
    // reservation; production must commit it durably BEFORE any signature.
    // There is intentionally no erase/cancel/reset-reservation operation.
    ReserveResult reserve(const Proposal &proposal, const Token &signer,
                          std::uint64_t now);
    ObserveResult observe(const Certificate &certificate, std::uint64_t now,
                          const SignatureVerifier &verifier);
private:
    std::vector<State> states_;
    std::map<Token, std::size_t> stateIndex_;
    std::map<Token, Token> children_;
    std::map<std::pair<Token, Token>, Token> reservations_;
    std::vector<Token> forkEvidence_;
    bool forked_ = false;
};
} // namespace cqs::trust
