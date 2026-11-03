// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust.h"
#include "state_store.h"
#include <atomic>

namespace cqs::trust {
class Identity;
class SyncKey;
struct Genesis {
    Token group{};
    Member founder;
    Token recovery{}, initialKeyCommitment{};
};
enum class JournalCode { Invalid, WrongPins, Confirmation, ClockRollback, Rollback, Uncertain, Busy,
                         Delivery, KeyReuse };
class JournalError final : public std::runtime_error {
public:
    explicit JournalError(JournalCode code);
    JournalCode code() const noexcept { return code_; }
private:
    JournalCode code_;
};
struct JournalStatus {
    State state;
    bool forked = false;
    std::uint64_t watermark = 0;
    std::size_t operations = 0, reservations = 0;
    // Full authenticated accepted and conflicting certificates, in observation order.
    std::vector<crypto::Bytes> certificates;
};

// Test-only control-plane coordinator. A dedicated encrypted FileStore outside
// transport is required; no user profile or clipboard key is opened here.
// Pins come from trusted local setup, NEVER from the cloud journal being read.
// The unlocked Identity belongs in a separately qualified private key vault.
// All public operations retain one Store lease through load/replay/commit/sign.
class TrustJournal final {
public:
    static constexpr std::size_t MaxOperations = 2 * MaxStates;
    static constexpr std::size_t MaxJournalBytes = 2 * 1024 * 1024;
    TrustJournal(transaction::Store &store, Genesis genesis, Member local);
    TrustJournal(const TrustJournal &) = delete;
    TrustJournal &operator=(const TrustJournal &) = delete;
    static std::string binding(const Genesis &genesis, const Member &local);
    // Pure builder for explicit setup/testing. Only initialize() performs
    // create-only disk provisioning; a failed open never invokes either.
    static transaction::Record initialRecord(const Genesis &genesis, const Member &local,
                                              std::uint64_t trustedNow);
    static void initialize(state::FileStore &store, const Genesis &genesis,
                           const Member &local, std::uint64_t trustedNow);
    JournalStatus inspect();
    Proposal propose(Operation operation, const Member &subject, const Token &request,
                     const Token &nonce, std::uint64_t created, std::uint64_t expires,
                     const Token &rotatedKeyCommitment = Token{});
    // confirmedDigest is supplied ONLY after a trusted local UI compared the
    // full verificationDigest(proposal, local) with the peer out of band.
    // Transport fields/QR files cannot provide this authorization.
    Approval approve(const Proposal &proposal, const Identity &identity,
                     const Token &confirmedDigest, std::uint64_t trustedNow);
    ObserveResult observe(const Certificate &certificate, std::uint64_t trustedNow);
    // Prepare one exact ciphertext for an authorized recipient at the accepted
    // head. Retry returns the stored bytes. A transport publisher must recheck
    // authorization under its live guard before releasing the prepared bytes.
    crypto::Bytes prepareDelivery(const Token &recipient, const Identity &sender,
                                  const SyncKey &key, std::uint64_t trustedNow);
    // Authenticates against the current pinned head before opening. The returned
    // key remains guarded. Installing it in a CopyQ profile is a separate step.
    std::unique_ptr<SyncKey> receiveDelivery(const crypto::Bytes &wire, const Identity &recipient,
                                             std::uint64_t trustedNow);
private:
    std::unique_ptr<transaction::Store::Lease> lock();
    transaction::Record load();
    void save(const transaction::Record &expected, transaction::Record replacement);
    transaction::Store &store_;
    Genesis genesis_;
    Member local_;
    std::string binding_;
    std::atomic<bool> uncertain_{false};
    std::optional<std::uint64_t> seenGeneration_;
    Token seenRecord_{};
};
} // namespace cqs::trust
