// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust.h"
#include "device_join.h"
#include "device_signed_event.h"
#include "state_store.h"
#include <atomic>
#include <functional>

namespace cqs::storage { class Directory; }

namespace cqs::trust {
class Identity;
class SyncKey;
struct LegacyArchiveSource;
enum class KeyScope : std::uint8_t;
struct Genesis {
    Token group{};
    Member founder;
    Token recovery{}, initialKeyCommitment{};
};
enum class JournalCode { Invalid, WrongPins, Confirmation, ClockRollback, Rollback, Uncertain, Busy,
                         Delivery, KeyReuse, MissingKey, EventPending, EventReservation, EventBudget,
                         EventPublication, HistoryChanged, EventVersion, Migration, Enrollment };
class JournalError final : public std::runtime_error {
public:
    explicit JournalError(JournalCode code);
    JournalCode code() const noexcept { return code_; }
private:
    JournalCode code_;
};
struct PendingClipboardEvent {
    std::uint64_t sequence;
    bool ready;
    bool publicationAttempted;
};
enum class ClipboardPublication { Append, Seed };
struct PreparedClipboardEvent {
    std::uint64_t sequence;
    crypto::Bytes wire;
};
struct ArchiveMigrationStatus {
    std::uint64_t sequence;
    bool completed;
};
struct JournalStatus {
    State state;
    bool forked = false;
    std::uint64_t watermark = 0;
    std::size_t operations = 0, reservations = 0;
    // Full authenticated accepted and conflicting certificates, in observation order.
    std::vector<crypto::Bytes> certificates;
    bool installedKey = false;
    std::vector<Token> confirmedDeliveries;
    std::uint64_t allocatedEventSequence = 0;
    std::optional<PendingClipboardEvent> pendingEvent;
    std::uint32_t eventEncryptionAttempts = 0;
    std::size_t eventWitnesses = 0;
    std::optional<ArchiveMigrationStatus> migration;
    bool verifiedJoin = false;
};
struct JoinActivation {
    std::string profileBinding;
    Token group, root, head, member, tipDigest;
    std::uint64_t generation;
    std::string tipId;
};
using JoinActivationWriter = std::function<void(const JoinActivation &, const events::Event &,
                                                 const transaction::Snapshot &)>;
struct SignedEventHistory {
    std::vector<events::Event> events;
    history::Graph graph;
    std::map<std::string, Token> wireDigests;
};

// Test-only coordinator. Use a dedicated encrypted FileStore outside transport
// with capacity for MaxJournalBytes plus record framing. No user profile is opened.
// Pins come from trusted local setup, NEVER from the cloud journal being read.
// The unlocked Identity belongs in a separately qualified private key vault.
// All public operations retain one Store lease through load/replay/commit/sign.
class TrustJournal final {
public:
    static constexpr std::size_t MaxOperations = 2 * MaxStates;
    static constexpr std::size_t MaxControlBytes = 2 * 1024 * 1024;
    static constexpr std::size_t MaxClipboardEventBytes = 2 * 1024 * 1024;
    static constexpr std::size_t MaxJournalBytes = MaxControlBytes + MaxClipboardEventBytes +
                                                   94 + 77 * history::MaxEvents;
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
    // Pins and the identity vault must come from trusted local setup.
    JoinRequest beginJoin(const Identity &applicant, std::uint64_t trustedNow);
    Proposal proposeJoin(const JoinRequest &request, std::uint64_t trustedNow, std::uint64_t expires);
    JoinReview reviewJoin(const Proposal &proposal, const std::vector<Token> &approvers,
                          std::uint64_t trustedNow);
    JoinReview reviewJoinApproval(const Proposal &proposal, std::uint64_t trustedNow);
    ObserveResult acceptJoin(const Certificate &certificate,
                             const std::vector<JoinConfirmation> &confirmations,
                             std::uint64_t trustedNow);
    // Verifies readiness and durably witnesses the signed history. The result
    // contains no key or clipboard data and does not authorize a later write.
    JoinActivation preflightJoinActivation(const Identity &applicant, const storage::Directory &transport,
                                           std::string profileBinding, std::uint64_t trustedNow);
    // Revalidate the exact reviewed checkpoint. The detached writer runs under
    // the trust lease and must own the destination session through persistence.
    void applyJoinActivation(const Identity &applicant, const storage::Directory &transport,
                             const JoinActivation &expected, std::uint64_t trustedNow,
                             const JoinActivationWriter &write);
    ObserveResult observe(const Certificate &certificate, std::uint64_t trustedNow);
    // Prepare one exact ciphertext for an authorized recipient at the accepted
    // head. Retry returns the stored bytes. A transport publisher must recheck
    // authorization under its live guard before releasing the prepared bytes.
    crypto::Bytes prepareDelivery(const Token &recipient, const Identity &sender,
                                  const SyncKey &key, std::uint64_t trustedNow);
    // Explicit catch-up after a later Add for a member who was already admitted.
    crypto::Bytes prepareCatchUp(const Token &recipient, const Identity &sender,
                                const SyncKey &key, std::uint64_t trustedNow);
    // Authenticates against the current pinned head before opening. The returned
    // key remains guarded. Installing it in a CopyQ profile is a separate step.
    std::unique_ptr<SyncKey> receiveDelivery(const crypto::Bytes &wire, const Identity &recipient,
                                             std::uint64_t trustedNow);
    // Store the authenticated sealed package before signing the storage receipt.
    crypto::Bytes installDelivery(const crypto::Bytes &wire, const Identity &recipient,
                                  std::uint64_t trustedNow);
    std::unique_ptr<SyncKey> loadInstalledKey(const Identity &recipient, std::uint64_t trustedNow);
    // True when a verified storage receipt was added to the current outbox.
    bool recordReceipt(const crypto::Bytes &receipt, std::uint64_t trustedNow);
    // Publish only a currently authorized staged package, under the journal lease.
    std::string publishDelivery(const Token &recipient, const storage::Directory &transport,
                                std::uint64_t trustedNow, const std::filesystem::path &privateStaging = {});
    // A storage receipt for the current head is signed after a durable local
    // barrier, then published under the same lease. Returns its packet address.
    std::string publishReceipt(const Identity &recipient, const storage::Directory &transport,
                               std::uint64_t trustedNow, const std::filesystem::path &privateStaging = {});
    // Local laboratory outbox. Burns one sequence before sealing and commits
    // the exact wire before returning it. Never sends to shared storage.
    PreparedClipboardEvent prepareClipboardEvent(const Identity &author, const SyncKey &key,
                                                const std::vector<SignedEventParent> &parents,
                                                const std::vector<std::string> &packedItems,
                                                std::uint64_t trustedNow, events::Limits limits = {});
    // Reestablishes the durable barrier for exactly the requested ready slot.
    PreparedClipboardEvent resumeClipboardEvent(std::uint64_t sequence, std::uint64_t trustedNow);
    // Explicitly retire a slot without changing its high-water sequence.
    void discardClipboardEvent(std::uint64_t sequence, std::uint64_t trustedNow);
    // Operational laboratory scan, scoped by the accepted membership. Retains
    // exact witnesses before returning decoded contents.
    SignedEventHistory scanClipboardEvents(const SyncKey &key, const storage::Directory &transport,
                                            std::uint64_t trustedNow, events::Limits limits = {});
    // Publish the exact staged packet. Seed needs explicit local authorization.
    std::string publishClipboardEvent(std::uint64_t sequence, const SyncKey &key,
                                       const storage::Directory &transport, std::uint64_t trustedNow,
                                       ClipboardPublication mode = ClipboardPublication::Append,
                                       const std::filesystem::path &privateStaging = {});
    // Read-only preview. A trusted local caller must confirm the exact digest
    // before the source tip can become the fresh founder's signed Seed.
    Token previewLegacyMigration(const LegacyArchiveSource &source, const SyncKey &successorKey,
                                 std::uint64_t trustedNow);
    std::string migrateLegacyArchive(const LegacyArchiveSource &source, const Token &confirmed,
                                     const Identity &founder, const SyncKey &successorKey,
                                     const storage::Directory &successor, std::uint64_t trustedNow,
                                     const std::filesystem::path &privateStaging = {});
    // Pure laboratory validator. Caller-supplied input grants no authority.
    SignedEventHistory readSignedHistory(const SyncKey &key, const std::vector<events::Envelope> &input,
                                         std::uint64_t trustedNow, events::Limits limits = {});
private:
    JoinActivation verifyJoinActivation(const Identity &, const storage::Directory &, std::string,
                                        std::uint64_t, const JoinActivation *, const JoinActivationWriter &);
    PreparedClipboardEvent prepareClipboardEventLocked(const Identity &author, const SyncKey &key,
        const std::vector<SignedEventParent> &parents, const std::vector<std::string> &packedItems,
        std::uint64_t now, events::Limits limits, const Token *migration = nullptr);
    std::string publishClipboardEventLocked(std::uint64_t sequence, const SyncKey &key,
        const storage::Directory &transport, std::uint64_t now, ClipboardPublication mode,
        const std::filesystem::path &privateStaging, const Token *migration = nullptr);
    crypto::Bytes prepare(const Token &recipient, const Identity &sender, const SyncKey &key,
                         std::uint64_t now, KeyScope scope);
    std::unique_ptr<transaction::Store::Lease> lock();
    transaction::Record load();
    void save(const transaction::Record &expected, transaction::Record &replacement);
    transaction::Store &store_;
    Genesis genesis_;
    Member local_;
    std::string binding_;
    std::atomic<bool> uncertain_{false};
    std::optional<std::uint64_t> seenGeneration_;
    Token seenRecord_{};
};
} // namespace cqs::trust
