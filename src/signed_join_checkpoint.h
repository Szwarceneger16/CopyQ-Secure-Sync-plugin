// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "device_trust_journal.h"
#include <cstddef>
#include <cstdint>
#include <memory>

namespace cqs::trust {

// Experimental encrypted destination for an explicit signed Join. The
// caller must provision a separate private directory outside transport and
// call apply() only from the freshly revalidated trust-journal operation.
class SignedJoinCheckpoint final {
    struct Backing;

public:
    class Mounted final {
    public:
        ~Mounted();
        Mounted(const Mounted &) = delete;
        Mounted &operator=(const Mounted &) = delete;

        // References describe the current confirmed record. Copy a snapshot
        // before holding it across a call that can update the checkpoint.
        const transaction::Snapshot &snapshot() const noexcept;
        const SignedReplicaState &replica() const noexcept;
        std::uint64_t generation() const noexcept;
        // Serialize access to the handle. A save with an unconfirmed outcome
        // requires releasing the handle and reopening the checkpoint.
        void save(const transaction::Snapshot &snapshot, std::uint64_t expectedGeneration);
        // The journal coordinator validates history and intent transitions.
        // This update atomically stores the cursor, intent and local view.
        void updateReplica(const SignedReplicaState &replica, const transaction::Snapshot &snapshot,
                           std::uint64_t expectedGeneration);
        // Preflight the post-resolution record before reserving any packet.
        // The first remote-selection intent also commits the backup atomically.
        void checkConflictBackupCapacity(const transaction::Snapshot &target) const;
        std::size_t conflictBackupCount() const noexcept;
        const transaction::Snapshot &conflictBackup(std::size_t index) const;
        // Restore swaps the selected backup and current local snapshot.
        // Neither operation changes the signed cursor or works during a pending publication.
        void restoreConflictBackup(std::size_t index, std::uint64_t expectedGeneration);
        void discardConflictBackup(std::size_t index, std::uint64_t expectedGeneration);

    private:
        friend class SignedJoinCheckpoint;
        struct Impl;
        explicit Mounted(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };

    SignedJoinCheckpoint(const std::filesystem::path &privateDirectory,
                         const crypto::Bytes &localCredential, std::string profileBinding,
                         state::Protection protection = state::Protection::Key);
    SignedJoinCheckpoint(const SignedJoinCheckpoint &) = delete;
    SignedJoinCheckpoint &operator=(const SignedJoinCheckpoint &) = delete;
    void apply(const JoinActivation &verified, const events::Event &tip,
               const transaction::Snapshot &snapshot);
    // A reviewed generation transition creates a separate checkpoint and
    // retains the old local view as an encrypted backup in the same commit.
    // Call only inside the revalidated journal activation callback.
    void applySuccessor(const JoinActivation &verified, const events::Event &tip,
        const transaction::Snapshot &snapshot, const transaction::Snapshot &previousLocal,
        const Token &transitionReceipt);
    // Serialize the complete successor and retained source before publishing
    // a new-generation Seed. A zero provisional wire digest is size-checked.
    void checkSuccessorCapacity(const JoinActivation &provisional, const transaction::Snapshot &snapshot,
        const transaction::Snapshot &previousLocal) const;
    // Read the immutable snapshot confirmed by the original signed Join.
    transaction::Snapshot read(const JoinActivation &expected);
    // Open the editable local snapshot and hold the exclusive session lease.
    std::unique_ptr<Mounted> mount(const JoinActivation &expected);

private:
    std::shared_ptr<Backing> backing_;
};

} // namespace cqs::trust
