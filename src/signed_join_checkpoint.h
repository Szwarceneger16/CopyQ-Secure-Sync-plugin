// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "device_trust_journal.h"
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

        const transaction::Snapshot &snapshot() const noexcept;
        std::uint64_t generation() const noexcept;
        // Serialize access to the handle. A save with an unconfirmed outcome
        // requires releasing the handle and reopening the checkpoint.
        void save(const transaction::Snapshot &snapshot, std::uint64_t expectedGeneration);

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
    // Read the immutable snapshot confirmed by the original signed Join.
    transaction::Snapshot read(const JoinActivation &expected);
    // Open the editable local snapshot and hold the exclusive session lease.
    std::unique_ptr<Mounted> mount(const JoinActivation &expected);

private:
    std::shared_ptr<Backing> backing_;
};

} // namespace cqs::trust
