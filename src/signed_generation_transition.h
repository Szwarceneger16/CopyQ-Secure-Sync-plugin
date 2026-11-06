// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "signed_join_checkpoint.h"

namespace cqs::trust {
struct SignedGenerationReview {
    JoinActivation previous;
    JoinActivation successor;
    SignedReplicaCursor sourceCursor;
    std::uint64_t sourceGeneration = 0;
    Token localDigest{}, confirmation{};
    std::size_t sourceItems = 0;
    bool seedsEmptyGeneration = false;
    bool resumesPendingSeed = false;
    bool retiresStaleSeed = false;
    Token retirementDigest{}, pendingSeedDigest{};
    std::size_t pendingSeedItems = 0;
    bool pendingSeedDiffers = false;
};

// An explicit local adoption into a separate encrypted checkpoint. Signed
// events from different key generations do not claim cryptographic ancestry.
class SignedGenerationTransition final {
public:
    // A ready packet may contain an earlier local snapshot. The opt-in review
    // exposes its exact fingerprint/count for separate user consent; default
    // review refuses a mismatch. No preflight publishes clipboard data.
    static SignedGenerationReview review(TrustJournal &journal, const Identity &identity,
        const storage::Directory &transport, SignedJoinCheckpoint &source, const JoinActivation &previous,
        std::string successorBinding, std::uint64_t trustedNow, bool explicitlyReviewPending = false);
    // The activation callback runs while both the journal operation and old
    // checkpoint session are held. Persist the active profile atomically there.
    static void apply(TrustJournal &journal, const Identity &identity, const storage::Directory &transport,
        SignedJoinCheckpoint &source, SignedJoinCheckpoint &destination, const SignedGenerationReview &review,
        const Token &confirmed, std::uint64_t trustedNow,
        const std::function<void(const JoinActivation &)> &activate,
        const std::filesystem::path &privateStaging = {}, const SignedReplicaTargetValidator &validateTarget = {});
};
} // namespace cqs::trust
