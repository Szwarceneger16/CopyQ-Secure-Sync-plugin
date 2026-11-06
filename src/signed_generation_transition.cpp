// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_generation_transition.h"

#include "packed_items.h"
#include <algorithm>
#include <iterator>
#include <sodium.h>

namespace cqs::trust {
namespace {
using crypto::Bytes;
using transaction::Snapshot;

[[noreturn]] void refuse() {
    throw JournalError(JournalCode::HistoryChanged);
}

template<class Range> void append(Bytes &out, const Range &value) {
    out.insert(out.end(), std::begin(value), std::end(value));
}

void number(Bytes &out, std::uint64_t value) {
    for (unsigned shift = 64; shift; shift -= 8)
        out.push_back(static_cast<std::uint8_t>(value >> (shift - 8)));
}

void text(Bytes &out, std::string_view value) {
    number(out, value.size());
    append(out, value);
}

Token digest(const Bytes &bytes) {
    const auto value = crypto::sha256(bytes);
    if (value.size() != Token{}.size()) refuse();
    Token result{};
    std::copy(value.begin(), value.end(), result.begin());
    return result;
}

bool equal(const Token &a, const Token &b) noexcept {
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

struct WipedBytes {
    Bytes value;
    ~WipedBytes() { crypto::wipe(value); }
};

Token localDigest(const Snapshot &snapshot) {
    packed::validateSnapshot(snapshot, {});
    WipedBytes input;
    text(input.value, "CopyQ-Secure-Sync-generation-local-v1");
    number(input.value, snapshot.size());
    for (const auto &item : snapshot) {
        number(input.value, item.size());
        for (const auto &entry : item) {
            text(input.value, entry.first);
            number(input.value, entry.second.size());
            append(input.value, entry.second);
        }
    }
    return digest(input.value);
}

void activation(Bytes &out, const JoinActivation &value) {
    text(out, value.profileBinding);
    append(out, value.group); append(out, value.root); append(out, value.head);
    append(out, value.member); append(out, value.tipDigest);
    number(out, value.generation); text(out, value.tipId);
}

void source(Bytes &out, const SignedGenerationReview &review) {
    activation(out, review.previous);
    text(out, review.sourceCursor.id); append(out, review.sourceCursor.digest);
    number(out, review.sourceGeneration); append(out, review.localDigest); number(out, review.sourceItems);
}

Token confirmation(const SignedGenerationReview &review) {
    Bytes input;
    text(input, "CopyQ-Secure-Sync-generation-review-v1");
    source(input, review); activation(input, review.successor);
    input.push_back(review.seedsEmptyGeneration ? 1 : 0);
    input.push_back(review.resumesPendingSeed ? 1 : 0);
    input.push_back(review.retiresStaleSeed ? 1 : 0);
    append(input, review.retirementDigest); append(input, review.pendingSeedDigest);
    number(input, review.pendingSeedItems); input.push_back(review.pendingSeedDiffers ? 1 : 0);
    return digest(input);
}

Token receipt(const SignedGenerationReview &review, const JoinActivation &actual) {
    Bytes input;
    text(input, "CopyQ-Secure-Sync-generation-successor-receipt-v1");
    source(input, review); activation(input, actual);
    return digest(input);
}
} // namespace

SignedGenerationReview SignedGenerationTransition::review(TrustJournal &journal, const Identity &identity,
    const storage::Directory &transport, SignedJoinCheckpoint &checkpoint, const JoinActivation &previous,
    std::string successorBinding, std::uint64_t trustedNow, bool explicitlyReviewPending) {
    const auto mounted = checkpoint.mount(previous);
    if (mounted->replica().pending) refuse();
    const auto target = journal.preflightGenerationActivation(identity, transport, previous,
        std::move(successorBinding), trustedNow, &mounted->snapshot(), explicitlyReviewPending);
    SignedGenerationReview result;
    result.previous = previous;
    result.successor = target.activation;
    result.sourceCursor = mounted->replica().cursor;
    result.sourceGeneration = mounted->generation();
    result.localDigest = localDigest(mounted->snapshot());
    result.sourceItems = mounted->snapshot().size();
    result.seedsEmptyGeneration = target.seed;
    result.resumesPendingSeed = target.resuming;
    result.retiresStaleSeed = target.retiresStaleSeed;
    result.retirementDigest = target.retirementDigest;
    result.pendingSeedDigest = target.seedDigest;
    result.pendingSeedItems = target.seedItems;
    result.pendingSeedDiffers = target.pendingSnapshotDiffers;
    result.confirmation = confirmation(result);
    return result;
}

void SignedGenerationTransition::apply(TrustJournal &journal, const Identity &identity,
    const storage::Directory &transport, SignedJoinCheckpoint &sourceCheckpoint, SignedJoinCheckpoint &destination,
    const SignedGenerationReview &reviewed, const Token &confirmed, std::uint64_t trustedNow,
    const std::function<void(const JoinActivation &)> &activate, const std::filesystem::path &privateStaging,
    const SignedReplicaTargetValidator &validateTarget) {
    if (!activate || confirmed == Token{} || !equal(confirmed, reviewed.confirmation) ||
        !equal(confirmed, confirmation(reviewed))) refuse();
    const auto mounted = sourceCheckpoint.mount(reviewed.previous);
    const auto &local = mounted->snapshot();
    const auto &replica = mounted->replica();
    if (replica.pending || mounted->generation() != reviewed.sourceGeneration || local.size() != reviewed.sourceItems ||
        replica.cursor.id != reviewed.sourceCursor.id || !equal(replica.cursor.digest, reviewed.sourceCursor.digest) ||
        !equal(localDigest(local), reviewed.localDigest)) refuse();
    const SignedGenerationTarget target{reviewed.successor, reviewed.seedsEmptyGeneration,
        reviewed.resumesPendingSeed, reviewed.retiresStaleSeed, reviewed.retirementDigest,
        reviewed.pendingSeedDigest, reviewed.pendingSeedItems, reviewed.pendingSeedDiffers};
    journal.applyGenerationActivation(identity, transport, reviewed.previous, target, confirmed, local, trustedNow,
        [&](const JoinActivation &actual, const events::Event &tip, const Snapshot &snapshot) {
            destination.applySuccessor(actual, tip, snapshot, local, receipt(reviewed, actual));
            activate(actual);
        }, privateStaging, [&](const Snapshot &oldLocal, const Snapshot &targetSnapshot) {
            if (validateTarget) validateTarget(oldLocal, targetSnapshot);
            destination.checkSuccessorCapacity(reviewed.successor, targetSnapshot, oldLocal);
        });
}
} // namespace cqs::trust
