// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_join_checkpoint.h"

#include "packed_items.h"
#include "storage.h"
#include <iterator>
#include <limits>
#include <sodium.h>
#include <utility>

namespace cqs::trust {
namespace {
using crypto::Bytes;
using transaction::Record;
using transaction::Snapshot;

constexpr char BindingDomain[] = "CopyQ-Secure-Sync-signed-join-checkpoint-binding-lab-v1";
constexpr char DescriptorDomain[] = "CopyQ-Secure-Sync-signed-join-checkpoint-proof-lab-v1";
constexpr char DescriptorMime[] = "application/x-copyq-secure-sync-signed-join-checkpoint-lab-v1";

[[noreturn]] void refuse() {
    throw state::Error(state::ErrorCode::InvalidRecord, "Signed Join checkpoint does not match the confirmed profile and tip");
}

template<class Range>
void append(Bytes &out, const Range &value) {
    out.insert(out.end(), std::begin(value), std::end(value));
}

void appendNumber(Bytes &out, std::uint64_t value) {
    for (unsigned shift = 64; shift; shift -= 8)
        out.push_back(static_cast<std::uint8_t>(value >> (shift - 8)));
}

void appendText(Bytes &out, std::string_view value) {
    appendNumber(out, value.size());
    append(out, value);
}

std::string digestHex(const Bytes &value) {
    const auto digest = crypto::sha256(value);
    if (digest.size() != Token{}.size()) refuse();
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * digest.size());
    for (auto byte : digest) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

std::string checkpointBinding(const std::filesystem::path &directory, const std::string &profile) {
    state::validateBinding(profile);
    Bytes input;
    append(input, BindingDomain);
    appendText(input, directory.generic_u8string());
    appendText(input, profile);
    return "CqsSignedJoinCheckpoint-" + digestHex(input);
}

Bytes descriptor(const JoinActivation &verified, const std::string &profile) {
    if (verified.profileBinding != profile || !storage::validSignedEventId(verified.tipId) ||
        verified.group == Token{} || verified.root == Token{} || verified.head == Token{} ||
        verified.member == Token{} || verified.tipDigest == Token{}) refuse();
    Bytes proof;
    append(proof, DescriptorDomain);
    appendText(proof, profile);
    append(proof, verified.group);
    append(proof, verified.root);
    append(proof, verified.head);
    append(proof, verified.member);
    appendNumber(proof, verified.generation);
    append(proof, verified.tipDigest);
    appendText(proof, verified.tipId);
    return proof;
}

void wipe(Snapshot &snapshot) noexcept {
    for (auto &item : snapshot)
        for (auto &field : item) crypto::wipe(field.second);
}

void wipe(transaction::Head &head) noexcept {
    for (auto &item : head.event.items)
        if (!item.empty()) sodium_memzero(item.data(), item.size());
    wipe(head.snapshot);
}

struct WipedSnapshot {
    Snapshot value;
    ~WipedSnapshot() { wipe(value); }
};

struct WipedRecord {
    Record value;
    ~WipedRecord() {
        if (value.local) wipe(*value.local);
        if (value.head) wipe(*value.head);
        if (value.pending) {
            wipe(value.pending->target);
            wipe(value.pending->original);
        }
        if (value.publication) wipe(value.publication->target);
        if (value.preserved) wipe(*value.preserved);
        for (auto &archive : value.archives) wipe(archive);
    }
};

std::unique_ptr<transaction::Store::Lease> lock(state::FileStore &store) {
    auto lease = store.lock();
    if (!lease) throw state::Error(state::ErrorCode::Busy, "Signed Join profile is busy");
    return lease;
}

void checkRecord(const Record &record, const std::string &binding, const Snapshot &proof, const std::string &identity) {
    if (record.schema != 3 || record.binding != binding || !record.generation || !record.local ||
        record.keyIdentity != identity || record.preserved != proof || record.head || record.pending ||
        record.allocatedSequence || record.publication || record.resolution || !record.archives.empty() ||
        !record.witnessed.empty()) refuse();
}
} // namespace

SignedJoinCheckpoint::SignedJoinCheckpoint(const std::filesystem::path &privateDirectory,
    const Bytes &localCredential, std::string profileBinding, state::Protection protection)
    : profileBinding_(std::move(profileBinding)), binding_(checkpointBinding(privateDirectory, profileBinding_)),
      session_(privateDirectory, binding_, Bytes(32), {}, state::Protection::Key, state::LeaseKind::Session),
      store_(privateDirectory, binding_, localCredential, {}, protection) {}

void SignedJoinCheckpoint::apply(const JoinActivation &verified, const events::Event &tip, const Snapshot &snapshot) {
    const auto proofBytes = descriptor(verified, profileBinding_);
    const auto identity = digestHex(proofBytes);
    const Snapshot proof{{{DescriptorMime, proofBytes}}};
    if (tip.revision.id != verified.tipId) refuse();
    history::validateRevision(tip.revision);
    const WipedSnapshot decoded{packed::decode(tip.items)};
    if (decoded.value != snapshot) refuse();

    const auto session = lock(session_);
    const auto lease = lock(store_);
    WipedRecord wanted{{3, binding_, 1, {}, {}, snapshot, identity}};
    wanted.value.preserved = proof;
    WipedRecord current{};
    bool missing = false;
    try {
        current.value = store_.load();
    } catch (const state::Error &error) {
        if (error.code() != state::ErrorCode::Missing) throw;
        missing = true;
    }
    if (missing) {
        store_.initialize(wanted.value);
    } else {
        checkRecord(current.value, binding_, proof, identity);
        if (*current.value.local != snapshot) refuse();
        if (current.value.generation == std::numeric_limits<std::uint64_t>::max())
            throw state::Error(state::ErrorCode::Generation, "Signed Join checkpoint generation exhausted");
        wanted.value.generation = current.value.generation + 1;
        store_.commit(current.value, wanted.value);
    }
    const WipedRecord actual{store_.load()};
    checkRecord(actual.value, binding_, proof, identity);
    if (actual.value.generation != wanted.value.generation || *actual.value.local != snapshot)
        throw state::Error(state::ErrorCode::CommitUnconfirmed, "Signed Join checkpoint readback did not match");
}

Snapshot SignedJoinCheckpoint::read(const JoinActivation &expected) {
    const auto proofBytes = descriptor(expected, profileBinding_);
    const Snapshot proof{{{DescriptorMime, proofBytes}}};
    const auto session = lock(session_);
    const auto lease = lock(store_);
    WipedRecord actual{store_.load()};
    checkRecord(actual.value, binding_, proof, digestHex(proofBytes));
    packed::validateSnapshot(*actual.value.local, {});
    return std::move(*actual.value.local);
}
} // namespace cqs::trust
