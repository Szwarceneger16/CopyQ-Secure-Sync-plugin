// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_archive_migration.h"
#include "device_trust_journal.h"
#include "packed_items.h"
#include "state_record.h"
#include "storage.h"
#include <iterator>
#include <sodium.h>
#include <utility>

namespace cqs::trust {
namespace {
using crypto::Bytes;
constexpr char KeyIdentityDomain[] = "CopyQ-Secure-Sync-key-identity-v1";
constexpr char ProofKeyDomain[] = "CopyQ-Secure-Sync-legacy-archive-proof-key-lab-v1";
constexpr char ArchiveDomain[] = "CopyQ-Secure-Sync-legacy-archive-proof-lab-v1";
constexpr char ConfirmationDomain[] = "CopyQ-Secure-Sync-legacy-archive-confirmation-lab-v1";

[[noreturn]] void refuse() { throw JournalError(JournalCode::Migration); }

template<class Range> void append(Bytes &output, const Range &value) {
    output.insert(output.end(), std::begin(value), std::end(value));
}
void u64(Bytes &output, std::uint64_t value) {
    for (unsigned shift = 64; shift; shift -= 8) output.push_back(static_cast<std::uint8_t>(value >> (shift - 8)));
}
void wipe(std::vector<std::string> &items) noexcept {
    for (auto &item : items) if (!item.empty()) sodium_memzero(item.data(), item.size());
}
void wipe(transaction::Snapshot &snapshot) noexcept {
    for (auto &item : snapshot) for (auto &field : item) crypto::wipe(field.second);
}
void wipe(transaction::Head &head) noexcept {
    wipe(head.event.items);
    wipe(head.snapshot);
}
struct WipedBytes {
    Bytes value;
    ~WipedBytes() { crypto::wipe(value); }
};
struct WipedToken {
    Token value;
    ~WipedToken() { sodium_memzero(value.data(), value.size()); }
};
struct WipedSnapshot {
    transaction::Snapshot value;
    ~WipedSnapshot() { wipe(value); }
};
struct WipedRecord {
    transaction::Record value;
    ~WipedRecord() {
        if (value.head) wipe(*value.head);
        if (value.local) wipe(*value.local);
        if (value.pending) { wipe(value.pending->target); wipe(value.pending->original); }
        if (value.publication) wipe(value.publication->target);
        if (value.preserved) wipe(*value.preserved);
        for (auto &snapshot : value.archives) wipe(snapshot);
        for (auto &witness : value.witnessed) crypto::wipe(witness.second);
    }
};
struct WipedHistory {
    events::AuthenticatedHistory value;
    ~WipedHistory() {
        // The authenticated result is owned and mutable here. Its public
        // view is const to protect consistency with the graph and fingerprints.
        for (const auto &event : value.events())
            wipe(const_cast<std::vector<std::string> &>(event.items));
        for (const auto &entry : value.fingerprints()) crypto::wipe(const_cast<Bytes &>(entry.second));
    }
};
Token mac(const Bytes &input, const std::uint8_t *key) {
    static_assert(crypto_auth_hmacsha256_KEYBYTES == SyncKey::Size && crypto_auth_hmacsha256_BYTES == Token{}.size(),
                  "Migration proof HMAC sizes changed");
    Token result{};
    if (sodium_init() < 0 || crypto_auth_hmacsha256(result.data(), input.data(), input.size(), key) != 0) refuse();
    return result;
}
} // namespace

std::string legacyArchiveKeyIdentity(const Bytes &legacyKey) {
    if (legacyKey.size() != SyncKey::Size) refuse();
    WipedBytes input;
    append(input.value, KeyIdentityDomain);
    append(input.value, legacyKey);
    const auto digest = crypto::sha256(input.value);
    if (digest.size() != Token{}.size()) refuse();
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * digest.size());
    for (auto byte : digest) { result.push_back(digits[byte >> 4]); result.push_back(digits[byte & 15]); }
    return result;
}

VerifiedLegacyArchive::VerifiedLegacyArchive(const LegacyArchiveSource &source) {
    state::validateBinding(source.binding);
    const auto keyIdentity = legacyArchiveKeyIdentity(source.legacyKey);
    lease_ = source.store.lock();
    if (!lease_) throw JournalError(JournalCode::Busy);
    WipedRecord record{source.store.load()};
    auto &r = record.value;
    if (r.binding != source.binding || r.keyIdentity != keyIdentity || r.schema != 6 ||
        !r.head || !r.local || r.pending || r.publication || r.resolution || r.head->snapshot != *r.local)
        refuse();

    WipedHistory history{source.transport.scan(source.legacyKey)};
    transaction::verifyHistory(r, history.value);
    const auto &tips = history.value.graph().tips();
    if (tips.size() != 1 || tips.front() != r.head->event.revision.id ||
        r.witnessed != history.value.fingerprints()) refuse();
    WipedSnapshot decoded{packed::decode(r.head->event.items)};
    if (decoded.value != r.head->snapshot) refuse();

    WipedBytes recordBytes{state::serialize(r)};
    const WipedToken proofKey{mac(Bytes(ProofKeyDomain, ProofKeyDomain + sizeof(ProofKeyDomain)),
                                 source.legacyKey.data())};
    const WipedToken recordDigest{mac(recordBytes.value, proofKey.value.data())};
    WipedBytes proof;
    append(proof.value, ArchiveDomain);
    append(proof.value, recordDigest.value);
    const auto &fingerprints = history.value.fingerprints();
    u64(proof.value, fingerprints.size());
    for (const auto &[id, digest] : fingerprints) {
        u64(proof.value, id.size());
        append(proof.value, id);
        append(proof.value, digest);
    }
    archiveDigest_ = mac(proof.value, proofKey.value.data());
    proofKey_ = proofKey.value;
    items_ = std::move(r.head->event.items);
}

VerifiedLegacyArchive::~VerifiedLegacyArchive() {
    wipe(items_);
    sodium_memzero(proofKey_.data(), proofKey_.size());
    sodium_memzero(archiveDigest_.data(), archiveDigest_.size());
}

Token VerifiedLegacyArchive::confirmation(const SignedEventContext &successor) const {
    WipedBytes proof;
    append(proof.value, ConfirmationDomain);
    append(proof.value, archiveDigest_);
    append(proof.value, successor.group);
    append(proof.value, successor.root);
    u64(proof.value, successor.generation);
    append(proof.value, successor.commitment);
    append(proof.value, successor.author);
    return mac(proof.value, proofKey_.data());
}
} // namespace cqs::trust
