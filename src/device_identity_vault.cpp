// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_identity_vault.h"
#include "state_store.h"
#include <algorithm>
#include <sodium.h>
#include <utility>

namespace cqs::trust {
namespace {
constexpr char Domain[] = "CopyQ-Secure-Sync-device-identity-vault-lab-v1";
constexpr char Mime[] = "application/x-copyq-secure-sync-device-identity-lab-v1";
constexpr char BindingPrefix[] = "trust-identity-";

bool zero(const crypto::Bytes &bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](auto byte) { return byte == 0; });
}
bool zero(const Token &token) {
    return std::all_of(token.begin(), token.end(), [](auto byte) { return byte == 0; });
}
std::string pinHash(const IdentityVaultPins &pins) {
    if (zero(pins.group) || zero(pins.root) || !SodiumVerifier::validMember(pins.member))
        throw state::Error(state::ErrorCode::WrongBinding, "Invalid device identity vault pins");
    crypto::Bytes input(Domain, Domain + sizeof(Domain));
    for (const auto *token : {&pins.group, &pins.root, &pins.member.id,
                              &pins.member.signingKey, &pins.member.encryptionKey}) {
        input.insert(input.end(), token->begin(), token->end());
    }
    const auto hash = crypto::sha256(input);
    constexpr char Digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * hash.size());
    for (const auto byte : hash) {
        result.push_back(Digits[byte >> 4]);
        result.push_back(Digits[byte & 15]);
    }
    return result;
}
state::Limits limits() {
    state::Limits value;
    value.recordBytes = 1024;
    value.snapshot.items = 1;
    value.snapshot.formatsPerItem = 1;
    value.snapshot.mimeNameBytes = sizeof(Mime) - 1;
    value.snapshot.snapshotBytes = 256;
    return value;
}
void validateCredential(const crypto::Bytes &credential, state::Protection protection, bool initializing) {
    state::validateSecret(credential, protection);
    if ((protection == state::Protection::Key && zero(credential)) ||
        (protection == state::Protection::Password && initializing && credential.size() < 12))
        throw state::Error(state::ErrorCode::InvalidKey, "Invalid identity vault credential");
}
void wipe(transaction::Snapshot &snapshot) noexcept {
    for (auto &item : snapshot)
        for (auto &field : item) crypto::wipe(field.second);
}
void wipe(transaction::Head &head) noexcept {
    wipe(head.snapshot);
    for (auto &item : head.event.items) if (!item.empty()) sodium_memzero(item.data(), item.size());
}
// Clean the returned Record even if its shape was rejected. The shared codec
// separately owns the transient serialization and parsing buffers.
struct PrivateRecord {
    transaction::Record value;
    PrivateRecord() = default;
    explicit PrivateRecord(transaction::Record &&record) : value(std::move(record)) {}
    PrivateRecord(const PrivateRecord &) = delete;
    PrivateRecord &operator=(const PrivateRecord &) = delete;
    ~PrivateRecord() {
        if (value.local) wipe(*value.local);
        if (value.head) wipe(*value.head);
        if (value.pending) { wipe(value.pending->target); wipe(value.pending->original); }
        if (value.publication) wipe(value.publication->target);
        if (value.preserved) wipe(*value.preserved);
        for (auto &snapshot : value.archives) wipe(snapshot);
        for (auto &witness : value.witnessed) crypto::wipe(witness.second);
    }
};
const crypto::Bytes &payload(const transaction::Record &record, const std::string &hash) {
    if (record.binding != BindingPrefix + hash || record.keyIdentity != hash)
        throw state::Error(state::ErrorCode::WrongBinding, "Device identity vault pins do not match");
    if (record.schema != 2 || record.generation != 0 || record.head || record.pending ||
        record.allocatedSequence != 0 || record.publication || record.resolution ||
        !record.archives.empty() || record.preserved || !record.witnessed.empty() ||
        !record.local || record.local->size() != 1 || record.local->front().size() != 1)
        throw state::Error(state::ErrorCode::InvalidRecord, "Invalid device identity vault record");
    const auto &entry = *record.local->front().begin();
    if (entry.first != Mime || entry.second.empty())
        throw state::Error(state::ErrorCode::InvalidRecord, "Invalid device identity vault payload");
    return entry.second;
}
void requireIdentity(const Identity &identity, const IdentityVaultPins &pins) {
    if (identity.member() != pins.member)
        throw state::Error(state::ErrorCode::WrongBinding, "Device identity does not match vault pins");
}
} // namespace

std::string IdentityVault::binding(const IdentityVaultPins &pins) {
    return BindingPrefix + pinHash(pins);
}

void IdentityVault::initialize(const std::filesystem::path &directory, const IdentityVaultPins &pins,
                               const crypto::Bytes &credential, const Identity &identity,
                               state::Protection protection) {
    validateCredential(credential, protection, true);
    const auto hash = pinHash(pins);
    requireIdentity(identity, pins);
    const auto bound = BindingPrefix + hash;
    state::FileStore store(directory, bound, credential, limits(), protection);
    const auto lease = store.lock();
    if (!lease) throw state::Error(state::ErrorCode::Busy, "Device identity vault is busy");
    store.checkInitializable();

    PrivateRecord record;
    record.value.schema = 2;
    record.value.binding = bound;
    record.value.keyIdentity = hash;
    auto &item = record.value.local.emplace().emplace_back();
    item.try_emplace(Mime).first->second = identity.exportPrivate();
    store.initialize(record.value);
}

std::unique_ptr<Identity> IdentityVault::load(const std::filesystem::path &directory, const IdentityVaultPins &pins,
                                             const crypto::Bytes &credential, state::Protection protection) {
    validateCredential(credential, protection, false);
    const auto hash = pinHash(pins);
    state::FileStore store(directory, BindingPrefix + hash, credential, limits(), protection);
    const auto lease = store.lock();
    if (!lease) throw state::Error(state::ErrorCode::Busy, "Device identity vault is busy");

    const PrivateRecord record{store.load()};
    auto identity = Identity::restore(payload(record.value, hash));
    requireIdentity(*identity, pins);
    return identity;
}
} // namespace cqs::trust
