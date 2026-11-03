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
// Schema 3 keeps the Join snapshot in local. After the first edit, schema 5
// keeps the original in its single archive and the editable view in local.
constexpr unsigned InitialSchema = 3;
constexpr unsigned EditableSchema = 5;

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
    WipedRecord() = default;
    explicit WipedRecord(Record record) : value(std::move(record)) {}
    WipedRecord(WipedRecord &&) = default;
    WipedRecord(const WipedRecord &) = delete;
    WipedRecord &operator=(const WipedRecord &) = delete;
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
    const bool initial = record.schema == InitialSchema && record.archives.empty();
    const bool edited = record.schema == EditableSchema && record.archives.size() == 1 && record.generation >= 2;
    if ((!initial && !edited) || record.binding != binding || !record.generation || !record.local ||
        record.keyIdentity != identity || record.preserved != proof || record.head || record.pending ||
        record.allocatedSequence || record.publication || record.resolution || !record.witnessed.empty()) refuse();
}

Snapshot &originalSnapshot(Record &record) {
    return record.archives.empty() ? *record.local : record.archives.front();
}

// All other fields are checked by checkRecord().
bool sameCheckpoint(const Record &a, const Record &b) {
    return a.schema == b.schema && a.generation == b.generation && a.local == b.local && a.archives == b.archives;
}

std::uint64_t nextGeneration(std::uint64_t generation) {
    if (generation == std::numeric_limits<std::uint64_t>::max())
        throw state::Error(state::ErrorCode::Generation, "Signed Join checkpoint generation exhausted");
    return generation + 1;
}

[[noreturn]] void unconfirmed() {
    throw state::Error(state::ErrorCode::CommitUnconfirmed, "Signed Join checkpoint readback did not match");
}

WipedRecord confirm(state::FileStore &store, const Record &wanted) {
    try {
        WipedRecord actual{store.load()};
        checkRecord(actual.value, wanted.binding, *wanted.preserved, wanted.keyIdentity);
        if (sameCheckpoint(actual.value, wanted)) return actual;
    } catch (...) {
        unconfirmed();
    }
    unconfirmed();
}
} // namespace

struct SignedJoinCheckpoint::Backing {
    std::string profileBinding;
    std::string binding;
    state::FileStore session;
    state::FileStore store;

    Backing(const std::filesystem::path &directory, const Bytes &credential, std::string profile,
            state::Protection protection)
        : profileBinding(std::move(profile)), binding(checkpointBinding(directory, profileBinding)),
          session(directory, binding, Bytes(32), {}, state::Protection::Key, state::LeaseKind::Session),
          store(directory, binding, credential, {}, protection) {}
};

struct SignedJoinCheckpoint::Mounted::Impl {
    std::shared_ptr<Backing> backing;
    std::unique_ptr<transaction::Store::Lease> session;
    WipedRecord checkpoint;
    bool uncertain = false;

    Impl(std::shared_ptr<Backing> storage, std::unique_ptr<transaction::Store::Lease> lease, WipedRecord record)
        : backing(std::move(storage)), session(std::move(lease)), checkpoint(std::move(record)) {}
};

SignedJoinCheckpoint::SignedJoinCheckpoint(const std::filesystem::path &privateDirectory,
    const Bytes &localCredential, std::string profileBinding, state::Protection protection)
    : backing_(std::make_shared<Backing>(privateDirectory, localCredential, std::move(profileBinding), protection)) {}

void SignedJoinCheckpoint::apply(const JoinActivation &verified, const events::Event &tip, const Snapshot &snapshot) {
    auto &backing = *backing_;
    const auto proofBytes = descriptor(verified, backing.profileBinding);
    const auto identity = digestHex(proofBytes);
    const Snapshot proof{{{DescriptorMime, proofBytes}}};
    if (tip.revision.id != verified.tipId) refuse();
    history::validateRevision(tip.revision);
    const WipedSnapshot decoded{packed::decode(tip.items)};
    if (decoded.value != snapshot) refuse();

    const auto session = lock(backing.session);
    const auto lease = lock(backing.store);
    WipedRecord current{};
    bool missing = false;
    try {
        current.value = backing.store.load();
    } catch (const state::Error &error) {
        if (error.code() != state::ErrorCode::Missing) throw;
        missing = true;
    }
    if (missing) {
        WipedRecord wanted{{InitialSchema, backing.binding, 1, {}, {}, snapshot, identity}};
        wanted.value.preserved = proof;
        backing.store.initialize(wanted.value);
        (void)confirm(backing.store, wanted.value);
    } else {
        checkRecord(current.value, backing.binding, proof, identity);
        if (originalSnapshot(current.value) != snapshot) refuse();
        WipedRecord wanted{current.value};
        wanted.value.generation = nextGeneration(current.value.generation);
        backing.store.commit(current.value, wanted.value);
        (void)confirm(backing.store, wanted.value);
    }
}

Snapshot SignedJoinCheckpoint::read(const JoinActivation &expected) {
    auto &backing = *backing_;
    const auto proofBytes = descriptor(expected, backing.profileBinding);
    const Snapshot proof{{{DescriptorMime, proofBytes}}};
    const auto session = lock(backing.session);
    const auto lease = lock(backing.store);
    WipedRecord actual{backing.store.load()};
    checkRecord(actual.value, backing.binding, proof, digestHex(proofBytes));
    auto &original = originalSnapshot(actual.value);
    packed::validateSnapshot(original, {});
    return std::move(original);
}

std::unique_ptr<SignedJoinCheckpoint::Mounted> SignedJoinCheckpoint::mount(const JoinActivation &expected) {
    auto &backing = *backing_;
    const auto proofBytes = descriptor(expected, backing.profileBinding);
    const Snapshot proof{{{DescriptorMime, proofBytes}}};
    auto session = lock(backing.session);
    const auto lease = lock(backing.store);
    WipedRecord actual{backing.store.load()};
    checkRecord(actual.value, backing.binding, proof, digestHex(proofBytes));
    packed::validateSnapshot(*actual.value.local, {});
    if (!actual.value.archives.empty()) packed::validateSnapshot(actual.value.archives.front(), {});
    return std::unique_ptr<Mounted>(new Mounted(
        std::make_unique<Mounted::Impl>(backing_, std::move(session), std::move(actual))));
}

SignedJoinCheckpoint::Mounted::Mounted(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

SignedJoinCheckpoint::Mounted::~Mounted() = default;

const Snapshot &SignedJoinCheckpoint::Mounted::snapshot() const noexcept {
    return *impl_->checkpoint.value.local;
}

std::uint64_t SignedJoinCheckpoint::Mounted::generation() const noexcept {
    return impl_->checkpoint.value.generation;
}

void SignedJoinCheckpoint::Mounted::save(const Snapshot &snapshot, std::uint64_t expectedGeneration) {
    if (impl_->uncertain) unconfirmed();
    auto &cached = impl_->checkpoint.value;
    if (expectedGeneration != cached.generation)
        throw state::Error(state::ErrorCode::Stale, "Signed Join checkpoint mount generation changed");
    packed::validateSnapshot(snapshot, {});
    auto &store = impl_->backing->store;
    const auto lease = lock(store);
    if (snapshot == *cached.local) {
        const WipedRecord current{store.load()};
        checkRecord(current.value, cached.binding, *cached.preserved, cached.keyIdentity);
        if (!sameCheckpoint(current.value, cached))
            throw state::Error(state::ErrorCode::Stale, "Signed Join checkpoint changed since mount");
        return;
    }

    WipedRecord wanted{{EditableSchema, cached.binding, nextGeneration(cached.generation), {}, {}, snapshot, cached.keyIdentity}};
    wanted.value.preserved = cached.preserved;
    wanted.value.archives.push_back(originalSnapshot(cached));
    try {
        store.commit(cached, wanted.value);
    } catch (const state::Error &error) {
        if (error.code() == state::ErrorCode::CommitUnconfirmed) impl_->uncertain = true;
        throw;
    }
    impl_->uncertain = true;
    auto actual = confirm(store, wanted.value);
    std::swap(cached, actual.value);
    impl_->uncertain = false;
}
} // namespace cqs::trust
