// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_join_checkpoint.h"

#include "packed_items.h"
#include "storage.h"
#include <algorithm>
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
constexpr char ReplicaMime[] = "application/x-copyq-secure-sync-signed-replica-lab-v1";
// Schema 3 keeps the Join snapshot in local. After the first edit, schema 5
// keeps the original in its single archive. Schema 6 adds replica metadata
// alongside the original proof in the authenticated preserved field.
constexpr unsigned InitialSchema = 3;
constexpr unsigned EditableSchema = 5;
constexpr unsigned ReplicaSchema = 6;
constexpr std::size_t ReplicaIdBytes = 45;

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

Bytes replicaDescriptor(const SignedReplicaState &replica) {
    if (!storage::validSignedEventId(replica.cursor.id) || replica.cursor.digest == Token{} ||
        (replica.pending && (!replica.pending->sequence || replica.pending->sequence > history::MaxSequence ||
                             replica.pending->payload == Token{}))) refuse();
    Bytes bytes;
    // The fixed-width event ID and digest are followed by a big-endian
    // sequence. Zero denotes absence and carries no payload fingerprint.
    append(bytes, replica.cursor.id);
    append(bytes, replica.cursor.digest);
    appendNumber(bytes, replica.pending ? replica.pending->sequence : 0);
    if (replica.pending) append(bytes, replica.pending->payload);
    return bytes;
}

SignedReplicaState decodeReplica(const Bytes &bytes) {
    constexpr auto tokenBytes = Token{}.size();
    constexpr auto baseSize = ReplicaIdBytes + tokenBytes + sizeof(std::uint64_t);
    if (bytes.size() != baseSize && bytes.size() != baseSize + tokenBytes) refuse();
    SignedReplicaState replica{{std::string(bytes.begin(), bytes.begin() + ReplicaIdBytes), {}}, {}};
    std::copy_n(bytes.begin() + ReplicaIdBytes, tokenBytes, replica.cursor.digest.begin());
    std::uint64_t sequence = 0;
    for (auto i = ReplicaIdBytes + tokenBytes; i < baseSize; ++i) sequence = (sequence << 8) | bytes[i];
    if (bytes.size() != baseSize) {
        replica.pending = SignedReplicaIntent{sequence, {}};
        std::copy_n(bytes.begin() + baseSize, tokenBytes, replica.pending->payload.begin());
    }
    if (replicaDescriptor(replica) != bytes) refuse();
    return replica;
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

SignedReplicaState checkRecord(const Record &record, const std::string &binding, const Bytes &proof,
                               const JoinActivation &expected) {
    const bool initial = record.schema == InitialSchema && record.archives.empty();
    const bool edited = (record.schema == EditableSchema || record.schema == ReplicaSchema) &&
                        record.archives.size() == 1 && record.generation >= 2;
    if ((!initial && !edited) || record.binding != binding || !record.generation || !record.local ||
        record.keyIdentity != digestHex(proof) || !record.preserved || record.preserved->size() != 1 ||
        record.head || record.pending ||
        record.allocatedSequence || record.publication || record.resolution || !record.witnessed.empty()) refuse();
    const auto &metadata = record.preserved->front();
    const bool replicated = record.schema == ReplicaSchema;
    const auto descriptor = metadata.find(DescriptorMime);
    if (metadata.size() != (replicated ? 2u : 1u) || descriptor == metadata.end() ||
        descriptor->second != proof) refuse();
    if (!replicated) return {{expected.tipId, expected.tipDigest}, {}};
    const auto replica = metadata.find(ReplicaMime);
    if (replica == metadata.end()) refuse();
    return decodeReplica(replica->second);
}

Snapshot &originalSnapshot(Record &record) {
    return record.archives.empty() ? *record.local : record.archives.front();
}

// The expected record was validated on mount or assembled by this adapter.
bool sameCheckpoint(const Record &actual, const Record &expected) {
    return actual.schema == expected.schema && actual.binding == expected.binding &&
           actual.generation == expected.generation && actual.keyIdentity == expected.keyIdentity &&
           actual.local == expected.local && actual.archives == expected.archives && actual.preserved == expected.preserved &&
           !actual.head && !actual.pending && !actual.allocatedSequence &&
           !actual.publication && !actual.resolution && actual.witnessed.empty();
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
    SignedReplicaState replica;
    bool uncertain = false;

    Impl(std::shared_ptr<Backing> storage, std::unique_ptr<transaction::Store::Lease> lease,
         WipedRecord record, SignedReplicaState state)
        : backing(std::move(storage)), session(std::move(lease)), checkpoint(std::move(record)), replica(std::move(state)) {}
};

SignedJoinCheckpoint::SignedJoinCheckpoint(const std::filesystem::path &privateDirectory,
    const Bytes &localCredential, std::string profileBinding, state::Protection protection)
    : backing_(std::make_shared<Backing>(privateDirectory, localCredential, std::move(profileBinding), protection)) {}

void SignedJoinCheckpoint::apply(const JoinActivation &verified, const events::Event &tip, const Snapshot &snapshot) {
    auto &backing = *backing_;
    const auto proofBytes = descriptor(verified, backing.profileBinding);
    const auto identity = digestHex(proofBytes);
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
        wanted.value.preserved = Snapshot{{{DescriptorMime, proofBytes}}};
        backing.store.initialize(wanted.value);
        (void)confirm(backing.store, wanted.value);
    } else {
        (void)checkRecord(current.value, backing.binding, proofBytes, verified);
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
    const auto session = lock(backing.session);
    const auto lease = lock(backing.store);
    WipedRecord actual{backing.store.load()};
    (void)checkRecord(actual.value, backing.binding, proofBytes, expected);
    auto &original = originalSnapshot(actual.value);
    packed::validateSnapshot(original, {});
    return std::move(original);
}

std::unique_ptr<SignedJoinCheckpoint::Mounted> SignedJoinCheckpoint::mount(const JoinActivation &expected) {
    auto &backing = *backing_;
    const auto proofBytes = descriptor(expected, backing.profileBinding);
    auto session = lock(backing.session);
    const auto lease = lock(backing.store);
    WipedRecord actual{backing.store.load()};
    auto replica = checkRecord(actual.value, backing.binding, proofBytes, expected);
    packed::validateSnapshot(*actual.value.local, {});
    if (!actual.value.archives.empty()) packed::validateSnapshot(actual.value.archives.front(), {});
    return std::unique_ptr<Mounted>(new Mounted(
        std::make_unique<Mounted::Impl>(backing_, std::move(session), std::move(actual), std::move(replica))));
}

SignedJoinCheckpoint::Mounted::Mounted(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

SignedJoinCheckpoint::Mounted::~Mounted() = default;

const Snapshot &SignedJoinCheckpoint::Mounted::snapshot() const noexcept {
    return *impl_->checkpoint.value.local;
}

const SignedReplicaState &SignedJoinCheckpoint::Mounted::replica() const noexcept {
    return impl_->replica;
}

std::uint64_t SignedJoinCheckpoint::Mounted::generation() const noexcept {
    return impl_->checkpoint.value.generation;
}

void SignedJoinCheckpoint::Mounted::save(const Snapshot &snapshot, std::uint64_t expectedGeneration) {
    updateReplica(impl_->replica, snapshot, expectedGeneration);
}

void SignedJoinCheckpoint::Mounted::updateReplica(const SignedReplicaState &replica, const Snapshot &snapshot,
                                                   std::uint64_t expectedGeneration) {
    if (impl_->uncertain) unconfirmed();
    auto &cached = impl_->checkpoint.value;
    if (expectedGeneration != cached.generation)
        throw state::Error(state::ErrorCode::Stale, "Signed Join checkpoint mount generation changed");
    packed::validateSnapshot(snapshot, {});
    auto replicaBytes = replicaDescriptor(replica);
    const bool replicaChanged = replicaBytes != replicaDescriptor(impl_->replica);
    auto &store = impl_->backing->store;
    const auto lease = lock(store);
    if (!replicaChanged && snapshot == *cached.local) {
        const WipedRecord current{store.load()};
        if (!sameCheckpoint(current.value, cached))
            throw state::Error(state::ErrorCode::Stale, "Signed Join checkpoint changed since mount");
        return;
    }

    const bool replicated = replicaChanged || cached.schema == ReplicaSchema;
    auto accepted = replica;
    WipedRecord wanted{{replicated ? ReplicaSchema : EditableSchema, cached.binding,
                         nextGeneration(cached.generation), {}, {}, snapshot, cached.keyIdentity}};
    wanted.value.preserved = cached.preserved;
    if (replicated) wanted.value.preserved->front()[ReplicaMime] = std::move(replicaBytes);
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
    std::swap(impl_->replica, accepted);
    impl_->uncertain = false;
}
} // namespace cqs::trust
