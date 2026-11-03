// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_trust_journal.h"
#include "device_identity.h"
#include "device_key_envelope.h"
#include "device_key_receipt.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace cqs::trust {
namespace {
using crypto::Bytes;
constexpr char JournalDomain[] = "CopyQ-Secure-Sync-trust-journal-lab-v1";
constexpr char PinDomain[] = "CopyQ-Secure-Sync-trust-journal-pins-lab-v1";
constexpr char Mime[] = "application/x-copyq-secure-sync-trust-journal-lab-v1";
constexpr std::size_t MaxEventBytes = 4096;
enum class Kind : std::uint8_t { Reserve = 1, Observe = 2 };
struct Entry { Kind kind; std::uint64_t now; Bytes bytes; };
struct Outbound { Bytes envelope, receipt; };
struct Log {
    std::uint64_t initial = 0, watermark = 0;
    std::vector<Entry> entries;
    std::map<Token, Outbound> deliveries;
    Bytes installed;
};
[[noreturn]] void fail(JournalCode code) { throw JournalError(code); }
template<class Range> void append(Bytes &out, const Range &value) {
    out.insert(out.end(), value.begin(), value.end());
}
template<std::size_t N> void domain(Bytes &out, const char (&value)[N]) {
    out.insert(out.end(), value, value + N);
}
void u32(Bytes &out, std::uint32_t value) {
    for (unsigned shift = 32; shift; shift -= 8) out.push_back(static_cast<std::uint8_t>(value >> (shift - 8)));
}
void u64(Bytes &out, std::uint64_t value) {
    for (unsigned shift = 64; shift; shift -= 8) out.push_back(static_cast<std::uint8_t>(value >> (shift - 8)));
}
Membership model(const Genesis &g) {
    return Membership(g.group, g.founder, g.recovery, g.initialKeyCommitment);
}
void valid(const Member &member) {
    if (!SodiumVerifier::validMember(member)) fail(JournalCode::Invalid);
}
Token pin(const Genesis &g, const Member &local) {
    valid(g.founder); valid(local);
    const auto membership = model(g);
    Bytes bytes; domain(bytes, PinDomain);
    append(bytes, g.group); append(bytes, membership.current().root);
    append(bytes, membership.current().digest);
    append(bytes, local.id); append(bytes, local.signingKey); append(bytes, local.encryptionKey);
    const auto hash = crypto::sha256(bytes); Token result{};
    if (hash.size() != result.size()) fail(JournalCode::Invalid);
    std::copy(hash.begin(), hash.end(), result.begin()); return result;
}
std::string hex(const Token &value) {
    constexpr char digits[] = "0123456789abcdef"; std::string out;
    for (auto byte : value) { out.push_back(digits[byte >> 4]); out.push_back(digits[byte & 15]); }
    return out;
}
void field(Bytes &out, const Bytes &bytes) {
    if (bytes.size() > MaxEventBytes) fail(JournalCode::Invalid);
    u32(out, static_cast<std::uint32_t>(bytes.size())); append(out, bytes);
    if (out.size() > TrustJournal::MaxJournalBytes) fail(JournalCode::Invalid);
}
Bytes encode(const Log &log, const Token &pins) {
    if (!log.initial || log.watermark < log.initial || log.entries.size() > TrustJournal::MaxOperations ||
        log.deliveries.size() > MaxMembers)
        fail(JournalCode::Invalid);
    const bool lifecycle = !log.deliveries.empty() || !log.installed.empty();
    Bytes out; domain(out, JournalDomain); u32(out, lifecycle ? 3 : 1); append(out, pins);
    u64(out, log.initial); u64(out, log.watermark);
    u32(out, static_cast<std::uint32_t>(log.entries.size()));
    for (const auto &entry : log.entries) {
        if (entry.bytes.empty()) fail(JournalCode::Invalid);
        out.push_back(static_cast<std::uint8_t>(entry.kind)); u64(out, entry.now);
        field(out, entry.bytes);
    }
    if (lifecycle) {
        u32(out, static_cast<std::uint32_t>(log.deliveries.size()));
        for (const auto &delivery : log.deliveries) {
            if (delivery.second.envelope.empty()) fail(JournalCode::Invalid);
            append(out, delivery.first);
            field(out, delivery.second.envelope); field(out, delivery.second.receipt);
        }
        field(out, log.installed);
    }
    return out;
}
class Reader {
public:
    explicit Reader(const Bytes &bytes) : bytes_(bytes) {}
    template<std::size_t N> void expect(const char (&value)[N]) {
        need(N);
        if (!std::equal(value, value + N, bytes_.begin() + static_cast<std::ptrdiff_t>(pos_))) fail(JournalCode::Invalid);
        pos_ += N;
    }
    std::uint8_t byte() { need(1); return bytes_[pos_++]; }
    std::uint32_t number32() { std::uint32_t n = 0; for (unsigned i = 0; i < 4; ++i) n = (n << 8) | byte(); return n; }
    std::uint64_t number64() { std::uint64_t n = 0; for (unsigned i = 0; i < 8; ++i) n = (n << 8) | byte(); return n; }
    Token token() {
        need(32); Token result{};
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(pos_), 32, result.begin()); pos_ += 32; return result;
    }
    Bytes bytes(bool optional = false) {
        const auto count = number32();
        if (!count && optional) return {};
        if (!count || count > MaxEventBytes) fail(JournalCode::Invalid);
        need(count); const auto start = bytes_.begin() + static_cast<std::ptrdiff_t>(pos_); pos_ += count;
        return {start, start + count};
    }
    bool done() const { return pos_ == bytes_.size(); }
private:
    void need(std::size_t count) { if (count > bytes_.size() - pos_) fail(JournalCode::Invalid); }
    const Bytes &bytes_; std::size_t pos_ = 0;
};
void shape(const transaction::Record &record, const std::string &binding, const Token &pins) {
    if (record.binding != binding || record.keyIdentity != hex(pins)) fail(JournalCode::WrongPins);
    if (record.schema != 2 || record.head || record.pending || !record.local || record.local->size() != 1 ||
        record.local->front().size() != 1 || record.local->front().begin()->first != Mime ||
        record.allocatedSequence || record.publication || record.resolution || !record.archives.empty() ||
        record.preserved || !record.witnessed.empty()) fail(JournalCode::Invalid);
}
Log decode(const transaction::Record &record, const std::string &binding, const Token &pins) {
    shape(record, binding, pins);
    const auto &bytes = record.local->front().begin()->second;
    if (bytes.size() > TrustJournal::MaxJournalBytes) fail(JournalCode::Invalid);
    Reader reader(bytes); reader.expect(JournalDomain);
    const auto version = reader.number32();
    if (version < 1 || version > 3) fail(JournalCode::Invalid);
    if (reader.token() != pins) fail(JournalCode::WrongPins);
    Log log; log.initial = reader.number64(); log.watermark = reader.number64();
    const auto count = reader.number32();
    if (!log.initial || log.watermark < log.initial || count > TrustJournal::MaxOperations) fail(JournalCode::Invalid);
    log.entries.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto kind = static_cast<Kind>(reader.byte());
        if (kind != Kind::Reserve && kind != Kind::Observe) fail(JournalCode::Invalid);
        const auto now = reader.number64();
        log.entries.push_back({kind, now, reader.bytes()});
    }
    if (version >= 2) {
        const auto deliveryCount = reader.number32();
        if (deliveryCount > MaxMembers || (version == 2 && !deliveryCount)) fail(JournalCode::Invalid);
        Token previous{};
        for (std::uint32_t i = 0; i < deliveryCount; ++i) {
            const auto recipient = reader.token();
            if (!(previous < recipient)) fail(JournalCode::Invalid);
            auto envelope = reader.bytes();
            if (version == 2 && KeyEnvelopeCodec::inspect(envelope).scope != KeyScope::CurrentGeneration)
                fail(JournalCode::Invalid);
            log.deliveries.emplace(recipient, Outbound{std::move(envelope), version == 3 ? reader.bytes(true) : Bytes{}});
            previous = recipient;
        }
    }
    if (version == 3) {
        log.installed = reader.bytes(true);
        if (log.deliveries.empty() && log.installed.empty()) fail(JournalCode::Invalid);
    }
    if (!reader.done()) fail(JournalCode::Invalid);
    return log;
}
const Member &member(const State &state, const Token &id) {
    const auto found = std::find_if(state.members.begin(), state.members.end(),
        [&](const Member &candidate) { return candidate.id == id; });
    if (found == state.members.end()) throw Error(ErrorCode::NotMember);
    return *found;
}
Proposal currentProposal(const Log &log, const Membership &membership) {
    if (membership.forked()) throw Error(ErrorCode::Forked);
    if (!membership.current().epoch) fail(JournalCode::Delivery);
    for (auto entry = log.entries.rbegin(); entry != log.entries.rend(); ++entry) {
        if (entry->kind == Kind::Observe) {
            auto proposal = decodeCertificate(entry->bytes).proposal;
            if (proposalDigest(proposal) != membership.current().intent) fail(JournalCode::Invalid);
            return proposal;
        }
    }
    fail(JournalCode::Invalid);
}
KeyEnvelopeContext deliveryContext(const State &state, const Proposal &proposal, const Member &sender,
                                   const Token &recipientId, KeyScope scope) {
    if (member(state, sender.id) != sender) fail(JournalCode::WrongPins);
    const auto &recipient = member(state, recipientId);
    if (sender.id == recipientId) fail(JournalCode::Delivery);
    // Normal Add and catch-up have disjoint recipients. Remove already grants
    // normal delivery between survivors and never uses catch-up scope.
    const bool catchUp = proposal.operation == Operation::Add && recipient != proposal.subject;
    if (scope != (catchUp ? KeyScope::CatchUp : KeyScope::CurrentGeneration)) fail(JournalCode::Delivery);
    return {state.group, state.root, state.digest, state.intent, recipient, sender.id,
            state.keyGeneration, state.keyCommitment, scope};
}
ReceiptContext receiptContext(const KeyEnvelopeContext &context, const Bytes &envelope) {
    const auto hash = crypto::sha256(envelope); Token digest{};
    if (hash.size() != digest.size()) fail(JournalCode::Invalid);
    std::copy(hash.begin(), hash.end(), digest.begin());
    return {context.group, context.root, context.successor, context.proposal, context.sender,
            context.recipient, context.generation, context.commitment, digest, context.scope};
}
struct EnvelopeAuthority { KeyEnvelopeContext context; Member sender; };
EnvelopeAuthority incoming(const State &state, const Proposal &proposal, const Member &local,
                           const KeyEnvelopeContext &claimed) {
    const auto &sender = member(state, claimed.sender);
    return {deliveryContext(state, proposal, sender, local.id, claimed.scope), sender};
}
Membership replay(const Log &log, const Genesis &g, const Member &local,
                  std::optional<EnvelopeAuthority> *installed = nullptr) {
    auto membership = model(g); SodiumVerifier verifier;
    const auto claimed = log.installed.empty() ? std::nullopt
        : std::optional<KeyEnvelopeContext>(KeyEnvelopeCodec::inspect(log.installed));
    std::optional<EnvelopeAuthority> proof;
    std::uint64_t watermark = log.initial;
    for (const auto &entry : log.entries) {
        if (!entry.now) fail(JournalCode::Invalid);
        if (entry.kind == Kind::Reserve) {
            if (entry.now < watermark) fail(JournalCode::Invalid);
            const auto proposal = decodeProposal(entry.bytes); valid(proposal.subject);
            if (membership.reserve(proposal, local.id, entry.now) != ReserveResult::Reserved) fail(JournalCode::Invalid);
        } else {
            const auto certificate = decodeCertificate(entry.bytes); valid(certificate.proposal.subject);
            const auto result = membership.observe(certificate, entry.now, verifier);
            if (result == ObserveResult::AlreadyKnown ||
                (result == ObserveResult::Applied && entry.now < watermark)) fail(JournalCode::Invalid);
            if (claimed && result == ObserveResult::Applied && membership.current().digest == claimed->successor) {
                proof = incoming(membership.current(), certificate.proposal, local, *claimed);
                KeyEnvelopeCodec::verify(log.installed, proof->context, proof->sender);
            }
        }
        watermark = std::max(watermark, entry.now);
    }
    if (log.watermark < watermark) fail(JournalCode::Invalid);
    if (claimed && (!proof || membership.forked() ||
        proof->context.generation != membership.current().keyGeneration ||
        proof->context.commitment != membership.current().keyCommitment ||
        member(membership.current(), local.id) != local)) fail(JournalCode::Invalid);
    if (installed) *installed = std::move(proof);
    if (!log.deliveries.empty()) {
        const auto proposal = currentProposal(log, membership);
        for (const auto &delivery : log.deliveries) {
            const auto &outbound = delivery.second;
            const auto scope = KeyEnvelopeCodec::inspect(outbound.envelope).scope;
            const auto context = deliveryContext(membership.current(), proposal, local, delivery.first, scope);
            KeyEnvelopeCodec::verify(outbound.envelope, context, local);
            if (!outbound.receipt.empty())
                KeyReceiptCodec::verify(outbound.receipt, receiptContext(context, outbound.envelope));
        }
    }
    return membership;
}
void checkPriorKeys(const Log &log, const Genesis &genesis, const State &state, const SyncKey &key) {
    if (!state.keyGeneration) return;
    if (key.commitment(state.group, 0) == genesis.initialKeyCommitment) fail(JournalCode::KeyReuse);
    for (const auto &entry : log.entries) {
        if (entry.kind != Kind::Observe) continue;
        const auto proposal = decodeCertificate(entry.bytes).proposal;
        if (proposal.operation == Operation::Remove && proposal.keyGeneration < state.keyGeneration &&
            key.commitment(state.group, proposal.keyGeneration) == proposal.keyCommitment)
            fail(JournalCode::KeyReuse);
    }
}
void clock(const Log &log, std::uint64_t now) {
    if (!now || now < log.watermark) fail(JournalCode::ClockRollback);
}
void storeLog(transaction::Record &record, const Log &log, const Token &pins) {
    record.local = transaction::Snapshot{{{Mime, encode(log, pins)}}};
}
void add(Log &log, Kind kind, std::uint64_t now, Bytes bytes) {
    if (log.entries.size() >= TrustJournal::MaxOperations) throw Error(ErrorCode::Limit);
    log.entries.push_back({kind, now, std::move(bytes)});
    log.watermark = std::max(log.watermark, now);
}
} // namespace

JournalError::JournalError(JournalCode code) : std::runtime_error("Device trust journal refused"), code_(code) {}
std::string TrustJournal::binding(const Genesis &g, const Member &local) { return "trust-" + hex(pin(g, local)); }
transaction::Record TrustJournal::initialRecord(const Genesis &g, const Member &local, std::uint64_t now) {
    if (!now) fail(JournalCode::ClockRollback);
    const auto pins = pin(g, local);
    transaction::Record record; record.schema = 2; record.binding = binding(g, local);
    record.keyIdentity = hex(pins); storeLog(record, {now, now, {}, {}, {}}, pins); return record;
}
void TrustJournal::initialize(state::FileStore &store, const Genesis &g, const Member &local, std::uint64_t now) {
    auto lease = store.lock(); if (!lease) fail(JournalCode::Busy);
    store.initialize(initialRecord(g, local, now));
}
TrustJournal::TrustJournal(transaction::Store &store, Genesis genesis, Member local)
    : store_(store), genesis_(std::move(genesis)), local_(std::move(local)), binding_(binding(genesis_, local_)) {
    (void)inspect();
}
std::unique_ptr<transaction::Store::Lease> TrustJournal::lock() {
    if (uncertain_) fail(JournalCode::Uncertain);
    auto lease = store_.lock(); if (!lease) fail(JournalCode::Busy);
    if (uncertain_) fail(JournalCode::Uncertain);
    return lease;
}
transaction::Record TrustJournal::load() {
    auto record = store_.load();
    shape(record, binding_, pin(genesis_, local_));
    const auto &bytes = record.local->front().begin()->second;
    if (bytes.size() > MaxJournalBytes) fail(JournalCode::Invalid);
    const auto hash = crypto::sha256(bytes); Token digest{};
    if (hash.size() != digest.size()) fail(JournalCode::Invalid);
    std::copy(hash.begin(), hash.end(), digest.begin());
    if (seenGeneration_ && (record.generation < *seenGeneration_ ||
        (record.generation == *seenGeneration_ && digest != seenRecord_))) fail(JournalCode::Rollback);
    seenGeneration_ = record.generation; seenRecord_ = digest;
    return record;
}
void TrustJournal::save(const transaction::Record &expected, transaction::Record replacement) {
    if (expected.generation == std::numeric_limits<std::uint64_t>::max()) throw Error(ErrorCode::Overflow);
    replacement.generation = expected.generation + 1;
    const auto hash = crypto::sha256(replacement.local->front().begin()->second);
    if (hash.size() != seenRecord_.size()) fail(JournalCode::Invalid);
    try { store_.commit(expected, replacement); }
    catch (...) { uncertain_ = true; throw; }
    // A live instance also rejects replacing its record with an older valid
    // ciphertext. Complete disk/key rollback across restart needs an external
    // monotonic anchor and remains outside this laboratory's guarantee.
    seenGeneration_ = replacement.generation;
    std::copy(hash.begin(), hash.end(), seenRecord_.begin());
}
JournalStatus TrustJournal::inspect() {
    const auto lease = lock(); const auto record = load();
    const auto log = decode(record, binding_, pin(genesis_, local_));
    const auto membership = replay(log, genesis_, local_);
    JournalStatus result{membership.current(), membership.forked(), log.watermark,
                         log.entries.size(), membership.reservationCount(), {}, !log.installed.empty(), {}};
    for (const auto &entry : log.entries) if (entry.kind == Kind::Observe) result.certificates.push_back(entry.bytes);
    for (const auto &entry : log.deliveries)
        if (!entry.second.receipt.empty()) result.confirmedDeliveries.push_back(entry.first);
    return result;
}
Proposal TrustJournal::propose(Operation operation, const Member &subject, const Token &request,
                              const Token &nonce, std::uint64_t created, std::uint64_t expires,
                              const Token &rotatedKeyCommitment) {
    const auto lease = lock(); const auto record = load();
    const auto log = decode(record, binding_, pin(genesis_, local_));
    const auto membership = replay(log, genesis_, local_); clock(log, created); valid(subject);
    if (std::find(membership.current().members.begin(), membership.current().members.end(), local_) == membership.current().members.end())
        throw Error(ErrorCode::NotMember);
    return membership.propose(operation, subject, request, nonce, created, expires, rotatedKeyCommitment);
}
Approval TrustJournal::approve(const Proposal &proposal, const Identity &identity,
                              const Token &confirmedDigest, std::uint64_t now) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins); auto membership = replay(log, genesis_, local_);
    if (identity.member() != local_) fail(JournalCode::WrongPins);
    valid(proposal.subject); clock(log, now);
    if (verificationDigest(proposal, local_) != confirmedDigest) fail(JournalCode::Confirmation);
    const auto result = membership.reserve(proposal, local_.id, now);
    if (result == ReserveResult::Reserved) add(log, Kind::Reserve, now, encodeProposal(proposal));
    log.watermark = now;
    auto replacement = record; storeLog(replacement, log, pins);
    // No signing adapter is called until a successful durability barrier.
    save(record, std::move(replacement));
    return {local_.id, identity.sign(approvalBytes(proposal, local_))};
}
ObserveResult TrustJournal::observe(const Certificate &certificate, std::uint64_t now) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins); auto membership = replay(log, genesis_, local_);
    valid(certificate.proposal.subject); SodiumVerifier verifier;
    const auto previousGeneration = membership.current().keyGeneration;
    const auto result = membership.observe(certificate, now, verifier);
    if (result == ObserveResult::AlreadyKnown) return result;
    if (result == ObserveResult::Applied) clock(log, now);
    else if (!now) fail(JournalCode::ClockRollback);
    add(log, Kind::Observe, now, encodeCertificate(certificate));
    log.deliveries.clear();
    if (membership.forked() || previousGeneration != membership.current().keyGeneration)
        log.installed.clear();
    auto replacement = record; storeLog(replacement, log, pins); save(record, std::move(replacement)); return result;
}
Bytes TrustJournal::prepareDelivery(const Token &recipient, const Identity &sender, const SyncKey &key,
                                    std::uint64_t now) {
    return prepare(recipient, sender, key, now, KeyScope::CurrentGeneration);
}
Bytes TrustJournal::prepareCatchUp(const Token &recipient, const Identity &sender, const SyncKey &key,
                                   std::uint64_t now) {
    return prepare(recipient, sender, key, now, KeyScope::CatchUp);
}
Bytes TrustJournal::prepare(const Token &recipient, const Identity &sender, const SyncKey &key,
                            std::uint64_t now, KeyScope scope) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins); const auto membership = replay(log, genesis_, local_);
    if (sender.member() != local_) fail(JournalCode::WrongPins);
    clock(log, now);
    const auto proposal = currentProposal(log, membership);
    const auto context = deliveryContext(membership.current(), proposal, local_, recipient, scope);
    if (key.commitment(context.group, context.generation) != context.commitment)
        throw EnvelopeError(EnvelopeCode::KeyMismatch);
    checkPriorKeys(log, genesis_, membership.current(), key);
    const auto prior = log.deliveries.find(recipient);
    auto wire = prior == log.deliveries.end() ? KeyEnvelopeCodec::seal(context, sender, key) : prior->second.envelope;
    if (prior == log.deliveries.end()) log.deliveries.emplace(recipient, Outbound{wire, {}});
    // Reopening after an unconfirmed fsync can expose the replacement bytes.
    // Recommit the exact saved package before returning it on retry.
    log.watermark = now;
    auto replacement = record; storeLog(replacement, log, pins); save(record, std::move(replacement));
    return wire;
}
std::unique_ptr<SyncKey> TrustJournal::receiveDelivery(const Bytes &wire, const Identity &recipient,
                                                       std::uint64_t now) {
    const auto lease = lock(); const auto record = load();
    const auto log = decode(record, binding_, pin(genesis_, local_));
    const auto membership = replay(log, genesis_, local_);
    if (recipient.member() != local_) fail(JournalCode::WrongPins);
    clock(log, now);
    const auto proposal = currentProposal(log, membership);
    const auto authority = incoming(membership.current(), proposal, local_, KeyEnvelopeCodec::inspect(wire));
    auto key = KeyEnvelopeCodec::open(wire, authority.context, authority.sender, recipient);
    checkPriorKeys(log, genesis_, membership.current(), *key);
    return key;
}
Bytes TrustJournal::installDelivery(const Bytes &wire, const Identity &recipient, std::uint64_t now) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins); const auto membership = replay(log, genesis_, local_);
    if (recipient.member() != local_) fail(JournalCode::WrongPins);
    clock(log, now);
    const auto proposal = currentProposal(log, membership);
    const auto authority = incoming(membership.current(), proposal, local_, KeyEnvelopeCodec::inspect(wire));
    {
        const auto key = KeyEnvelopeCodec::open(wire, authority.context, authority.sender, recipient);
        checkPriorKeys(log, genesis_, membership.current(), *key);
    }
    const auto receipt = receiptContext(authority.context, wire);
    log.installed = wire; log.watermark = now;
    auto replacement = record; storeLog(replacement, log, pins);
    save(record, std::move(replacement));
    return KeyReceiptCodec::sign(receipt, recipient);
}
std::unique_ptr<SyncKey> TrustJournal::loadInstalledKey(const Identity &recipient, std::uint64_t now) {
    const auto lease = lock(); const auto record = load();
    const auto log = decode(record, binding_, pin(genesis_, local_));
    std::optional<EnvelopeAuthority> proof;
    const auto membership = replay(log, genesis_, local_, &proof);
    if (recipient.member() != local_) fail(JournalCode::WrongPins);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    clock(log, now);
    if (member(membership.current(), local_.id) != local_) fail(JournalCode::WrongPins);
    if (!proof) fail(JournalCode::MissingKey);
    auto key = KeyEnvelopeCodec::open(log.installed, proof->context, proof->sender, recipient);
    checkPriorKeys(log, genesis_, membership.current(), *key);
    return key;
}
bool TrustJournal::recordReceipt(const Bytes &receipt, std::uint64_t now) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins); const auto membership = replay(log, genesis_, local_);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    clock(log, now);
    const auto claimed = KeyReceiptCodec::inspect(receipt);
    const auto found = log.deliveries.find(claimed.recipient.id);
    if (found == log.deliveries.end()) fail(JournalCode::Delivery);
    auto &delivery = found->second;
    const auto envelope = KeyEnvelopeCodec::inspect(delivery.envelope);
    KeyReceiptCodec::verify(receipt, receiptContext(envelope, delivery.envelope));
    if (!delivery.receipt.empty()) return false;
    delivery.receipt = receipt; log.watermark = now;
    auto replacement = record; storeLog(replacement, log, pins); save(record, std::move(replacement));
    return true;
}
} // namespace cqs::trust
