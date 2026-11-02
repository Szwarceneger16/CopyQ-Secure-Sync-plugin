// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_trust_journal.h"
#include "device_identity.h"
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
struct Log {
    std::uint64_t initial = 0, watermark = 0;
    std::vector<Entry> entries;
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
Bytes encode(const Log &log, const Token &pins) {
    if (!log.initial || log.watermark < log.initial || log.entries.size() > TrustJournal::MaxOperations)
        fail(JournalCode::Invalid);
    Bytes out; domain(out, JournalDomain); u32(out, 1); append(out, pins);
    u64(out, log.initial); u64(out, log.watermark);
    u32(out, static_cast<std::uint32_t>(log.entries.size()));
    for (const auto &entry : log.entries) {
        if (entry.bytes.empty() || entry.bytes.size() > MaxEventBytes) fail(JournalCode::Invalid);
        out.push_back(static_cast<std::uint8_t>(entry.kind)); u64(out, entry.now);
        u32(out, static_cast<std::uint32_t>(entry.bytes.size())); append(out, entry.bytes);
        if (out.size() > TrustJournal::MaxJournalBytes) fail(JournalCode::Invalid);
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
    Bytes bytes() {
        const auto count = number32();
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
    if (reader.number32() != 1) fail(JournalCode::Invalid);
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
    if (!reader.done()) fail(JournalCode::Invalid);
    return log;
}
Membership replay(const Log &log, const Genesis &g, const Member &local) {
    auto membership = model(g); SodiumVerifier verifier;
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
        }
        watermark = std::max(watermark, entry.now);
    }
    if (log.watermark < watermark) fail(JournalCode::Invalid);
    return membership;
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
    record.keyIdentity = hex(pins); storeLog(record, {now, now, {}}, pins); return record;
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
                         log.entries.size(), membership.reservationCount(), {}};
    for (const auto &entry : log.entries) if (entry.kind == Kind::Observe) result.certificates.push_back(entry.bytes);
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
    const auto result = membership.observe(certificate, now, verifier);
    if (result == ObserveResult::AlreadyKnown) return result;
    if (result == ObserveResult::Applied) clock(log, now);
    else if (!now) fail(JournalCode::ClockRollback);
    add(log, Kind::Observe, now, encodeCertificate(certificate));
    auto replacement = record; storeLog(replacement, log, pins); save(record, std::move(replacement)); return result;
}
} // namespace cqs::trust
