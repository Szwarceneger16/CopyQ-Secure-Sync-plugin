// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_trust_journal.h"
#include "device_archive_migration.h"
#include "device_identity.h"
#include "device_key_envelope.h"
#include "device_key_receipt.h"
#include "storage.h"
#include <sodium.h>
#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace cqs::trust {
namespace {
using crypto::Bytes;
constexpr char JournalDomain[] = "CopyQ-Secure-Sync-trust-journal-lab-v1";
constexpr char PinDomain[] = "CopyQ-Secure-Sync-trust-journal-pins-lab-v1";
constexpr char Mime[] = "application/x-copyq-secure-sync-trust-journal-lab-v1";
constexpr std::size_t MaxEventBytes = 4096;
static_assert(TrustJournal::MaxClipboardEventBytes == storage::MaxSignedEventPacketBytes,
              "Signed packet limits differ between journal and transport");
enum class Kind : std::uint8_t { Reserve = 1, Observe = 2 };
struct Entry { Kind kind; std::uint64_t now; Bytes bytes; };
struct Outbound { Bytes envelope, receipt; };
using Witnesses = std::map<std::string, Token>;
struct EventLedger {
    std::uint64_t generation;
    std::uint32_t attempts = 0;
    bool publicationAttempted = false;
    Witnesses witnesses;
};
struct ArchiveMigration {
    Token confirmation;
    std::uint64_t sequence;
    bool completed;
};
struct Log {
    std::uint64_t initial = 0, watermark = 0;
    std::vector<Entry> entries;
    std::map<Token, Outbound> deliveries;
    Bytes installed;
    std::uint64_t allocatedSequence = 0;
    std::optional<Bytes> pendingEvent;
    std::optional<EventLedger> eventLedger;
    std::optional<ArchiveMigration> migration;
};
[[noreturn]] void fail(JournalCode code) { throw JournalError(code); }
bool sameConfirmation(const Token &a, const Token &b) noexcept {
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}
EventLedger &eventLedger(Log &log, std::uint64_t generation) {
    if (!log.eventLedger) log.eventLedger = EventLedger{generation, 0, false, {}};
    return *log.eventLedger;
}
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
    if (out.size() > TrustJournal::MaxControlBytes) fail(JournalCode::Invalid);
}
Bytes encode(const Log &log, const Token &pins) {
    if (!log.initial || log.watermark < log.initial || log.entries.size() > TrustJournal::MaxOperations ||
        log.deliveries.size() > MaxMembers || log.allocatedSequence > history::MaxSequence ||
        (!log.allocatedSequence && log.pendingEvent))
        fail(JournalCode::Invalid);
    const bool lifecycle = !log.deliveries.empty() || !log.installed.empty();
    const auto version = log.migration ? 6 : (log.eventLedger ? 5 : (log.allocatedSequence ? 4 : (lifecycle ? 3 : 1)));
    Bytes out; domain(out, JournalDomain); u32(out, version); append(out, pins);
    u64(out, log.initial); u64(out, log.watermark);
    u32(out, static_cast<std::uint32_t>(log.entries.size()));
    for (const auto &entry : log.entries) {
        if (entry.bytes.empty()) fail(JournalCode::Invalid);
        out.push_back(static_cast<std::uint8_t>(entry.kind)); u64(out, entry.now);
        field(out, entry.bytes);
    }
    if (version >= 3) {
        u32(out, static_cast<std::uint32_t>(log.deliveries.size()));
        for (const auto &delivery : log.deliveries) {
            if (delivery.second.envelope.empty()) fail(JournalCode::Invalid);
            append(out, delivery.first);
            field(out, delivery.second.envelope); field(out, delivery.second.receipt);
        }
        field(out, log.installed);
    }
    if (version >= 4) {
        u64(out, log.allocatedSequence);
        out.push_back(log.pendingEvent ? 1 : 0);
        const auto size = log.pendingEvent ? log.pendingEvent->size() : 0;
        if (size > TrustJournal::MaxClipboardEventBytes) fail(JournalCode::Invalid);
        u32(out, static_cast<std::uint32_t>(size));
        if (log.pendingEvent) append(out, *log.pendingEvent);
    }
    if (log.eventLedger) {
        const auto &ledger = *log.eventLedger;
        if (ledger.witnesses.size() > history::MaxEvents) fail(JournalCode::Invalid);
        u64(out, ledger.generation);
        u32(out, ledger.attempts);
        out.push_back(ledger.publicationAttempted ? 1 : 0);
        u32(out, static_cast<std::uint32_t>(ledger.witnesses.size()));
        for (const auto &[id, digest] : ledger.witnesses) { append(out, id); append(out, digest); }
    }
    if (log.migration) {
        append(out, log.migration->confirmation);
        u64(out, log.migration->sequence);
        out.push_back(log.migration->completed ? 1 : 0);
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
    std::string eventId() {
        constexpr std::size_t size = 45;
        need(size);
        std::string result(bytes_.begin() + static_cast<std::ptrdiff_t>(pos_),
                           bytes_.begin() + static_cast<std::ptrdiff_t>(pos_ + size));
        pos_ += size;
        return result;
    }
    Bytes bytes(bool optional = false, std::size_t limit = MaxEventBytes) {
        const auto count = number32();
        if (!count && optional) return {};
        if (!count || count > limit) fail(JournalCode::Invalid);
        need(count); const auto start = bytes_.begin() + static_cast<std::ptrdiff_t>(pos_); pos_ += count;
        return {start, start + count};
    }
    std::size_t consumed() const { return pos_; }
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
    if (version < 1 || version > 6) fail(JournalCode::Invalid);
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
            log.deliveries.emplace(recipient, Outbound{std::move(envelope), version >= 3 ? reader.bytes(true) : Bytes{}});
            previous = recipient;
        }
    }
    if (version >= 3) {
        log.installed = reader.bytes(true);
        if (version == 3 && log.deliveries.empty() && log.installed.empty()) fail(JournalCode::Invalid);
    }
    if (reader.consumed() > TrustJournal::MaxControlBytes) fail(JournalCode::Invalid);
    if (version >= 4) {
        log.allocatedSequence = reader.number64();
        const auto pending = reader.byte();
        if (log.allocatedSequence > history::MaxSequence || pending > 1 ||
            (!log.allocatedSequence && (pending || version == 4)))
            fail(JournalCode::Invalid);
        auto wire = reader.bytes(true, TrustJournal::MaxClipboardEventBytes);
        if (pending) log.pendingEvent = std::move(wire);
        else if (!wire.empty()) fail(JournalCode::Invalid);
    }
    if (version >= 5) {
        EventLedger ledger{reader.number64(), reader.number32(), false, {}};
        const auto attempted = reader.byte();
        const auto witnessCount = reader.number32();
        if (ledger.attempts > SignedEventCodec::MaxAttemptsPerAuthorPerGeneration ||
            ledger.attempts > log.allocatedSequence || attempted > 1 || witnessCount > history::MaxEvents ||
            (attempted && (!log.pendingEvent || log.pendingEvent->empty() || !ledger.attempts)))
            fail(JournalCode::Invalid);
        ledger.publicationAttempted = attempted != 0;
        std::string previous;
        for (std::uint32_t i = 0; i < witnessCount; ++i) {
            auto id = reader.eventId();
            if (!storage::validSignedEventId(id) || !(previous < id)) fail(JournalCode::Invalid);
            previous = id;
            ledger.witnesses.emplace(std::move(id), reader.token());
        }
        log.eventLedger = std::move(ledger);
    }
    if (version == 6) {
        const auto confirmation = reader.token();
        const auto sequence = reader.number64();
        const auto completed = reader.byte();
        if (confirmation == Token{} || !sequence || sequence > log.allocatedSequence || completed > 1 ||
            (!completed && (!log.pendingEvent || sequence != log.allocatedSequence)) ||
            (completed && log.pendingEvent && sequence == log.allocatedSequence))
            fail(JournalCode::Invalid);
        log.migration = ArchiveMigration{confirmation, sequence, completed != 0};
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
SignedEventContext eventContext(const State &state, const Token &author) {
    return {state.group, state.root, state.digest, state.keyCommitment, author, state.keyGeneration};
}
SignedEventContext verifyPendingEvent(const Log &log, const Membership &membership, const Member &local) {
    const auto &wire = *log.pendingEvent;
    const std::string_view bytes(reinterpret_cast<const char *>(wire.data()), wire.size());
    const auto header = SignedEventCodec::inspect(bytes);
    const auto *state = membership.acceptedState(header.context.head);
    if (!state || member(*state, local.id) != local) fail(JournalCode::Invalid);
    const auto id = history::makeId(SignedEventCodec::deviceName(local.id), log.allocatedSequence);
    SignedEventCodec::verify({id, bytes}, eventContext(*state, local.id), local);
    if (header.version == SignedEventCodec::CurrentVersion &&
        (!log.eventLedger || (state->keyGeneration == log.eventLedger->generation && !log.eventLedger->attempts)))
        fail(JournalCode::Invalid);
    if (log.eventLedger && log.eventLedger->publicationAttempted &&
        (header.version != SignedEventCodec::CurrentVersion || state->keyGeneration != log.eventLedger->generation))
        fail(JournalCode::Invalid);
    if (log.migration && !log.migration->completed &&
        (header.version != SignedEventCodec::CurrentVersion || state->keyGeneration || !header.parents.empty()))
        fail(JournalCode::Invalid);
    return header.context;
}
Membership replay(const Log &log, const Genesis &g, const Member &local,
                  std::optional<EnvelopeAuthority> *installed = nullptr, std::uint64_t *pendingGeneration = nullptr) {
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
    if (log.eventLedger && log.eventLedger->generation != membership.current().keyGeneration)
        fail(JournalCode::Invalid);
    if (log.migration) {
        if (local != g.founder) fail(JournalCode::Invalid);
        if (log.migration->completed && !membership.current().keyGeneration &&
            !log.eventLedger->witnesses.count(history::makeId(SignedEventCodec::deviceName(local.id),
                                                               log.migration->sequence)))
            fail(JournalCode::Invalid);
    }
    if (log.pendingEvent && !log.pendingEvent->empty()) {
        const auto context = verifyPendingEvent(log, membership, local);
        if (pendingGeneration) *pendingGeneration = context.generation;
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
void checkEventKey(const Log &log, const Genesis &genesis, const State &state, const SyncKey &key) {
    if (key.commitment(state.group, state.keyGeneration) != state.keyCommitment)
        throw EnvelopeError(EnvelopeCode::KeyMismatch);
    checkPriorKeys(log, genesis, state, key);
}
std::map<Token, std::size_t> eventAuthors(const State &state) {
    std::map<Token, std::size_t> authors;
    std::set<std::string> names;
    for (const auto &member : state.members) {
        if (!names.insert(SignedEventCodec::deviceName(member.id)).second) throw Error(ErrorCode::Invalid);
        authors.emplace(member.id, authors.size());
    }
    return authors;
}
struct EventEvidence {
    std::vector<SignedEventParent> parents;
    std::uint64_t epoch;
    std::size_t author;
};
history::Graph checkedSignedGraph(const std::vector<history::Revision> &revisions,
                                  const std::vector<EventEvidence> &evidence,
                                  const std::map<std::string, std::size_t> &positions,
                                  const std::map<std::string, Token> &digests) {
    std::vector<std::array<std::uint64_t, MaxMembers>> ancestors(revisions.size());
    std::vector<std::vector<std::size_t>> children(revisions.size());
    std::vector<std::size_t> remaining, ready;
    remaining.reserve(revisions.size()); ready.reserve(revisions.size());
    for (std::size_t index = 0; index < evidence.size(); ++index) {
        const auto &event = evidence[index];
        remaining.push_back(event.parents.size());
        if (event.parents.empty()) ready.push_back(index);
        for (const auto &parent : event.parents) {
            // Report contradictions among present parents even when another
            // parent has not yet arrived. The Graph handles absent parents.
            const auto found = positions.find(parent.id);
            if (found == positions.end()) continue;
            const auto prior = found->second;
            if (digests.at(parent.id) != parent.digest || evidence[prior].epoch > event.epoch)
                throw Error(ErrorCode::Invalid);
            children[prior].push_back(index);
        }
    }
    history::Graph graph(revisions);
    for (std::size_t cursor = 0; cursor < ready.size(); ++cursor) {
        const auto index = ready[cursor];
        auto &witness = ancestors[index];
        const auto author = evidence[index].author;
        const auto sequence = revisions[index].sequence;
        if (sequence <= witness[author])
            throw history::Error(history::ErrorCode::NonmonotonicParent, "Signed event refers to its author's future");
        witness[author] = sequence;
        for (const auto child : children[index]) {
            for (std::size_t slot = 0; slot < witness.size(); ++slot)
                ancestors[child][slot] = std::max(ancestors[child][slot], witness[slot]);
            if (--remaining[child] == 0) ready.push_back(child);
        }
    }
    return graph;
}
} // namespace

JournalError::JournalError(JournalCode code) : std::runtime_error("Device trust journal refused"), code_(code) {}
std::string TrustJournal::binding(const Genesis &g, const Member &local) { return "trust-" + hex(pin(g, local)); }
transaction::Record TrustJournal::initialRecord(const Genesis &g, const Member &local, std::uint64_t now) {
    if (!now) fail(JournalCode::ClockRollback);
    const auto pins = pin(g, local);
    transaction::Record record; record.schema = 2; record.binding = binding(g, local);
    record.keyIdentity = hex(pins); storeLog(record, {now, now, {}, {}, {}, 0, {}, {}, {}}, pins); return record;
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
void TrustJournal::save(const transaction::Record &expected, transaction::Record &replacement) {
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
                         log.entries.size(), membership.reservationCount(), {}, !log.installed.empty(), {},
                         log.allocatedSequence, {}, 0, 0, {}};
    if (log.migration)
        result.migration = ArchiveMigrationStatus{log.migration->sequence, log.migration->completed};
    if (log.eventLedger) {
        result.eventEncryptionAttempts = log.eventLedger->attempts;
        result.eventWitnesses = log.eventLedger->witnesses.size();
    }
    if (log.pendingEvent)
        result.pendingEvent = PendingClipboardEvent{log.allocatedSequence, !log.pendingEvent->empty(),
                                                     log.eventLedger && log.eventLedger->publicationAttempted};
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
    if (log.migration && !log.migration->completed) fail(JournalCode::Migration);
    if (identity.member() != local_) fail(JournalCode::WrongPins);
    valid(proposal.subject); clock(log, now);
    if (verificationDigest(proposal, local_) != confirmedDigest) fail(JournalCode::Confirmation);
    const auto result = membership.reserve(proposal, local_.id, now);
    if (result == ReserveResult::Reserved) add(log, Kind::Reserve, now, encodeProposal(proposal));
    log.watermark = now;
    auto replacement = record; storeLog(replacement, log, pins);
    // No signing adapter is called until a successful durability barrier.
    save(record, replacement);
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
    if (log.eventLedger && previousGeneration != membership.current().keyGeneration)
        log.eventLedger = EventLedger{membership.current().keyGeneration, 0, false, {}};
    auto replacement = record; storeLog(replacement, log, pins); save(record, replacement); return result;
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
    if (log.migration && !log.migration->completed) fail(JournalCode::Migration);
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
    auto replacement = record; storeLog(replacement, log, pins); save(record, replacement);
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
    save(record, replacement);
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
    auto replacement = record; storeLog(replacement, log, pins); save(record, replacement);
    return true;
}

std::string TrustJournal::publishDelivery(const Token &recipient, const storage::Directory &transport,
                                         std::uint64_t now, const std::filesystem::path &privateStaging) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins); const auto membership = replay(log, genesis_, local_);
    if (log.migration && !log.migration->completed) fail(JournalCode::Migration);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    clock(log, now);
    const auto delivery = log.deliveries.find(recipient);
    if (delivery == log.deliveries.end()) fail(JournalCode::Delivery);
    const auto &wire = delivery->second.envelope;
    const auto id = storage::controlPacketId(wire);
    // Replay checked the saved envelope against this exact current head. Keep
    // the same lease through the local and transport durability barriers.
    log.watermark = now;
    auto replacement = record; storeLog(replacement, log, pins);
    save(record, replacement);
    transport.publishControl(wire, privateStaging);
    return id;
}

std::string TrustJournal::publishReceipt(const Identity &recipient, const storage::Directory &transport,
                                        std::uint64_t now, const std::filesystem::path &privateStaging) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    std::optional<EnvelopeAuthority> proof;
    const auto membership = replay(log, genesis_, local_, &proof);
    if (recipient.member() != local_) fail(JournalCode::WrongPins);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    clock(log, now);
    if (!proof || proof->context.successor != membership.current().digest) fail(JournalCode::Delivery);
    {
        const auto key = KeyEnvelopeCodec::open(log.installed, proof->context, proof->sender, recipient);
        checkPriorKeys(log, genesis_, membership.current(), *key);
    }
    const auto receipt = receiptContext(proof->context, log.installed);
    log.watermark = now;
    auto replacement = record; storeLog(replacement, log, pins);
    save(record, replacement);
    const auto wire = KeyReceiptCodec::sign(receipt, recipient);
    const auto id = storage::controlPacketId(wire);
    transport.publishControl(wire, privateStaging);
    return id;
}

PreparedClipboardEvent TrustJournal::prepareClipboardEvent(const Identity &author, const SyncKey &key,
                                                            const std::vector<SignedEventParent> &parents,
                                                            const std::vector<std::string> &packedItems,
                                                            std::uint64_t now, events::Limits limits) {
    const auto lease = lock();
    return prepareClipboardEventLocked(author, key, parents, packedItems, now, limits);
}

PreparedClipboardEvent TrustJournal::prepareClipboardEventLocked(const Identity &author, const SyncKey &key,
    const std::vector<SignedEventParent> &parents, const std::vector<std::string> &packedItems,
    std::uint64_t now, events::Limits limits, const Token *migration) {
    SignedEventCodec::validateLimits(limits);
    limits.eventBytes = std::min(limits.eventBytes, MaxClipboardEventBytes);
    const auto record = load();
    const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    const auto membership = replay(log, genesis_, local_);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    if (author.member() != local_) fail(JournalCode::WrongPins);
    clock(log, now);
    const auto &state = membership.current();
    if (member(state, local_.id) != local_) fail(JournalCode::WrongPins);
    (void)eventAuthors(state);
    checkEventKey(log, genesis_, state, key);
    if (log.migration && !log.migration->completed &&
        (!migration || !sameConfirmation(*migration, log.migration->confirmation))) fail(JournalCode::Migration);
    if (log.pendingEvent && (!migration || !log.migration || !log.pendingEvent->empty()))
        fail(JournalCode::EventPending);
    auto &ledger = eventLedger(log, state.keyGeneration);
    if (ledger.attempts == SignedEventCodec::MaxAttemptsPerAuthorPerGeneration) fail(JournalCode::EventBudget);
    // Leave room for both commits, a recovery barrier, and explicit retirement.
    if (log.allocatedSequence == history::MaxSequence ||
        record.generation > std::numeric_limits<std::uint64_t>::max() - 4) throw Error(ErrorCode::Overflow);

    const auto sequence = ++log.allocatedSequence;
    ++ledger.attempts;
    log.pendingEvent.emplace();
    if (migration) log.migration = ArchiveMigration{*migration, sequence, false};
    log.watermark = now;
    auto burned = record;
    storeLog(burned, log, pins);
    save(record, burned);
    // Keep the first committed generation for the next CAS. If sealing or
    // either barrier fails, there is no way to reuse a durably burned sequence.
    *log.pendingEvent = SignedEventCodec::seal(eventContext(state, local_.id), author, key, sequence,
                                              parents, packedItems, limits);
    auto ready = burned;
    storeLog(ready, log, pins);
    save(burned, ready);
    return {sequence, std::move(*log.pendingEvent)};
}

PreparedClipboardEvent TrustJournal::resumeClipboardEvent(std::uint64_t sequence, std::uint64_t now) {
    const auto lease = lock(); const auto record = load();
    const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    std::uint64_t pendingGeneration = 0;
    const auto membership = replay(log, genesis_, local_, nullptr, &pendingGeneration);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    clock(log, now);
    const auto &state = membership.current();
    if (member(state, local_.id) != local_) fail(JournalCode::WrongPins);
    if (!log.pendingEvent || log.pendingEvent->empty() || sequence != log.allocatedSequence)
        fail(JournalCode::EventReservation);
    if (log.migration && !log.migration->completed) fail(JournalCode::Migration);
    if (pendingGeneration != state.keyGeneration) throw Error(ErrorCode::Stale);
    (void)eventAuthors(state);
    if (record.generation >= std::numeric_limits<std::uint64_t>::max() - 1) throw Error(ErrorCode::Overflow);

    // A reopened record may have survived an unconfirmed prior commit.
    // Reestablish the local barrier before returning its exact bytes.
    log.watermark = now;
    auto replacement = record;
    storeLog(replacement, log, pins);
    save(record, replacement);
    return {sequence, std::move(*log.pendingEvent)};
}

void TrustJournal::discardClipboardEvent(std::uint64_t sequence, std::uint64_t now) {
    const auto lease = lock(); const auto record = load();
    const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    (void)replay(log, genesis_, local_);
    clock(log, now);
    if (!log.pendingEvent || sequence != log.allocatedSequence) fail(JournalCode::EventReservation);
    if (log.migration && !log.migration->completed) fail(JournalCode::Migration);
    if (log.eventLedger && log.eventLedger->publicationAttempted) fail(JournalCode::EventPublication);
    log.pendingEvent.reset();
    log.watermark = now;
    auto replacement = record;
    storeLog(replacement, log, pins);
    save(record, replacement);
}

namespace {
struct WipeEvents {
    std::vector<events::Event> &events;
    bool released = false;
    ~WipeEvents() {
        if (!released) for (auto &event : events)
            for (auto &item : event.items) if (!item.empty()) sodium_memzero(item.data(), item.size());
    }
};

const State &clipboardAuthority(const Log &log, const Membership &membership, const Genesis &genesis,
                                const Member &local, const SyncKey &key, std::uint64_t now) {
    if (membership.forked()) throw Error(ErrorCode::Forked);
    clock(log, now);
    const auto &state = membership.current();
    if (member(state, local.id) != local) fail(JournalCode::WrongPins);
    checkEventKey(log, genesis, state, key);
    return state;
}

SignedEventHistory authenticateHistory(const Membership &membership, const SyncKey &key,
                                       const std::vector<events::Envelope> &input, events::Limits limits,
                                       bool sharedTransport) {
    SignedEventCodec::validateLimits(limits);
    if (input.size() > limits.events) throw Error(ErrorCode::Limit);
    std::size_t remainingWire = limits.historyBytes;
    for (const auto &wire : input) {
        if (wire.bytes.size() > limits.eventBytes || wire.bytes.size() > remainingWire)
            throw Error(ErrorCode::Limit);
        remainingWire -= wire.bytes.size();
    }
    const auto &state = membership.current();
    const auto authors = eventAuthors(state);
    std::vector<events::Event> decoded;
    WipeEvents wipe{decoded};
    std::vector<history::Revision> revisions;
    std::vector<EventEvidence> evidence;
    std::map<std::string, std::size_t> positions;
    std::map<std::string, Token> digests;
    decoded.reserve(input.size()); revisions.reserve(input.size()); evidence.reserve(input.size());
    std::size_t remainingPlain = limits.historyPlaintextBytes;
    std::size_t roots = 0;
    for (const auto &wire : input) {
        auto header = SignedEventCodec::inspect(wire.bytes, limits);
        if (sharedTransport && header.version != SignedEventCodec::CurrentVersion) fail(JournalCode::EventVersion);
        const auto &claimed = header.context;
        if (claimed.group != state.group || claimed.root != state.root) throw Error(ErrorCode::WrongGroup);
        if (claimed.generation != state.keyGeneration || claimed.commitment != state.keyCommitment)
            throw Error(ErrorCode::Stale);
        const auto *head = membership.acceptedState(claimed.head);
        if (!head) throw Error(ErrorCode::MissingParent);
        if (head->keyGeneration != state.keyGeneration || head->keyCommitment != state.keyCommitment)
            throw Error(ErrorCode::Stale);
        const auto &author = member(*head, claimed.author);
        if (member(state, claimed.author) != author) throw Error(ErrorCode::NotMember);
        if (!remainingPlain) throw Error(ErrorCode::Limit);
        auto perEvent = limits;
        perEvent.plaintextBytes = std::min(limits.plaintextBytes, remainingPlain);
        decoded.push_back(SignedEventCodec::open(wire, eventContext(*head, author.id), author, key, perEvent));
        const auto &event = decoded.back();
        if (event.plaintextBytes > remainingPlain) throw Error(ErrorCode::Limit);
        remainingPlain -= event.plaintextBytes;
        if (!positions.emplace(event.revision.id, revisions.size()).second)
            throw history::Error(history::ErrorCode::DuplicateRevision, "Duplicate signed revision ID");
        digests.emplace(event.revision.id, SignedEventCodec::digest(wire.bytes));
        revisions.push_back(event.revision);
        if (sharedTransport && header.parents.empty() && ++roots > 1) fail(JournalCode::EventPublication);
        evidence.push_back({std::move(header.parents), head->epoch, authors.at(author.id)});
    }
    auto graph = checkedSignedGraph(revisions, evidence, positions, digests);
    wipe.released = true;
    return {std::move(decoded), std::move(graph), std::move(digests)};
}

storage::SignedEventScope eventScope(const State &state) {
    return {state.group, state.root, state.keyGeneration};
}

std::vector<events::Envelope> transportEnvelopes(const std::vector<storage::SignedEventPacket> &packets,
                                                const EventLedger &ledger, const std::string &localDevice,
                                                const std::string &attemptedId, std::string_view attemptedWire,
                                                bool restoreAttempted = false) {
    std::vector<events::Envelope> input;
    input.reserve(packets.size());
    std::size_t known = 0;
    bool attemptedVisible = false;
    for (const auto &packet : packets) {
        if (packet.id == attemptedId) attemptedVisible = true;
        const auto witness = ledger.witnesses.find(packet.id);
        if (witness != ledger.witnesses.end()) {
            if (SignedEventCodec::digest(packet.wire) != witness->second) fail(JournalCode::HistoryChanged);
            ++known;
        } else if (std::string_view(packet.id).substr(0, localDevice.size()) == localDevice &&
                   (packet.id != attemptedId || packet.wire != attemptedWire)) {
            fail(JournalCode::HistoryChanged);
        }
        input.push_back({packet.id, packet.wire});
    }
    if (known != ledger.witnesses.size()) {
        const auto attempted = ledger.witnesses.find(attemptedId);
        if (!restoreAttempted || attemptedVisible || known + 1 != ledger.witnesses.size() ||
            attempted == ledger.witnesses.end() || SignedEventCodec::digest(attemptedWire) != attempted->second)
            fail(JournalCode::HistoryChanged);
    }
    return input;
}

std::string_view eventBytes(const Bytes &wire) {
    return {reinterpret_cast<const char *>(wire.data()), wire.size()};
}
} // namespace

SignedEventHistory TrustJournal::readSignedHistory(const SyncKey &key, const std::vector<events::Envelope> &input,
                                                  std::uint64_t now, events::Limits limits) {
    const auto lease = lock(); const auto record = load();
    const auto log = decode(record, binding_, pin(genesis_, local_));
    const auto membership = replay(log, genesis_, local_);
    (void)clipboardAuthority(log, membership, genesis_, local_, key, now);
    return authenticateHistory(membership, key, input, limits, false);
}

SignedEventHistory TrustJournal::scanClipboardEvents(const SyncKey &key, const storage::Directory &transport,
                                                     std::uint64_t now, events::Limits limits) {
    SignedEventCodec::validateLimits(limits);
    const auto lease = lock(); const auto record = load();
    const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    const auto membership = replay(log, genesis_, local_);
    const auto &state = clipboardAuthority(log, membership, genesis_, local_, key, now);
    if (log.migration && !log.migration->completed) fail(JournalCode::Migration);
    const auto localDevice = SignedEventCodec::deviceName(local_.id);
    auto &ledger = eventLedger(log, state.keyGeneration);
    const auto folder = transport.openSignedEvents(eventScope(state));
    const auto packets = folder->scan({limits});
    std::string attemptedId;
    std::string_view attemptedWire;
    if (ledger.publicationAttempted) {
        attemptedId = history::makeId(localDevice, log.allocatedSequence);
        attemptedWire = eventBytes(*log.pendingEvent);
    }
    const auto input = transportEnvelopes(packets, ledger, localDevice, attemptedId, attemptedWire);
    if (ledger.publicationAttempted &&
        std::none_of(packets.begin(), packets.end(), [&](const auto &packet) { return packet.id == attemptedId; }))
        fail(JournalCode::EventPublication);
    auto result = authenticateHistory(membership, key, input, limits, true);
    WipeEvents wipe{result.events};
    if (!result.wireDigests.empty()) {
        ledger.witnesses = result.wireDigests;
        log.watermark = now;
        auto replacement = record;
        storeLog(replacement, log, pins);
        save(record, replacement);
    }
    wipe.released = true;
    return result;
}

std::string TrustJournal::publishClipboardEvent(std::uint64_t sequence, const SyncKey &key,
                                                const storage::Directory &transport, std::uint64_t now,
                                                ClipboardPublication mode, const std::filesystem::path &privateStaging) {
    const auto lease = lock();
    return publishClipboardEventLocked(sequence, key, transport, now, mode, privateStaging);
}

std::string TrustJournal::publishClipboardEventLocked(std::uint64_t sequence, const SyncKey &key,
    const storage::Directory &transport, std::uint64_t now, ClipboardPublication mode,
    const std::filesystem::path &privateStaging, const Token *migration) {
    const auto record = load();
    const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    std::uint64_t pendingGeneration = 0;
    const auto membership = replay(log, genesis_, local_, nullptr, &pendingGeneration);
    const auto &state = clipboardAuthority(log, membership, genesis_, local_, key, now);
    if (migration) {
        if (!log.migration || !sameConfirmation(log.migration->confirmation, *migration) ||
            log.migration->sequence != sequence || state.keyGeneration || mode != ClipboardPublication::Seed ||
            (!log.migration->completed && state.epoch))
            fail(JournalCode::Migration);
    } else if (log.migration && (!log.migration->completed || log.migration->sequence == sequence)) {
        fail(JournalCode::Migration);
    }
    const auto localDevice = SignedEventCodec::deviceName(local_.id);
    if (!sequence || sequence > log.allocatedSequence) fail(JournalCode::EventReservation);
    const auto id = history::makeId(localDevice, sequence);
    auto &ledger = eventLedger(log, state.keyGeneration);
    const bool pending = log.pendingEvent && sequence == log.allocatedSequence;
    std::string_view wire;
    if (pending) {
        if (log.pendingEvent->empty()) fail(JournalCode::EventReservation);
        if (pendingGeneration != state.keyGeneration) throw Error(ErrorCode::Stale);
        wire = eventBytes(*log.pendingEvent);
        if (SignedEventCodec::inspect(wire).version != SignedEventCodec::CurrentVersion) fail(JournalCode::EventVersion);
    } else if (!ledger.witnesses.count(id) || ledger.publicationAttempted) {
        fail(JournalCode::EventReservation);
    }
    const auto folder = transport.openSignedEvents(eventScope(state));
    const auto packets = folder->scan();
    const std::string attemptedId = ledger.publicationAttempted ? id : std::string{};
    auto input = transportEnvelopes(packets, ledger, localDevice,
        attemptedId, ledger.publicationAttempted ? wire : std::string_view{}, ledger.publicationAttempted);
    const auto existing = std::find_if(packets.begin(), packets.end(), [&](const auto &packet) { return packet.id == id; });
    const bool visible = existing != packets.end();
    if (!pending) wire = existing->wire; // Every completed ID has a required witness.
    else if (visible && existing->wire != wire) fail(JournalCode::HistoryChanged);
    const bool seed = SignedEventCodec::inspect(wire).parents.empty();
    if (seed != (mode == ClipboardPublication::Seed) ||
        (seed && !visible && !packets.empty() && !ledger.publicationAttempted))
        fail(JournalCode::EventPublication);
    if (!visible) input.push_back({id, wire});
    auto verified = authenticateHistory(membership, key, input, {}, true);
    const WipeEvents wipe{verified.events};
    if (pending && record.generation >= std::numeric_limits<std::uint64_t>::max() - 1)
        throw Error(ErrorCode::Overflow);
    transport.checkPublicationStaging(privateStaging);

    // Record all visible evidence and irrevocably mark the slot before any
    // native publication. An absent candidate is witnessed only after success.
    const bool firstObservation = !ledger.witnesses.count(id);
    ledger.witnesses = verified.wireDigests;
    if (!visible && firstObservation) ledger.witnesses.erase(id);
    ledger.publicationAttempted = pending;
    log.watermark = now;
    auto attempted = record;
    storeLog(attempted, log, pins);
    save(record, attempted);
    folder->publish({id, wire}, privateStaging);
    if (pending) {
        ledger.witnesses = std::move(verified.wireDigests);
        ledger.publicationAttempted = false;
        log.pendingEvent.reset();
        if (migration) log.migration->completed = true;
        auto finished = attempted;
        storeLog(finished, log, pins);
        save(attempted, finished);
    }
    return id;
}

namespace {
Token migrationConfirmation(const VerifiedLegacyArchive &archive, const LegacyArchiveSource &source,
    const Log &log, const Membership &membership, const Genesis &genesis, const Member &local,
    const SyncKey &key, std::uint64_t now) {
    const auto &state = clipboardAuthority(log, membership, genesis, local, key, now);
    if (local != genesis.founder || state.keyGeneration ||
        ((!log.migration || !log.migration->completed) && state.epoch) ||
        (!log.migration && (!log.entries.empty() || log.allocatedSequence ||
                            (log.eventLedger && !log.eventLedger->witnesses.empty()))))
        fail(JournalCode::Migration);
    if (key.sameKey(*SyncKey::import(source.legacyKey))) fail(JournalCode::Migration);
    const auto confirmation = archive.confirmation(eventContext(state, local.id));
    if (confirmation == Token{} || (log.migration && !sameConfirmation(log.migration->confirmation, confirmation)))
        fail(JournalCode::Migration);
    if (!log.migration || (log.pendingEvent && log.pendingEvent->empty())) {
        events::Limits limits;
        limits.eventBytes = TrustJournal::MaxClipboardEventBytes;
        SignedEventCodec::validateSeedPayload(archive.packedItems(), limits);
    }
    return confirmation;
}
} // namespace

Token TrustJournal::previewLegacyMigration(const LegacyArchiveSource &source, const SyncKey &key,
                                          std::uint64_t now) {
    const VerifiedLegacyArchive archive(source);
    const auto lease = lock();
    const auto log = decode(load(), binding_, pin(genesis_, local_));
    const auto membership = replay(log, genesis_, local_);
    return migrationConfirmation(archive, source, log, membership, genesis_, local_, key, now);
}

std::string TrustJournal::migrateLegacyArchive(const LegacyArchiveSource &source, const Token &confirmed,
    const Identity &founder, const SyncKey &key, const storage::Directory &successor, std::uint64_t now,
    const std::filesystem::path &privateStaging) {
    const VerifiedLegacyArchive archive(source);
    const auto lease = lock();
    const auto log = decode(load(), binding_, pin(genesis_, local_));
    const auto membership = replay(log, genesis_, local_);
    if (founder.member() != local_) fail(JournalCode::WrongPins);
    if (!sameConfirmation(migrationConfirmation(archive, source, log, membership, genesis_, local_, key, now), confirmed))
        fail(JournalCode::Confirmation);
    successor.checkPublicationStaging(privateStaging);
    if (!log.migration && !successor.openSignedEvents(eventScope(membership.current()))->scan().empty())
        fail(JournalCode::Migration);

    const bool needsPacket = !log.migration || (log.pendingEvent && log.pendingEvent->empty());
    const auto sequence = needsPacket
        ? prepareClipboardEventLocked(founder, key, {}, archive.packedItems(), now, {}, &confirmed).sequence
        : log.migration->sequence;
    return publishClipboardEventLocked(sequence, key, successor, now, ClipboardPublication::Seed,
                                       privateStaging, &confirmed);
}
} // namespace cqs::trust
