// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_trust_journal.h"
#include "device_archive_migration.h"
#include "device_identity.h"
#include "device_key_envelope.h"
#include "device_key_receipt.h"
#include "packed_items.h"
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
struct Enrollment {
    Token request, acceptedIntent;
};
enum class ReplicaPublicationState : std::uint8_t { Unattempted = 1, PossiblyPublished, ConfirmedPublished };
struct ReplicaEvidence {
    Token tag;
    std::uint64_t generation;
    ReplicaPublicationState publication;
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
    std::optional<Enrollment> enrollment;
    std::optional<Token> replicaTag;
    std::optional<ReplicaEvidence> replicaEvidence;
};
[[noreturn]] void fail(JournalCode code) { throw JournalError(code); }
bool sameConfirmation(const Token &a, const Token &b) noexcept {
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}
Token randomJoinToken() {
    const auto random = crypto::random(Token{}.size());
    Token token{};
    std::copy(random.begin(), random.end(), token.begin());
    if (token == Token{}) fail(JournalCode::Enrollment);
    return token;
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
        (!log.allocatedSequence && log.pendingEvent) ||
        (log.enrollment && (!log.eventLedger || log.migration)) ||
        ((log.replicaTag || log.replicaEvidence) && (!log.enrollment || log.enrollment->acceptedIntent == Token{})) ||
        (log.replicaTag && (!log.pendingEvent || *log.replicaTag == Token{})) ||
        (log.replicaEvidence && (log.replicaEvidence->tag == Token{} || !log.allocatedSequence)))
        fail(JournalCode::Invalid);
    const bool lifecycle = !log.deliveries.empty() || !log.installed.empty();
    const auto version = log.enrollment ? (log.replicaEvidence ? 9 : (log.replicaTag ? 8 : 7)) : (log.migration ? 6 :
        (log.eventLedger ? 5 : (log.allocatedSequence ? 4 : (lifecycle ? 3 : 1))));
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
    if (log.enrollment) {
        append(out, log.enrollment->request);
        append(out, log.enrollment->acceptedIntent);
    }
    if (version == 9) out.push_back(log.replicaTag ? 1 : 0);
    if (log.replicaTag) append(out, *log.replicaTag);
    if (log.replicaEvidence) {
        append(out, log.replicaEvidence->tag);
        u64(out, log.replicaEvidence->generation);
        out.push_back(static_cast<std::uint8_t>(log.replicaEvidence->publication));
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
    if (version < 1 || version > 9) fail(JournalCode::Invalid);
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
    if (version >= 7) {
        const auto request = reader.token();
        const auto acceptedIntent = reader.token();
        if (request == Token{}) fail(JournalCode::Invalid);
        log.enrollment = Enrollment{request, acceptedIntent};
    }
    const auto tagged = version == 9 ? reader.byte() : (version == 8 ? 1 : 0);
    if (tagged > 1) fail(JournalCode::Invalid);
    if (tagged) {
        const auto tag = reader.token();
        if (tag == Token{} || !log.pendingEvent || log.enrollment->acceptedIntent == Token{})
            fail(JournalCode::Invalid);
        log.replicaTag = tag;
    }
    if (version == 9) {
        const auto tag = reader.token();
        const auto generation = reader.number64();
        const auto publication = static_cast<ReplicaPublicationState>(reader.byte());
        if (tag == Token{} || !log.allocatedSequence || log.enrollment->acceptedIntent == Token{} ||
            publication < ReplicaPublicationState::Unattempted || publication > ReplicaPublicationState::ConfirmedPublished ||
            (log.replicaTag && (tag != *log.replicaTag || publication == ReplicaPublicationState::ConfirmedPublished)))
            fail(JournalCode::Invalid);
        log.replicaEvidence = ReplicaEvidence{tag, generation, publication};
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
bool hasIdentity(const std::vector<Member> &members, const Token &id) {
    return std::any_of(members.begin(), members.end(), [&](const Member &m) { return m.id == id; });
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
    bool acceptedJoin = false;
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
            const auto &proposal = certificate.proposal;
            if (log.enrollment && result == ObserveResult::Applied &&
                proposal.operation == Operation::Add && proposal.subject.id == local.id) {
                if (acceptedJoin || proposal.subject != local || proposal.request != log.enrollment->request ||
                    proposalDigest(proposal) != log.enrollment->acceptedIntent) fail(JournalCode::Invalid);
                acceptedJoin = true;
            }
            if (claimed && result == ObserveResult::Applied && membership.current().digest == claimed->successor) {
                proof = incoming(membership.current(), certificate.proposal, local, *claimed);
                KeyEnvelopeCodec::verify(log.installed, proof->context, proof->sender);
            }
        }
        watermark = std::max(watermark, entry.now);
    }
    if (log.watermark < watermark) fail(JournalCode::Invalid);
    if (log.enrollment &&
        (local.id == g.founder.id || acceptedJoin != (log.enrollment->acceptedIntent != Token{})))
        fail(JournalCode::Invalid);
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
    if (log.replicaEvidence &&
        (log.replicaEvidence->generation > membership.current().keyGeneration ||
         (log.replicaTag && log.replicaEvidence->generation == membership.current().keyGeneration)))
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
        if (log.replicaTag && log.replicaEvidence && log.replicaEvidence->generation != context.generation)
            fail(JournalCode::Invalid);
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
    record.keyIdentity = hex(pins);
    Log log;
    log.initial = log.watermark = now;
    storeLog(record, log, pins);
    return record;
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
                         log.allocatedSequence, {}, 0, 0, {}, false};
    result.verifiedJoin = log.enrollment && log.enrollment->acceptedIntent != Token{};
    if (log.migration)
        result.migration = ArchiveMigrationStatus{log.migration->sequence, log.migration->completed};
    if (log.eventLedger) {
        result.eventEncryptionAttempts = log.eventLedger->attempts;
        result.eventWitnesses = log.eventLedger->witnesses.size();
    }
    if (log.pendingEvent) {
        const bool recordedAttempt = log.replicaTag && log.replicaEvidence &&
            log.replicaEvidence->publication == ReplicaPublicationState::PossiblyPublished;
        result.pendingEvent = PendingClipboardEvent{log.allocatedSequence, !log.pendingEvent->empty(),
            recordedAttempt || (log.eventLedger && log.eventLedger->publicationAttempted)};
    }
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

JoinRequest TrustJournal::beginJoin(const Identity &applicant, std::uint64_t now) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    const auto membership = replay(log, genesis_, local_);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    if (applicant.member() != local_) fail(JournalCode::WrongPins);
    clock(log, now);
    const auto &state = membership.current();
    if (hasIdentity(state.members, local_.id) || hasIdentity(state.retired, local_.id) || log.migration)
        fail(JournalCode::Enrollment);
    if (!log.enrollment) {
        log.enrollment = Enrollment{randomJoinToken(), {}};
        (void)eventLedger(log, state.keyGeneration);
    }
    log.watermark = now;
    auto replacement = record;
    storeLog(replacement, log, pins);
    save(record, replacement);
    return {local_, log.enrollment->request};
}

Proposal TrustJournal::proposeJoin(const JoinRequest &request, std::uint64_t now, std::uint64_t expires) {
    return propose(Operation::Add, request.applicant, request.request, randomJoinToken(), now, expires);
}

JoinReview TrustJournal::reviewJoin(const Proposal &proposal, const std::vector<Token> &approvers,
                                   std::uint64_t now) {
    const auto lease = lock(); const auto record = load();
    const auto log = decode(record, binding_, pin(genesis_, local_));
    const auto membership = replay(log, genesis_, local_);
    clock(log, now);
    if (!log.enrollment || log.enrollment->acceptedIntent != Token{}) fail(JournalCode::Enrollment);
    return reviewJoinProposal(membership, proposal, {local_, log.enrollment->request}, approvers, now);
}

JoinReview TrustJournal::reviewJoinApproval(const Proposal &proposal, std::uint64_t now) {
    const auto lease = lock(); const auto record = load();
    const auto log = decode(record, binding_, pin(genesis_, local_));
    const auto membership = replay(log, genesis_, local_);
    clock(log, now);
    if (log.migration && !log.migration->completed) fail(JournalCode::Migration);
    return trust::reviewJoinApproval(membership, proposal, local_, now);
}

ObserveResult TrustJournal::acceptJoin(const Certificate &certificate,
                                      const std::vector<JoinConfirmation> &confirmations, std::uint64_t now) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    auto membership = replay(log, genesis_, local_);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    clock(log, now);
    if (!log.enrollment) fail(JournalCode::Enrollment);
    const auto &proposal = certificate.proposal;
    const auto wire = encodeCertificate(certificate);
    const auto intent = proposalDigest(proposal);
    if (intent == Token{}) fail(JournalCode::Enrollment);
    const bool accepted = log.enrollment->acceptedIntent != Token{};
    if (accepted) {
        if (member(membership.current(), local_.id) != local_ || intent != log.enrollment->acceptedIntent ||
            std::none_of(log.entries.begin(), log.entries.end(), [&](const Entry &entry) {
                return entry.kind == Kind::Observe && entry.bytes == wire;
            })) fail(JournalCode::Enrollment);
    } else {
        std::vector<Token> approvers;
        approvers.reserve(certificate.approvals.size());
        for (const auto &approval : certificate.approvals) approvers.push_back(approval.signer);
        const auto review = reviewJoinProposal(membership, proposal, {local_, log.enrollment->request}, approvers, now);
        verifyJoinConfirmations(review, confirmations);
        if (membership.observe(certificate, now, SodiumVerifier{}) != ObserveResult::Applied)
            fail(JournalCode::Enrollment);
        add(log, Kind::Observe, now, wire);
        log.enrollment->acceptedIntent = intent;
        log.deliveries.clear();
    }
    // The accepted Add and its locally verified enrollment marker share one
    // durability barrier. An exact retry confirms that barrier after reopen.
    log.watermark = now;
    auto replacement = record;
    storeLog(replacement, log, pins);
    save(record, replacement);
    return accepted ? ObserveResult::AlreadyKnown : ObserveResult::Applied;
}

ObserveResult TrustJournal::observe(const Certificate &certificate, std::uint64_t now) {
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins); auto membership = replay(log, genesis_, local_);
    valid(certificate.proposal.subject); SodiumVerifier verifier;
    const auto previousGeneration = membership.current().keyGeneration;
    const auto result = membership.observe(certificate, now, verifier);
    if (result == ObserveResult::AlreadyKnown) return result;
    if (result == ObserveResult::Applied && log.enrollment && certificate.proposal.operation == Operation::Add &&
        certificate.proposal.subject.id == local_.id) fail(JournalCode::Enrollment);
    if (result == ObserveResult::Applied) clock(log, now);
    else if (!now) fail(JournalCode::ClockRollback);
    add(log, Kind::Observe, now, encodeCertificate(certificate));
    log.deliveries.clear();
    if (membership.forked() || previousGeneration != membership.current().keyGeneration)
        log.installed.clear();
    if (log.eventLedger && previousGeneration != membership.current().keyGeneration) {
        if (log.replicaTag && !log.replicaEvidence && log.eventLedger->attempts) {
            const auto publication = log.eventLedger->publicationAttempted
                ? ReplicaPublicationState::PossiblyPublished : ReplicaPublicationState::Unattempted;
            log.replicaEvidence = ReplicaEvidence{*log.replicaTag, previousGeneration, publication};
        }
        log.eventLedger = EventLedger{membership.current().keyGeneration, 0, false, {}};
    }
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
    std::uint64_t now, events::Limits limits, const Token *migration, const Token *replicaTag) {
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
    if (replicaTag) {
        log.replicaTag = *replicaTag;
        log.replicaEvidence.reset();
    }
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
    if (!log.pendingEvent || log.pendingEvent->empty() || sequence != log.allocatedSequence || log.replicaTag)
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
    if (!log.pendingEvent || sequence != log.allocatedSequence || log.replicaTag) fail(JournalCode::EventReservation);
    if (log.migration && !log.migration->completed) fail(JournalCode::Migration);
    if (log.eventLedger && log.eventLedger->publicationAttempted) fail(JournalCode::EventPublication);
    log.pendingEvent.reset();
    log.watermark = now;
    auto replacement = record;
    storeLog(replacement, log, pins);
    save(record, replacement);
}

namespace {
struct WipeItems {
    std::vector<std::string> &items;
    ~WipeItems() {
        for (auto &item : items) if (!item.empty()) sodium_memzero(item.data(), item.size());
    }
};
struct WipeEvents {
    std::vector<events::Event> &events;
    bool released = false;
    ~WipeEvents() {
        if (!released) for (auto &event : events) { const WipeItems wipe{event.items}; }
    }
};
struct WipeSnapshot {
    transaction::Snapshot &snapshot;
    ~WipeSnapshot() {
        for (auto &item : snapshot) for (auto &field : item) crypto::wipe(field.second);
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
    return {std::move(decoded), std::move(graph), std::move(digests),
            limits.historyBytes - remainingWire, limits.historyPlaintextBytes - remainingPlain};
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

SignedEventHistory verifiedTransportHistory(const storage::Directory &transport, const Membership &membership,
    const SyncKey &key, const Member &local, const Log &log, const EventLedger &ledger, events::Limits limits) {
    const auto localDevice = SignedEventCodec::deviceName(local.id);
    const auto folder = transport.openSignedEvents(eventScope(membership.current()));
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
    return authenticateHistory(membership, key, input, limits, true);
}

Token replicaToken(const Bytes &hash) {
    Token token{};
    if (hash.size() != token.size()) fail(JournalCode::Invalid);
    std::copy(hash.begin(), hash.end(), token.begin());
    return token;
}

Token replicaLocalDigest(const transaction::Snapshot &snapshot) {
    Bytes bytes;
    struct Wipe { Bytes &value; ~Wipe() { crypto::wipe(value); } } wipe{bytes};
    domain(bytes, "CopyQ-Secure-Sync-signed-replica-local-v1");
    u64(bytes, snapshot.size());
    for (const auto &item : snapshot) {
        u64(bytes, item.size());
        for (const auto &entry : item) {
            u64(bytes, entry.first.size()); append(bytes, entry.first);
            u64(bytes, entry.second.size()); append(bytes, entry.second);
        }
    }
    return replicaToken(crypto::sha256(bytes));
}

bool sameReplicaParents(const std::vector<SignedEventParent> &a, const std::vector<SignedEventParent> &b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](const auto &x, const auto &y) {
        return x.id == y.id && sameConfirmation(x.digest, y.digest);
    });
}

std::vector<SignedEventParent> replicaParents(const SignedReplicaState &replica) {
    if (!replica.pending->mergeParents.empty()) return replica.pending->mergeParents;
    return {{replica.cursor.id, replica.cursor.digest}};
}

void validateReplica(const JoinActivation &activation, const SignedReplicaState &replica,
                     const transaction::Snapshot &local) {
    state::validateBinding(activation.profileBinding);
    packed::validateSnapshot(local, {});
    if (!storage::validSignedEventId(activation.tipId) || !storage::validSignedEventId(replica.cursor.id) ||
        activation.tipDigest == Token{} || replica.cursor.digest == Token{}) fail(JournalCode::Enrollment);
    if (!replica.pending) return;
    const auto &intent = *replica.pending;
    if (!intent.sequence || intent.sequence > history::MaxSequence || intent.payload == Token{})
        fail(JournalCode::EventReservation);
    if (intent.mergeParents.empty()) {
        if (intent.localBefore != Token{} || !intent.selectedTip.empty()) fail(JournalCode::EventReservation);
        return;
    }
    if (intent.mergeParents.size() > 2 || intent.localBefore == Token{}) fail(JournalCode::EventReservation);
    std::string_view previous;
    bool selected = intent.selectedTip.empty();
    for (const auto &parent : intent.mergeParents) {
        if (!storage::validSignedEventId(parent.id) || parent.digest == Token{} || parent.id <= previous)
            fail(JournalCode::EventReservation);
        previous = parent.id;
        if (intent.selectedTip == parent.id) selected = true;
    }
    if (!selected) fail(JournalCode::EventReservation);
}

Token replicaTag(const JoinActivation &activation, const SignedReplicaState &replica) {
    Bytes bytes;
    domain(bytes, "CopyQ-Secure-Sync-signed-replica-reservation-v1");
    u64(bytes, activation.profileBinding.size()); append(bytes, activation.profileBinding);
    append(bytes, activation.group); append(bytes, activation.root);
    append(bytes, activation.head); append(bytes, activation.member); u64(bytes, activation.generation);
    append(bytes, activation.tipId); append(bytes, activation.tipDigest);
    append(bytes, replica.cursor.id); append(bytes, replica.cursor.digest);
    u64(bytes, replica.pending->sequence); append(bytes, replica.pending->payload);
    if (!replica.pending->mergeParents.empty()) {
        domain(bytes, "CopyQ-Secure-Sync-signed-replica-resolution-v1");
        append(bytes, replica.pending->localBefore);
        u64(bytes, replica.pending->selectedTip.size()); append(bytes, replica.pending->selectedTip);
        u64(bytes, replica.pending->mergeParents.size());
        for (const auto &parent : replica.pending->mergeParents) {
            append(bytes, parent.id); append(bytes, parent.digest);
        }
    }
    return replicaToken(crypto::sha256(bytes));
}

bool witnessed(const Witnesses &witnesses, const std::string &id, const Token &digest) {
    const auto entry = witnesses.find(id);
    return entry != witnesses.end() && sameConfirmation(entry->second, digest);
}

const events::Event &replicaEvent(const SignedEventHistory &history, const std::string &id) {
    const auto found = std::find_if(history.events.begin(), history.events.end(),
                                   [&](const auto &event) { return event.revision.id == id; });
    if (found == history.events.end()) fail(JournalCode::HistoryChanged);
    return *found;
}

void verifyReplicaHistory(const SignedEventHistory &history, const JoinActivation &activation,
                          const SignedReplicaCursor &cursor) {
    if (!witnessed(history.wireDigests, activation.tipId, activation.tipDigest) ||
        !witnessed(history.wireDigests, cursor.id, cursor.digest) ||
        !history.graph.isAncestor(activation.tipId, cursor.id)) fail(JournalCode::HistoryChanged);
}

void verifyReplicaIntent(const events::Event &event, const SignedReplicaState &replica,
                         const Witnesses *witnesses = nullptr) {
    std::vector<std::string> parents;
    for (const auto &parent : replicaParents(replica)) {
        if (witnesses && !witnessed(*witnesses, parent.id, parent.digest)) fail(JournalCode::EventReservation);
        parents.push_back(parent.id);
    }
    if (event.revision.sequence != replica.pending->sequence ||
        event.revision.parents != parents ||
        !sameConfirmation(replicaToken(events::fingerprint(event)), replica.pending->payload))
        fail(JournalCode::EventReservation);
}

std::unique_ptr<SyncKey> replicaAuthority(const Identity &identity, const JoinActivation &activation,
    const SignedReplicaState &replica, const Log &log, const Membership &membership,
    const std::optional<EnvelopeAuthority> &installed, const Genesis &genesis, const Member &local, std::uint64_t now) {
    if (membership.forked()) throw Error(ErrorCode::Forked);
    if (identity.member() != local || activation.member != local.id) fail(JournalCode::WrongPins);
    if (!log.enrollment || log.enrollment->acceptedIntent == Token{} || !log.eventLedger)
        fail(JournalCode::Enrollment);
    const auto &state = membership.current();
    const auto *admitted = membership.acceptedState(activation.head);
    if (!admitted || activation.group != state.group || activation.root != state.root ||
        activation.generation != state.keyGeneration || activation.generation != admitted->keyGeneration ||
        member(*admitted, local.id) != local) fail(JournalCode::HistoryChanged);
    if (!installed) fail(JournalCode::MissingKey);
    auto key = KeyEnvelopeCodec::open(log.installed, installed->context, installed->sender, identity);
    (void)clipboardAuthority(log, membership, genesis, local, *key, now);
    if (!witnessed(log.eventLedger->witnesses, activation.tipId, activation.tipDigest) ||
        !witnessed(log.eventLedger->witnesses, replica.cursor.id, replica.cursor.digest))
        fail(JournalCode::HistoryChanged);
    return key;
}

std::vector<SignedEventParent> replicaTips(const SignedEventHistory &verified) {
    std::vector<SignedEventParent> tips;
    for (const auto &id : verified.graph.tips()) tips.push_back({id, verified.wireDigests.at(id)});
    return tips;
}

bool replicaConflict(const SignedEventHistory &verified, const SignedReplicaState &replica,
                     const transaction::Snapshot &local) {
    const auto &tips = verified.graph.tips();
    if (tips.size() != 1 || !verified.graph.isAncestor(replica.cursor.id, tips.front())) return true;
    if (tips.front() == replica.cursor.id) return false;
    auto base = packed::decode(replicaEvent(verified, replica.cursor.id).items);
    const WipeSnapshot wipe{base};
    return base != local;
}
} // namespace

struct TrustJournal::ReplicaPublication {
    const JoinActivation &activation;
    const SignedReplicaState &state;
    const Token &tag;
    const std::function<bool()> &canProceed;
};

struct TrustJournal::ReplicaResolution {
    const SignedReplicaConflict &review;
    const std::string &selectedTip;
};

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
    auto &ledger = eventLedger(log, state.keyGeneration);
    auto result = verifiedTransportHistory(transport, membership, key, local_, log, ledger, limits);
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

JoinActivation TrustJournal::preflightJoinActivation(const Identity &applicant, const storage::Directory &transport,
                                                      std::string profileBinding, std::uint64_t now) {
    return verifyJoinActivation(applicant, transport, std::move(profileBinding), now, nullptr, {});
}

void TrustJournal::applyJoinActivation(const Identity &applicant, const storage::Directory &transport,
                                       const JoinActivation &expected, std::uint64_t now,
                                       const JoinActivationWriter &write) {
    if (!write) fail(JournalCode::Enrollment);
    (void)verifyJoinActivation(applicant, transport, expected.profileBinding, now, &expected, write);
}

JoinActivation TrustJournal::verifyJoinActivation(const Identity &applicant, const storage::Directory &transport,
    std::string profileBinding, std::uint64_t now, const JoinActivation *expected, const JoinActivationWriter &write) {
    state::validateBinding(profileBinding);
    const auto lease = lock(); const auto record = load(); const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    std::optional<EnvelopeAuthority> installed;
    const auto membership = replay(log, genesis_, local_, &installed);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    if (applicant.member() != local_) fail(JournalCode::WrongPins);
    clock(log, now);
    if (!log.enrollment || log.enrollment->acceptedIntent == Token{} || log.pendingEvent)
        fail(JournalCode::Enrollment);
    if (!installed) fail(JournalCode::MissingKey);
    const auto key = KeyEnvelopeCodec::open(log.installed, installed->context, installed->sender, applicant);
    const auto &state = clipboardAuthority(log, membership, genesis_, local_, *key, now);
    auto &ledger = eventLedger(log, state.keyGeneration);
    auto verified = verifiedTransportHistory(transport, membership, *key, local_, log, ledger, {});
    const WipeEvents wipe{verified.events};
    const auto &tips = verified.graph.tips();
    if (tips.size() != 1) fail(JournalCode::Enrollment);
    const auto &id = tips.front();
    const auto tip = std::find_if(verified.events.begin(), verified.events.end(),
                                  [&](const auto &event) { return event.revision.id == id; });
    if (tip == verified.events.end()) fail(JournalCode::Invalid);
    JoinActivation result{std::move(profileBinding), state.group, state.root, state.digest, local_.id,
                          verified.wireDigests.at(id), state.keyGeneration, id};
    if (expected && (result.group != expected->group || result.root != expected->root ||
        result.head != expected->head || result.member != expected->member || result.tipDigest != expected->tipDigest ||
        result.generation != expected->generation || result.tipId != expected->tipId))
        fail(JournalCode::HistoryChanged);
    auto snapshot = packed::decode(tip->items);
    const WipeSnapshot wipeSnapshot{snapshot};
    ledger.witnesses = std::move(verified.wireDigests);
    log.watermark = now;
    auto replacement = record;
    storeLog(replacement, log, pins);
    save(record, replacement);
    if (write) write(result, *tip, snapshot);
    return result;
}

SignedReplicaResult TrustJournal::synchronizeReplica(const Identity &identity, const storage::Directory &transport,
    const JoinActivation &activation, SignedReplicaState replica, const transaction::Snapshot &local,
    std::uint64_t now, const SignedReplicaWriter &write, const std::filesystem::path &privateStaging,
    const SignedReplicaTargetValidator &validateTarget, const std::function<bool()> &canProceed) {
    return synchronizeReplicaImpl(identity, transport, activation, std::move(replica), local, now, write,
                                  privateStaging, validateTarget, canProceed, nullptr);
}

std::optional<SignedReplicaConflict> TrustJournal::reviewReplicaConflict(const Identity &identity,
    const storage::Directory &transport, const JoinActivation &activation, const SignedReplicaState &replica,
    const transaction::Snapshot &local, std::uint64_t now) {
    validateReplica(activation, replica, local);
    if (replica.pending) fail(JournalCode::EventPending);
    const auto lease = lock();
    const auto record = load();
    const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    if (log.pendingEvent) fail(JournalCode::EventPending);
    std::optional<EnvelopeAuthority> installed;
    const auto membership = replay(log, genesis_, local_, &installed);
    const auto key = replicaAuthority(identity, activation, replica, log, membership, installed, genesis_, local_, now);
    auto &ledger = *log.eventLedger;
    auto verified = verifiedTransportHistory(transport, membership, *key, local_, log, ledger, {});
    const WipeEvents wipe{verified.events};
    verifyReplicaHistory(verified, activation, replica.cursor);
    if (ledger.witnesses != verified.wireDigests || log.watermark != now) {
        ledger.witnesses = verified.wireDigests;
        log.watermark = now;
        auto replacement = record;
        storeLog(replacement, log, pins);
        save(record, replacement);
    }
    if (!replicaConflict(verified, replica, local)) return {};
    const auto tips = replicaTips(verified);
    if (tips.empty() || tips.size() > 2) throw Error(ErrorCode::Limit);
    return SignedReplicaConflict{tips, replica.cursor, replicaLocalDigest(local), activation.profileBinding};
}

SignedReplicaResult TrustJournal::resolveReplicaConflict(const Identity &identity, const storage::Directory &transport,
    const JoinActivation &activation, SignedReplicaState replica, const transaction::Snapshot &local,
    const SignedReplicaConflict &review, const std::string &selectedTip, std::uint64_t now,
    const SignedReplicaWriter &write, const std::filesystem::path &privateStaging,
    const SignedReplicaTargetValidator &validateTarget) {
    const ReplicaResolution resolution{review, selectedTip};
    return synchronizeReplicaImpl(identity, transport, activation, std::move(replica), local, now, write,
                                  privateStaging, validateTarget, {}, &resolution);
}

SignedReplicaResult TrustJournal::synchronizeReplicaImpl(const Identity &identity, const storage::Directory &transport,
    const JoinActivation &activation, SignedReplicaState replica, const transaction::Snapshot &local,
    std::uint64_t now, const SignedReplicaWriter &write, const std::filesystem::path &privateStaging,
    const SignedReplicaTargetValidator &validateTarget, const std::function<bool()> &canProceed,
    const ReplicaResolution *resolution) {
    using Result = SignedReplicaResult;
    validateReplica(activation, replica, local);
    if (!write) fail(JournalCode::Enrollment);
    const auto checkProceed = [&] {
        if (canProceed && !canProceed()) fail(JournalCode::EventPublication);
    };
    checkProceed();
    if ((resolution || canProceed) && replica.pending) fail(JournalCode::EventPending);
    const auto lease = lock();
    auto record = load();
    const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    if ((resolution || canProceed) && log.pendingEvent) fail(JournalCode::EventPending);
    std::optional<EnvelopeAuthority> installed;
    const auto membership = replay(log, genesis_, local_, &installed);
    const auto key = replicaAuthority(identity, activation, replica, log, membership, installed, genesis_, local_, now);
    const auto persistReplica = [&](const transaction::Snapshot &snapshot) {
        checkProceed();
        write(replica, snapshot);
    };
    const auto device = SignedEventCodec::deviceName(local_.id);
    const auto pendingId = [&] { return history::makeId(device, replica.pending->sequence); };
    const auto persistLog = [&] {
        checkProceed();
        log.watermark = now;
        auto replacement = record;
        storeLog(replacement, log, pins);
        save(record, replacement);
        record = std::move(replacement);
    };
    const auto scan = [&] {
        checkProceed();
        auto &ledger = *log.eventLedger;
        auto verified = verifiedTransportHistory(transport, membership, *key, local_, log, ledger, {});
        WipeEvents wipe{verified.events};
        verifyReplicaHistory(verified, activation, replica.cursor);
        if (ledger.witnesses != verified.wireDigests || (!canProceed && log.watermark != now)) {
            ledger.witnesses = verified.wireDigests;
            persistLog();
        }
        wipe.released = true;
        return verified;
    };
    const auto publish = [&](const Token &tag) {
        const ReplicaPublication authorization{activation, replica, tag, canProceed};
        const auto id = publishClipboardEventLocked(replica.pending->sequence, *key, transport, now,
            ClipboardPublication::Append, privateStaging, nullptr, &authorization);
        if (id.empty()) {
            replica.pending.reset();
            persistReplica(local);
            return false;
        }
        record = load();
        log = decode(record, binding_, pins);
        return true;
    };
    const auto finish = [&](const SignedEventHistory &verified, const std::string &id) {
        const auto &published = replicaEvent(verified, id);
        verifyReplicaIntent(published, replica, &verified.wireDigests);
        const bool acceptRemote = !replica.pending->selectedTip.empty() &&
                                  sameConfirmation(replica.pending->localBefore, replicaLocalDigest(local));
        replica.cursor = {id, verified.wireDigests.at(id)};
        replica.pending.reset();
        if (acceptRemote) {
            auto selected = packed::decode(published.items);
            const WipeSnapshot wipe{selected};
            if (validateTarget) validateTarget(local, selected);
            persistReplica(selected);
        } else {
            persistReplica(local); // Newer edits remain a dirty working copy.
        }
        return verified.graph.hasConflict() ? Result::Conflict : Result::Published;
    };

    if (log.pendingEvent) {
        if (!replica.pending || replica.pending->sequence != log.allocatedSequence ||
            !log.replicaTag || !sameConfirmation(*log.replicaTag, replicaTag(activation, replica)))
            fail(JournalCode::EventReservation);
        if (!log.pendingEvent->empty() && !log.eventLedger->publicationAttempted) {
            const auto wire = eventBytes(*log.pendingEvent);
            const auto header = SignedEventCodec::inspect(wire);
            const auto *preparedHead = membership.acceptedState(header.context.head);
            if (!preparedHead || preparedHead->keyGeneration != membership.current().keyGeneration ||
                !sameReplicaParents(header.parents, replicaParents(replica)))
                fail(JournalCode::EventReservation);
            auto pending = SignedEventCodec::open({pendingId(), wire}, eventContext(*preparedHead, local_.id), local_, *key);
            const WipeItems wipePending{pending.items};
            verifyReplicaIntent(pending, replica);
            bool superseded;
            if (!replica.pending->mergeParents.empty()) {
                superseded = !sameConfirmation(replica.pending->localBefore, replicaLocalDigest(local));
            } else {
                auto prepared = packed::decode(pending.items);
                const WipeSnapshot wipePrepared{prepared};
                superseded = local != prepared;
            }
            if (superseded) {
                // An unattempted packet must not leak a snapshot the user
                // edited or removed before the next explicit sync.
                log.pendingEvent.reset();
                log.replicaTag.reset();
                persistLog();
            } else if (validateTarget) {
                if (replica.pending->selectedTip.empty()) {
                    validateTarget(local, local);
                } else {
                    auto target = packed::decode(pending.items);
                    const WipeSnapshot wipe{target};
                    validateTarget(local, target);
                }
            }
        }
        if (log.pendingEvent && !log.pendingEvent->empty() && !publish(*log.replicaTag)) return Result::Conflict;
    }
    events::Limits preflight;
    std::vector<SignedEventParent> parents;
    std::vector<std::string> selectedItems;
    const WipeItems wipeSelection{selectedItems};
    {
        auto verified = scan();
        const WipeEvents wipe{verified.events};
        if (replica.pending) {
            const auto id = pendingId();
            if (log.eventLedger->witnesses.count(id)) return finish(verified, id);
            // An intent with no allocation, or a tagged allocation that never
            // acquired wire bytes, cannot have reached transport. Retire only
            // this slot, and let this explicit retry re-evaluate the local data.
            if (replica.pending->sequence != log.allocatedSequence &&
                replica.pending->sequence != log.allocatedSequence + 1) fail(JournalCode::EventReservation);
            if (log.pendingEvent) {
                log.pendingEvent.reset();
                log.replicaTag.reset();
                persistLog();
            }
            replica.pending.reset();
            persistReplica(local);
        }
        if (resolution) {
            const auto &review = resolution->review;
            parents = replicaTips(verified);
            if (parents.empty() || parents.size() > 2 || !replicaConflict(verified, replica, local) ||
                !sameReplicaParents(review.tips, parents) || review.cursor.id != replica.cursor.id ||
                !sameConfirmation(review.cursor.digest, replica.cursor.digest) ||
                !sameConfirmation(review.localDigest, replicaLocalDigest(local)) ||
                review.profileBinding != activation.profileBinding) fail(JournalCode::HistoryChanged);
            if (!resolution->selectedTip.empty()) {
                if (std::none_of(parents.begin(), parents.end(), [&](const auto &tip) {
                    return tip.id == resolution->selectedTip;
                })) fail(JournalCode::Confirmation);
                const auto &selected = replicaEvent(verified, resolution->selectedTip);
                auto target = packed::decode(selected.items);
                const WipeSnapshot wipeTarget{target};
                if (validateTarget) validateTarget(local, target);
                selectedItems = selected.items;
            }
        } else {
            const auto &tips = verified.graph.tips();
            if (tips.size() != 1 || !verified.graph.isAncestor(replica.cursor.id, tips.front())) return Result::Conflict;
            auto base = packed::decode(replicaEvent(verified, replica.cursor.id).items);
            const WipeSnapshot wipeBase{base};
            const bool dirty = local != base;
            if (tips.front() != replica.cursor.id) {
                if (dirty) return Result::Conflict;
                auto target = packed::decode(replicaEvent(verified, tips.front()).items);
                const WipeSnapshot wipeTarget{target};
                if (validateTarget) validateTarget(local, target);
                if (log.watermark != now) persistLog();
                replica.cursor = {tips.front(), verified.wireDigests.at(tips.front())};
                persistReplica(target);
                return Result::Pulled;
            }
            if (!dirty) return Result::UpToDate;
            parents = {{replica.cursor.id, replica.cursor.digest}};
        }
        if (verified.graph.size() >= preflight.events) throw Error(ErrorCode::Limit);
        preflight.eventBytes = std::min(MaxClipboardEventBytes, preflight.historyBytes - verified.wireBytes);
        preflight.plaintextBytes = std::min(preflight.plaintextBytes,
            preflight.historyPlaintextBytes - verified.plaintextBytes);
    }

    if (log.eventLedger->attempts == SignedEventCodec::MaxAttemptsPerAuthorPerGeneration)
        fail(JournalCode::EventBudget);
    if (log.allocatedSequence == history::MaxSequence ||
        record.generation > std::numeric_limits<std::uint64_t>::max() - 4) throw Error(ErrorCode::Overflow);
    if (validateTarget && (!resolution || resolution->selectedTip.empty())) validateTarget(local, local);
    const auto sequence = log.allocatedSequence + 1;
    transaction::Limits snapshotLimits;
    snapshotLimits.snapshotBytes = MaxClipboardEventBytes;
    std::vector<std::string> parentIds;
    std::size_t parentBytes = 0;
    for (const auto &parent : parents) {
        parentIds.push_back(parent.id);
        parentBytes += parent.id.size() + parent.digest.size();
    }
    events::Event candidate{{history::makeId(device, sequence), device, sequence, std::move(parentIds)},
                            resolution && !resolution->selectedTip.empty()
                                ? std::move(selectedItems) : packed::encode(local, snapshotLimits)};
    const WipeItems wipe{candidate.items};
    // Reserve room for the exact parent addresses and wire digests.
    if (preflight.eventBytes <= parentBytes || !preflight.plaintextBytes) throw Error(ErrorCode::Limit);
    preflight.eventBytes -= parentBytes;
    SignedEventCodec::validateSeedPayload(candidate.items, preflight);
    transport.checkPublicationStaging(privateStaging);
    replica.pending = SignedReplicaIntent{sequence, replicaToken(events::fingerprint(candidate))};
    if (resolution) {
        replica.pending->mergeParents = parents;
        replica.pending->localBefore = resolution->review.localDigest;
        replica.pending->selectedTip = resolution->selectedTip;
    }
    const auto tag = replicaTag(activation, replica);
    persistReplica(local);
    checkProceed();
    const auto prepared = prepareClipboardEventLocked(identity, *key, parents, candidate.items, now, {}, nullptr, &tag);
    if (prepared.sequence != sequence) fail(JournalCode::EventReservation);
    if (!publish(tag)) return Result::Conflict;
    auto verified = scan();
    const WipeEvents wipeVerified{verified.events};
    return finish(verified, candidate.revision.id);
}

std::string TrustJournal::publishClipboardEvent(std::uint64_t sequence, const SyncKey &key,
                                                const storage::Directory &transport, std::uint64_t now,
                                                ClipboardPublication mode, const std::filesystem::path &privateStaging) {
    const auto lease = lock();
    return publishClipboardEventLocked(sequence, key, transport, now, mode, privateStaging);
}

SignedReplicaRecovery TrustJournal::recoverRotatedReplica(const Identity &identity, const JoinActivation &activation,
    SignedReplicaState replica, const transaction::Snapshot &local, std::uint64_t now, const SignedReplicaWriter &write) {
    validateReplica(activation, replica, local);
    if (!write) fail(JournalCode::Enrollment);

    const auto lease = lock();
    const auto record = load();
    const auto pins = pin(genesis_, local_);
    auto log = decode(record, binding_, pins);
    std::uint64_t pendingGeneration = 0;
    const auto membership = replay(log, genesis_, local_, nullptr, &pendingGeneration);
    if (membership.forked()) throw Error(ErrorCode::Forked);
    if (identity.member() != local_ || activation.member != local_.id) fail(JournalCode::WrongPins);
    if (!log.enrollment || log.enrollment->acceptedIntent == Token{} || !log.eventLedger)
        fail(JournalCode::Enrollment);
    clock(log, now);
    const auto &current = membership.current();
    const auto *admitted = membership.acceptedState(activation.head);
    if (!admitted || activation.group != current.group || activation.root != current.root ||
        activation.generation != admitted->keyGeneration || activation.generation >= current.keyGeneration ||
        member(*admitted, local_.id) != local_ || member(current, local_.id) != local_)
        fail(JournalCode::HistoryChanged);
    if (!replica.pending) return SignedReplicaRecovery::NothingPending;

    const auto sequence = replica.pending->sequence;
    const auto tag = replicaTag(activation, replica);
    const bool known = log.replicaEvidence && sameConfirmation(log.replicaEvidence->tag, tag) &&
                       log.replicaEvidence->generation == activation.generation;
    // Older rotated records may have discarded their attempt bit, and a
    // completed publication from those versions may leave no journal slot.
    auto publication = known ? log.replicaEvidence->publication : ReplicaPublicationState::PossiblyPublished;
    if (log.pendingEvent) {
        if (sequence != log.allocatedSequence || !log.replicaTag || !sameConfirmation(*log.replicaTag, tag) ||
            log.eventLedger->publicationAttempted ||
            (!log.pendingEvent->empty() && pendingGeneration != activation.generation) ||
            (log.replicaEvidence && !known)) fail(JournalCode::EventReservation);
        if (log.pendingEvent->empty()) publication = ReplicaPublicationState::Unattempted;
        // Commit the exact retirement marker first. If the checkpoint write
        // fails, reopening can prove the same slot was already retired.
        log.replicaEvidence = ReplicaEvidence{tag, activation.generation, publication};
        log.pendingEvent.reset();
        log.replicaTag.reset();
        log.watermark = now;
        auto replacement = record;
        storeLog(replacement, log, pins);
        save(record, replacement);
    } else if (!known) {
        if (sequence == log.allocatedSequence + 1) publication = ReplicaPublicationState::Unattempted;
        else if (sequence != log.allocatedSequence || log.replicaEvidence) fail(JournalCode::EventReservation);
    }
    replica.pending.reset();
    write(replica, local);
    switch (publication) {
    case ReplicaPublicationState::Unattempted: return SignedReplicaRecovery::RetiredUnattempted;
    case ReplicaPublicationState::PossiblyPublished: return SignedReplicaRecovery::RetiredPossiblyPublished;
    case ReplicaPublicationState::ConfirmedPublished: return SignedReplicaRecovery::RetiredConfirmedPublished;
    }
    fail(JournalCode::Invalid);
}

std::string TrustJournal::publishClipboardEventLocked(std::uint64_t sequence, const SyncKey &key,
    const storage::Directory &transport, std::uint64_t now, ClipboardPublication mode,
    const std::filesystem::path &privateStaging, const Token *migration, const ReplicaPublication *replica) {
    const auto checkProceed = [&] {
        if (replica && replica->canProceed && !replica->canProceed()) fail(JournalCode::EventPublication);
    };
    checkProceed();
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
    if ((replica && (!pending || !log.replicaTag || !sameConfirmation(*log.replicaTag, replica->tag))) ||
        (!replica && log.replicaTag)) fail(JournalCode::EventReservation);
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
    if (replica) {
        verifyReplicaHistory(verified, replica->activation, replica->state.cursor);
        verifyReplicaIntent(replicaEvent(verified, id), replica->state, &verified.wireDigests);
        if (!ledger.publicationAttempted) {
            if (visible || std::any_of(verified.events.begin(), verified.events.end(), [&](const auto &event) {
                const auto &parents = event.revision.parents;
                return std::find(parents.begin(), parents.end(), id) != parents.end();
            })) fail(JournalCode::HistoryChanged);
            // The candidate must consume every fresh tip. An added sibling
            // leaves a distinct tip and invalidates the first publication.
            if (verified.graph.tips() != std::vector<std::string>{id}) {
                checkProceed();
                verified.wireDigests.erase(id);
                ledger.witnesses = std::move(verified.wireDigests);
                log.pendingEvent.reset();
                log.replicaTag.reset();
                log.watermark = now;
                auto retired = record;
                storeLog(retired, log, pins);
                save(record, retired);
                return {};
            }
        }
    }
    if (pending && record.generation >= std::numeric_limits<std::uint64_t>::max() - 1)
        throw Error(ErrorCode::Overflow);
    transport.checkPublicationStaging(privateStaging);
    checkProceed();

    // Record all visible evidence and irrevocably mark the slot before any
    // native publication. An absent candidate is witnessed only after success.
    const bool firstObservation = !ledger.witnesses.count(id);
    const bool alreadyAttempted = ledger.publicationAttempted;
    ledger.witnesses = verified.wireDigests;
    if (!visible && firstObservation) ledger.witnesses.erase(id);
    ledger.publicationAttempted = pending;
    log.watermark = now;
    auto attempted = record;
    storeLog(attempted, log, pins);
    save(record, attempted);
    if (replica && replica->canProceed && !replica->canProceed()) {
        // A first cancellation here proves native publication was never
        // invoked. Reestablish the unattempted state so later edits can
        // supersede this packet. If this commit fails, retain conservative
        // attempted semantics on reopen.
        if (!alreadyAttempted) {
            ledger.publicationAttempted = false;
            auto cancelled = attempted;
            storeLog(cancelled, log, pins);
            save(attempted, cancelled);
        }
        fail(JournalCode::EventPublication);
    }
    folder->publish({id, wire}, privateStaging);
    if (pending) {
        ledger.witnesses = std::move(verified.wireDigests);
        ledger.publicationAttempted = false;
        if (replica)
            log.replicaEvidence = ReplicaEvidence{replica->tag, state.keyGeneration, ReplicaPublicationState::ConfirmedPublished};
        log.pendingEvent.reset();
        log.replicaTag.reset();
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
