// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_signed_event.h"
#include "device_trust_journal.h"
#include "test_check.h"

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <string_view>
#include <utility>
#ifdef __linux__
#include <unistd.h>
#endif

using namespace cqs::trust;
using cqs::crypto::Bytes;
namespace ev = cqs::events;
namespace hist = cqs::history;
namespace st = cqs::state;
namespace tx = cqs::transaction;

namespace {
constexpr std::uint64_t Now = 100;
int cases = 0;

void test(const char *name, const std::function<void()> &action)
{
    action();
    ++cases;
    std::cout << "PASS " << name << '\n';
}

template<class Failure, class Code, class Fn>
void rejects(Code expected, Fn &&action)
{
    bool rejected = false;
    try {
        action();
    } catch (const Failure &error) {
        rejected = true;
        CHECK(error.code() == expected);
    }
    CHECK(rejected);
}

Token token(std::uint32_t value)
{
    Token result{};
    for (unsigned i = 0; i < 4; ++i)
        result[31 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    return result;
}

std::string_view view(const Bytes &bytes)
{
    if (bytes.empty()) return {};
    return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

class MemoryStore final : public tx::Store {
public:
    enum class Fault { BeforeWrite, AfterWrite };

    explicit MemoryStore(tx::Record value) : record_(std::move(value)) {}

    void failCommit(std::size_t attempt, Fault fault) { failure_ = std::make_pair(attempt, fault); }
    std::size_t attempts() const { return attempts_; }
    const tx::Record &record() const { return record_; }
    void restore(tx::Record record) { record_ = std::move(record); }

    std::unique_ptr<Lease> lock() override
    {
        if (leased_) return {};
        auto lease = std::make_unique<Held>(leased_);
        leased_ = true;
        return lease;
    }

    tx::Record load() override
    {
        CHECK(leased_);
        return record_;
    }

    void commit(const tx::Record &expected, const tx::Record &replacement) override
    {
        CHECK(leased_);
        CHECK(st::serialize(expected) == st::serialize(record_));
        CHECK(replacement.generation == record_.generation + 1);
        ++attempts_;
        if (failure_ == std::make_pair(attempts_, Fault::BeforeWrite))
            throw st::Error(st::ErrorCode::Io, "Synthetic failure before commit");
        record_ = replacement;
        if (failure_ == std::make_pair(attempts_, Fault::AfterWrite))
            throw st::Error(st::ErrorCode::CommitUnconfirmed, "Synthetic lost commit acknowledgement");
    }

private:
    struct Held final : Lease {
        explicit Held(bool &leased) : leased_(leased) {}
        ~Held() override { leased_ = false; }
        bool &leased_;
    };

    bool leased_ = false;
    tx::Record record_;
    std::size_t attempts_ = 0;
    std::optional<std::pair<std::size_t, Fault>> failure_;
};

struct Fixture {
    std::unique_ptr<SyncKey> key;
    std::vector<std::unique_ptr<Identity>> identities;
    Genesis genesis;
    std::vector<std::unique_ptr<MemoryStore>> stores;
    std::vector<std::unique_ptr<TrustJournal>> journals;
    std::uint32_t request = 0;

    explicit Fixture(std::unique_ptr<SyncKey> dataKey = SyncKey::generate()) : key(std::move(dataKey))
    {
        for (unsigned i = 0; i < 4; ++i) identities.push_back(Identity::generate());
        const auto group = token(700);
        genesis = {group, member(0), token(701), key->commitment(group, 0)};
        for (std::size_t i = 0; i < identities.size(); ++i) {
            stores.push_back(std::make_unique<MemoryStore>(TrustJournal::initialRecord(genesis, member(i), Now)));
            journals.push_back(std::make_unique<TrustJournal>(*stores.back(), genesis, member(i)));
        }
    }

    const Member &member(std::size_t i) const { return identities[i]->member(); }
    TrustJournal &journal(std::size_t i) const { return *journals[i]; }

    void reopen(std::size_t i)
    {
        journals[i] = std::make_unique<TrustJournal>(*stores[i], genesis, member(i));
    }

    Proposal add(std::size_t subject)
    {
        ++request;
        return journal(0).propose(Operation::Add, member(subject), token(800 + request),
                                  token(900 + request), Now, 1000);
    }

    Certificate certificate(const Proposal &proposal, std::initializer_list<std::size_t> signers)
    {
        Certificate result{proposal, {}};
        for (auto i : signers) {
            result.approvals.push_back(journal(i).approve(proposal, *identities[i],
                verificationDigest(proposal, member(i)), Now));
        }
        return result;
    }

    void apply(const Certificate &certificate)
    {
        for (auto &journal : journals) CHECK(journal->observe(certificate, Now) == ObserveResult::Applied);
    }

    Certificate admit(std::size_t subject)
    {
        const auto proposal = add(subject);
        const auto accepted = subject == 1 ? certificate(proposal, {0}) : certificate(proposal, {0, 1});
        apply(accepted);
        return accepted;
    }

    std::string id(std::size_t author, std::uint64_t sequence) const
    {
        return hist::makeId(SignedEventCodec::deviceName(member(author).id), sequence);
    }

    ev::Envelope envelope(std::size_t author, std::uint64_t sequence, const Bytes &wire) const
    {
        return {id(author, sequence), view(wire)};
    }

    SignedEventParent parent(std::size_t author, std::uint64_t sequence, const Bytes &wire) const
    {
        return {id(author, sequence), SignedEventCodec::digest(view(wire))};
    }

    SignedEventContext context(std::size_t observer, std::size_t author)
    {
        const auto state = journal(observer).inspect().state;
        return {state.group, state.root, state.digest, state.keyCommitment, member(author).id, state.keyGeneration};
    }

    Bytes sign(std::size_t author, std::uint64_t sequence, const std::vector<SignedEventParent> &parents = {},
               const std::vector<std::string> &items = {"YQ=="})
    {
        return SignedEventCodec::seal(context(author, author), *identities[author], *key, sequence, parents, items);
    }

    PreparedClipboardEvent prepare(std::size_t author, const std::vector<SignedEventParent> &parents = {},
                                   const std::vector<std::string> &items = {"YQ=="})
    {
        return journal(author).prepareClipboardEvent(*identities[author], *key, parents, items, Now);
    }
};

const ev::Event &event(const std::vector<ev::Event> &events, const std::string &id)
{
    const auto found = std::find_if(events.begin(), events.end(), [&](const auto &e) { return e.revision.id == id; });
    CHECK(found != events.end());
    return *found;
}
} // namespace

int main()
{
    test("two authors authenticate an unordered signed chain with exact packet digests", [] {
        Fixture f;
        f.admit(1);
        const std::vector<std::string> firstItems{"AQIA/w==", "Wm9sYw=="};
        const auto first = f.prepare(0, {}, firstItems).wire;
        const auto parent = f.parent(0, 1, first);
        const auto child = f.prepare(1, {parent}, {}).wire;
        const auto firstId = f.id(0, 1);
        const auto childId = f.id(1, 1);
        const auto inspect = SignedEventCodec::inspect(view(child));
        CHECK(inspect.context.author == f.member(1).id);
        CHECK(inspect.revision.id == childId && inspect.parents.size() == 1);
        CHECK(inspect.parents.front().id == firstId && inspect.parents.front().digest == parent.digest);
        const std::vector<ev::Envelope> reversed{f.envelope(1, 1, child), f.envelope(0, 1, first)};
        for (const auto reader : {0U, 1U}) {
            const auto history = f.journal(reader).readSignedHistory(*f.key, reversed, Now);
            CHECK(history.events.size() == 2 && history.graph.size() == 2);
            CHECK(history.graph.tips() == std::vector<std::string>{childId});
            CHECK(history.graph.isAncestor(firstId, childId));
            CHECK(event(history.events, firstId).items == firstItems);
            CHECK(event(history.events, childId).items.empty());
            CHECK(history.wireDigests.at(firstId) == parent.digest);
            CHECK(history.wireDigests.at(childId) == SignedEventCodec::digest(view(child)));
        }
    });
    test("catch-up key opens earlier accepted heads from the unchanged generation", [] {
        Fixture f;
        const auto genesisEvent = f.prepare(0).wire;
        f.journal(0).discardClipboardEvent(1, Now);
        f.admit(1);
        const auto firstAdd = f.prepare(0, {f.parent(0, 1, genesisEvent)}).wire;
        f.admit(2);
        const auto catchUp = f.journal(0).prepareCatchUp(f.member(1).id, *f.identities[0], *f.key, Now);
        f.journal(1).installDelivery(catchUp, *f.identities[1], Now);
        f.reopen(1);
        auto received = f.journal(1).loadInstalledKey(*f.identities[1], Now);
        CHECK(received->sameKey(*f.key));
        const auto child = f.journal(1).prepareClipboardEvent(*f.identities[1], *received,
            {f.parent(0, 2, firstAdd)}, {"Yg=="}, Now).wire;
        const auto history = f.journal(1).readSignedHistory(*received,
            {f.envelope(0, 2, firstAdd), f.envelope(1, 1, child), f.envelope(0, 1, genesisEvent)}, Now);
        CHECK(history.graph.size() == 3);
        CHECK(history.graph.tips() == std::vector<std::string>{f.id(1, 1)});
        CHECK(history.graph.isAncestor(f.id(0, 1), f.id(1, 1)));
    });
    test("shared encryption key cannot impersonate another author or its file identity", [] {
        Fixture f;
        f.admit(1);
        const auto original = f.sign(1, 1);
        rejects<JournalError>(JournalCode::WrongPins, [&] {
            f.journal(0).prepareClipboardEvent(*f.identities[1], *f.key, {}, {"YQ=="}, Now);
        });
        const auto claimed = SignedEventCodec::inspect(view(original)).context;
        rejects<ev::Error>(ev::ErrorCode::WrongIdentity, [&] {
            SignedEventCodec::seal(claimed, *f.identities[0], *f.key, 1, {}, {"YQ=="});
        });
        rejects<ev::Error>(ev::ErrorCode::WrongIdentity, [&] {
            f.journal(0).readSignedHistory(*f.key, {f.envelope(0, 1, original)}, Now);
        });
        auto tampered = original;
        tampered.back() ^= 1;
        rejects<ev::Error>(ev::ErrorCode::AuthenticationFailed, [&] {
            f.journal(0).readSignedHistory(*f.key, {f.envelope(1, 1, tampered)}, Now);
        });
        const auto outsider = SignedEventCodec::seal(f.context(0, 3), *f.identities[3], *f.key, 1, {}, {"YQ=="});
        rejects<Error>(ErrorCode::NotMember, [&] {
            f.journal(0).readSignedHistory(*f.key, {f.envelope(3, 1, outsider)}, Now);
        });
        CHECK(f.journal(0).readSignedHistory(*f.key, {f.envelope(1, 1, original)}, Now).graph.size() == 1);
    });
    test("a current member cannot author events at a head before its admission", [] {
        Fixture f;
        const auto beforeAdmission = f.context(0, 1);
        f.admit(1);
        const auto forged = SignedEventCodec::seal(beforeAdmission, *f.identities[1], *f.key, 1, {}, {"YQ=="});
        rejects<Error>(ErrorCode::NotMember, [&] {
            f.journal(0).readSignedHistory(*f.key, {f.envelope(1, 1, forged)}, Now);
        });
    });
    test("an authenticated packet cannot supply its own group or membership head", [] {
        Fixture f;
        f.admit(1);
        auto context = f.context(0, 0);
        context.head[0] ^= 1;
        const auto unknown = SignedEventCodec::seal(context, *f.identities[0], *f.key, 1, {}, {"YQ=="});
        rejects<Error>(ErrorCode::MissingParent, [&] {
            f.journal(1).readSignedHistory(*f.key, {f.envelope(0, 1, unknown)}, Now);
        });
        context = f.context(0, 0);
        context.root[0] ^= 1;
        const auto foreign = SignedEventCodec::seal(context, *f.identities[0], *f.key, 1, {}, {"YQ=="});
        rejects<Error>(ErrorCode::WrongGroup, [&] {
            f.journal(1).readSignedHistory(*f.key, {f.envelope(0, 1, foreign)}, Now);
        });
    });
    test("equivalent re-sealed parent cannot replace the exact signed parent packet", [] {
        Fixture f;
        f.admit(1);
        const auto first = f.sign(0, 1);
        const auto replacement = f.sign(0, 1);
        CHECK(first != replacement);
        const auto child = f.sign(1, 1, {f.parent(0, 1, first)});
        CHECK(f.journal(1).readSignedHistory(*f.key, {f.envelope(0, 1, replacement)}, Now).graph.size() == 1);
        rejects<Error>(ErrorCode::Invalid, [&] {
            f.journal(1).readSignedHistory(*f.key, {f.envelope(0, 1, replacement), f.envelope(1, 1, child)}, Now);
        });
        rejects<hist::Error>(hist::ErrorCode::DuplicateRevision, [&] {
            f.journal(1).readSignedHistory(*f.key,
                {f.envelope(0, 1, first), f.envelope(0, 1, replacement), f.envelope(1, 1, child)}, Now);
        });
        rejects<hist::Error>(hist::ErrorCode::MissingParent, [&] {
            f.journal(1).readSignedHistory(*f.key, {f.envelope(1, 1, child)}, Now);
        });
        const auto both = f.sign(1, 2, {f.parent(0, 1, first), {f.id(0, 2), token(2001)}});
        rejects<Error>(ErrorCode::Invalid, [&] {
            f.journal(1).readSignedHistory(*f.key, {f.envelope(0, 1, replacement), f.envelope(1, 2, both)}, Now);
        });
    });
    test("a valid parent hash cannot reach forward to a later accepted membership epoch", [] {
        Fixture f;
        f.admit(1);
        const auto earlierHead = f.context(1, 1);
        f.admit(2);
        const auto laterParent = f.sign(0, 1);
        const auto child = SignedEventCodec::seal(earlierHead, *f.identities[1], *f.key, 1,
            {f.parent(0, 1, laterParent)}, {"Yg=="});
        CHECK(f.journal(0).readSignedHistory(*f.key, {f.envelope(0, 1, laterParent)}, Now).graph.size() == 1);
        rejects<Error>(ErrorCode::Invalid, [&] {
            f.journal(0).readSignedHistory(*f.key, {f.envelope(1, 1, child), f.envelope(0, 1, laterParent)}, Now);
        });
    });
    test("an indirect cross-device parent chain still enforces author sequence order", [] {
        Fixture f;
        f.admit(1);
        const auto root = f.sign(0, 5);
        const auto middle = f.sign(1, 1, {f.parent(0, 5, root)});
        const auto earlier = f.sign(0, 4, {f.parent(1, 1, middle)});
        rejects<hist::Error>(hist::ErrorCode::NonmonotonicParent, [&] {
            f.journal(0).readSignedHistory(*f.key,
                {f.envelope(0, 4, earlier), f.envelope(0, 5, root), f.envelope(1, 1, middle)}, Now);
        });
        const auto later = f.sign(0, 6, {f.parent(1, 1, middle)});
        const auto history = f.journal(0).readSignedHistory(*f.key,
            {f.envelope(0, 6, later), f.envelope(1, 1, middle), f.envelope(0, 5, root)}, Now);
        CHECK(history.graph.tips() == std::vector<std::string>{f.id(0, 6)});
        CHECK(history.graph.isAncestor(f.id(0, 5), f.id(0, 6)));
    });
    test("rotation refuses the old generation and retired author while survivors can start a new chain", [] {
        Fixture f;
        f.admit(1);
        f.admit(2);
        const auto oldPacket = f.sign(2, 1);
        const auto next = SyncKey::generate();
        const auto remove = f.journal(0).propose(Operation::Remove, f.member(2), token(1001), token(1002),
                                                  Now, 1000, next->commitment(f.genesis.group, 1));
        f.apply(f.certificate(remove, {0, 1}));
        rejects<EnvelopeError>(EnvelopeCode::KeyMismatch, [&] { f.prepare(0); });
        rejects<Error>(ErrorCode::Stale, [&] {
            f.journal(0).readSignedHistory(*next, {f.envelope(2, 1, oldPacket)}, Now);
        });
        rejects<Error>(ErrorCode::NotMember, [&] {
            f.journal(2).prepareClipboardEvent(*f.identities[2], *next, {}, {"YQ=="}, Now);
        });
        const auto forged = SignedEventCodec::seal(f.context(0, 2), *f.identities[2], *next, 2, {}, {"YQ=="});
        rejects<Error>(ErrorCode::NotMember, [&] {
            f.journal(0).readSignedHistory(*next, {f.envelope(2, 2, forged)}, Now);
        });
        const auto fresh = f.journal(0).prepareClipboardEvent(*f.identities[0], *next, {}, {"Yg=="}, Now).wire;
        rejects<Error>(ErrorCode::NotMember, [&] {
            f.journal(2).readSignedHistory(*next, {f.envelope(0, 1, fresh)}, Now);
        });
        CHECK(f.journal(1).readSignedHistory(*next, {f.envelope(0, 1, fresh)}, Now).graph.size() == 1);
    });
    test("a persisted membership fork blocks both signed reading and signing", [] {
        Fixture f;
        const auto sibling = f.add(2);
        f.admit(1);
        const auto packet = f.prepare(0).wire;
        // Simulate compromised signing authority at the old parent.
        const Certificate fork{sibling, {{f.member(0).id, f.identities[0]->sign(
            approvalBytes(sibling, f.member(0)))}}};
        CHECK(f.journal(0).observe(fork, Now) == ObserveResult::ForkDetected);
        f.reopen(0);
        rejects<Error>(ErrorCode::Forked, [&] { f.prepare(0); });
        rejects<Error>(ErrorCode::Forked, [&] { f.journal(0).resumeClipboardEvent(1, Now); });
        CHECK(f.journal(0).inspect().allocatedEventSequence == 1);
        rejects<Error>(ErrorCode::Forked, [&] {
            f.journal(0).readSignedHistory(*f.key, {f.envelope(0, 1, packet)}, Now);
        });
    });
    test("a valid shared-key legacy event cannot be mixed into a signed history", [] {
        // Frozen legacy fixture, encrypted under the public key 00 through 1f.
        constexpr std::string_view legacy = R"({"ciphertext":"P559TQ/Ji9agFyUB5+NNoXLZs4D8dlWPM+pN9zGeDQa0RSQp/utb1CYWLccmS2N2o9BPpBB69whuvXmrKk/w7rQd1JRZqzAZ3zo5a8+d+lNhQJf2","header":{"device":"mint-lab","parents":[],"protocol":"copyq-secure-sync-v1","seq":1},"nonce":"AAECAwQFBgcICQoL"})";
        Bytes testKey(32);
        std::iota(testKey.begin(), testKey.end(), 0);
        const ev::Envelope old{"mint-lab/000000000001", legacy};
        CHECK(ev::decode(testKey, old).items == std::vector<std::string>{"U1lOQ19URVNUXzAwMQ=="});
        Fixture f(SyncKey::import(testKey));
        const auto signedPacket = f.sign(0, 1);
        rejects<ev::Error>(ev::ErrorCode::InvalidHeader, [&] {
            f.journal(0).readSignedHistory(*f.key, {f.envelope(0, 1, signedPacket), old}, Now);
        });
    });
    test("batch counts, wire bytes and decoded plaintext enforce aggregate budgets", [] {
        Fixture f;
        f.admit(1);
        const auto first = f.sign(0, 1);
        const auto child = f.sign(1, 1, {f.parent(0, 1, first)}, {"Yg=="});
        const std::vector<ev::Envelope> batch{f.envelope(0, 1, first), f.envelope(1, 1, child)};
        const auto valid = f.journal(0).readSignedHistory(*f.key, batch, Now);
        const auto plaintext = valid.events[0].plaintextBytes + valid.events[1].plaintextBytes;
        CHECK(plaintext > 1);
        ev::Limits exact;
        exact.events = 2;
        exact.historyBytes = first.size() + child.size();
        exact.historyPlaintextBytes = plaintext;
        CHECK(f.journal(0).readSignedHistory(*f.key, batch, Now, exact).graph.size() == 2);
        auto lower = exact;
        --lower.events;
        rejects<Error>(ErrorCode::Limit, [&] { f.journal(0).readSignedHistory(*f.key, batch, Now, lower); });
        lower = exact;
        --lower.historyBytes;
        rejects<Error>(ErrorCode::Limit, [&] { f.journal(0).readSignedHistory(*f.key, batch, Now, lower); });
        lower = exact;
        --lower.historyPlaintextBytes;
        rejects<ev::Error>(ev::ErrorCode::SizeLimit, [&] { f.journal(0).readSignedHistory(*f.key, batch, Now, lower); });
        auto wrong = SyncKey::generate();
        rejects<EnvelopeError>(EnvelopeCode::KeyMismatch, [&] { f.journal(0).readSignedHistory(*wrong, batch, Now); });
    });
    test("a ready reservation is durable, exact, and cannot be replaced by another edit", [] {
        Fixture f;
        auto &store = *f.stores[0];
        const auto initial = f.journal(0).inspect();
        CHECK(initial.allocatedEventSequence == 0 && !initial.pendingEvent);
        // Exercise packets above the per-field bound for membership messages.
        const std::vector<std::string> items{std::string(8192, 'A')};
        const auto first = f.prepare(0, {}, items);
        CHECK(first.sequence == 1 && first.wire.size() > 8192 && store.attempts() == 2);
        const auto status = f.journal(0).inspect();
        CHECK(status.allocatedEventSequence == 1 && status.pendingEvent);
        CHECK(status.pendingEvent->sequence == 1 && status.pendingEvent->ready);
        CHECK(f.journal(0).readSignedHistory(*f.key, {f.envelope(0, 1, first.wire)}, Now).events.front().items == items);
        rejects<JournalError>(JournalCode::EventPending, [&] { f.prepare(0, {}, {"Yg=="}); });
        CHECK(store.attempts() == 2);
        f.reopen(0);
        const auto resumed = f.journal(0).resumeClipboardEvent(1, Now);
        CHECK(resumed.sequence == first.sequence && resumed.wire == first.wire && store.attempts() == 3);
        f.journal(0).discardClipboardEvent(1, Now);
        f.reopen(0);
        const auto cleared = f.journal(0).inspect();
        CHECK(cleared.allocatedEventSequence == 1 && !cleared.pendingEvent);
        const auto second = f.prepare(0, {}, {"Yg=="});
        CHECK(second.sequence == 2 && second.wire != first.wire);
        const auto beforeWrongSequence = store.attempts();
        rejects<JournalError>(JournalCode::EventReservation, [&] { f.journal(0).resumeClipboardEvent(1, Now); });
        rejects<JournalError>(JournalCode::EventReservation, [&] { f.journal(0).discardClipboardEvent(1, Now); });
        CHECK(store.attempts() == beforeWrongSequence);
        CHECK(f.journal(0).resumeClipboardEvent(2, Now).wire == second.wire);
    });
    test("an unapplied allocation returns no packet and leaves no reservation", [] {
        Fixture f;
        auto &store = *f.stores[0];
        store.failCommit(1, MemoryStore::Fault::BeforeWrite);
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.prepare(0); });
        CHECK(store.attempts() == 1);
        rejects<JournalError>(JournalCode::Uncertain, [&] { f.prepare(0); });
        f.reopen(0);
        const auto status = f.journal(0).inspect();
        CHECK(status.allocatedEventSequence == 0 && !status.pendingEvent);
        CHECK(f.prepare(0).sequence == 1);
    });
    test("an interrupted reservation burns its sequence without a resumable packet", [] {
        for (const auto failAt : {1U, 2U}) {
            Fixture f;
            auto &store = *f.stores[0];
            const auto fault = failAt == 1 ? MemoryStore::Fault::AfterWrite : MemoryStore::Fault::BeforeWrite;
            const auto code = failAt == 1 ? st::ErrorCode::CommitUnconfirmed : st::ErrorCode::Io;
            store.failCommit(failAt, fault);
            rejects<st::Error>(code, [&] { f.prepare(0); });
            CHECK(store.attempts() == failAt);
            rejects<JournalError>(JournalCode::Uncertain, [&] { f.journal(0).resumeClipboardEvent(1, Now); });
            f.reopen(0);
            const auto status = f.journal(0).inspect();
            CHECK(status.allocatedEventSequence == 1 && status.pendingEvent);
            CHECK(status.pendingEvent->sequence == 1 && !status.pendingEvent->ready);
            rejects<JournalError>(JournalCode::EventReservation, [&] { f.journal(0).resumeClipboardEvent(1, Now); });
            rejects<JournalError>(JournalCode::EventPending, [&] { f.prepare(0); });
            CHECK(store.attempts() == failAt);
            f.journal(0).discardClipboardEvent(1, Now);
            f.reopen(0);
            CHECK(f.prepare(0).sequence == 2);
        }
    });
    test("an unconfirmed exact packet is withheld until a fresh durability barrier", [] {
        Fixture f;
        auto &store = *f.stores[0];
        store.failCommit(2, MemoryStore::Fault::AfterWrite);
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.prepare(0); });
        rejects<JournalError>(JournalCode::Uncertain, [&] { f.journal(0).resumeClipboardEvent(1, Now); });
        CHECK(store.attempts() == 2);
        const auto record = store.record();
        f.reopen(0);
        const auto status = f.journal(0).inspect();
        CHECK(status.allocatedEventSequence == 1 && status.pendingEvent && status.pendingEvent->ready);
        store.failCommit(3, MemoryStore::Fault::BeforeWrite);
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.journal(0).resumeClipboardEvent(1, Now); });
        rejects<JournalError>(JournalCode::Uncertain, [&] { f.journal(0).resumeClipboardEvent(1, Now); });
        CHECK(store.attempts() == 3);
        f.reopen(0);
        const auto recovered = f.journal(0).resumeClipboardEvent(1, Now);
        CHECK(recovered.sequence == 1 && !recovered.wire.empty() && store.attempts() == 4);
        const auto &oldJournal = record.local->front().begin()->second;
        CHECK(std::search(oldJournal.begin(), oldJournal.end(), recovered.wire.begin(), recovered.wire.end()) != oldJournal.end());
        CHECK(f.journal(0).readSignedHistory(*f.key, {f.envelope(0, 1, recovered.wire)}, Now).graph.size() == 1);
    });
    test("an Add keeps a reservation resumable but rotation blocks release and preserves its sequence", [] {
        Fixture f;
        f.admit(1);
        const auto packet = f.prepare(0);
        f.admit(2);
        f.reopen(0);
        CHECK(f.journal(0).resumeClipboardEvent(1, Now).wire == packet.wire);
        const auto next = SyncKey::generate();
        const auto remove = f.journal(0).propose(Operation::Remove, f.member(2), token(1101), token(1102),
                                                  Now, 1000, next->commitment(f.genesis.group, 1));
        f.apply(f.certificate(remove, {0, 1}));
        f.reopen(0);
        const auto status = f.journal(0).inspect();
        CHECK(status.allocatedEventSequence == 1 && status.pendingEvent && status.pendingEvent->ready);
        rejects<Error>(ErrorCode::Stale, [&] { f.journal(0).resumeClipboardEvent(1, Now); });
        f.journal(0).discardClipboardEvent(1, Now);
        const auto fresh = f.journal(0).prepareClipboardEvent(*f.identities[0], *next, {}, {"Yg=="}, Now);
        CHECK(fresh.sequence == 2);
        CHECK(f.journal(1).readSignedHistory(*next, {f.envelope(0, 2, fresh.wire)}, Now).graph.size() == 1);
    });
    test("a live coordinator rejects record rollback before resuming a reservation", [] {
        Fixture f;
        auto &store = *f.stores[0];
        const auto initial = store.record();
        const auto packet = f.prepare(0);
        store.restore(initial);
        rejects<JournalError>(JournalCode::Rollback, [&] { f.journal(0).resumeClipboardEvent(packet.sequence, Now); });
        CHECK(store.attempts() == 2);
    });
    test("replay verifies the stored signature and the allocated revision identity", [] {
        Fixture f;
        auto &store = *f.stores[0];
        const auto packet = f.prepare(0);
        const auto original = store.record();
        auto replacePacket = [&](const Bytes &replacement) {
            auto modified = original;
            auto &journal = modified.local->front().begin()->second;
            auto start = std::search(journal.begin(), journal.end(), packet.wire.begin(), packet.wire.end());
            CHECK(start != journal.end() && replacement.size() == packet.wire.size());
            std::copy(replacement.begin(), replacement.end(), start);
            store.restore(std::move(modified));
        };
        const auto wrongSequence = f.sign(0, 2);
        auto tampered = packet.wire;
        tampered.back() ^= 1;
        replacePacket(tampered);
        rejects<ev::Error>(ev::ErrorCode::AuthenticationFailed, [&] { f.reopen(0); });
        replacePacket(wrongSequence);
        rejects<ev::Error>(ev::ErrorCode::WrongIdentity, [&] { f.reopen(0); });
        CHECK(store.attempts() == 2);
    });
    test("v4 replay refuses malformed allocation fields and extra or missing bytes", [] {
        Fixture f;
        auto &store = *f.stores[0];
        const auto packet = f.prepare(0);
        const auto original = store.record();
        auto modify = [&](const std::function<void(Bytes &, std::size_t)> &change) {
            auto modified = original;
            auto &journal = modified.local->front().begin()->second;
            // v4 suffix: sequence u64, pending u8, wire length u32, wire.
            const auto start = journal.size() - packet.wire.size() - 13;
            CHECK(start > 0 && journal[start + 7] == 1 && journal[start + 8] == 1);
            change(journal, start);
            store.restore(std::move(modified));
            rejects<JournalError>(JournalCode::Invalid, [&] { f.reopen(0); });
        };
        modify([](Bytes &journal, std::size_t start) { journal[start + 7] = 0; });
        modify([](Bytes &journal, std::size_t start) { journal[start] = 0xff; });
        modify([](Bytes &journal, std::size_t start) { journal[start + 8] = 2; });
        modify([](Bytes &journal, std::size_t start) { journal[start + 8] = 0; });
        modify([](Bytes &journal, std::size_t start) { journal[start + 9] = 0xff; });
        modify([](Bytes &journal, std::size_t) { journal.pop_back(); });
        modify([](Bytes &journal, std::size_t) { journal.push_back(0); });
        CHECK(store.attempts() == 2);
    });
    test("the largest event sequence can be reserved once and never wraps", [] {
        Fixture f;
        auto &store = *f.stores[0];
        const auto packet = f.prepare(0);
        f.journal(0).discardClipboardEvent(packet.sequence, Now);
        auto nearlyExhausted = store.record();
        auto &journal = nearlyExhausted.local->front().begin()->second;
        const auto start = journal.size() - 13;
        CHECK(start > 0 && journal[start + 7] == 1 && journal[start + 8] == 0);
        const auto previousSequence = hist::MaxSequence - 1;
        for (unsigned i = 0; i < 8; ++i)
            journal[start + 7 - i] = static_cast<std::uint8_t>(previousSequence >> (8 * i));
        store.restore(std::move(nearlyExhausted));
        f.reopen(0);
        CHECK(f.journal(0).inspect().allocatedEventSequence == previousSequence);
        const auto last = f.prepare(0);
        CHECK(last.sequence == hist::MaxSequence);
        f.journal(0).discardClipboardEvent(last.sequence, Now);
        const auto attempts = store.attempts();
        rejects<Error>(ErrorCode::Overflow, [&] { f.prepare(0); });
        CHECK(store.attempts() == attempts && f.journal(0).inspect().allocatedEventSequence == hist::MaxSequence);
    });
    test("generation exhaustion leaves room to resume and retire the last reservation", [] {
        Fixture f;
        auto &store = *f.stores[0];
        constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
        auto nearlyExhausted = store.record();
        nearlyExhausted.generation = maximum - 3;
        store.restore(nearlyExhausted);
        f.reopen(0);
        rejects<Error>(ErrorCode::Overflow, [&] { f.prepare(0); });
        CHECK(store.attempts() == 0 && !f.journal(0).inspect().pendingEvent);
        nearlyExhausted.generation = maximum - 4;
        store.restore(std::move(nearlyExhausted));
        f.reopen(0);
        const auto packet = f.prepare(0);
        CHECK(store.record().generation == maximum - 2);
        CHECK(f.journal(0).resumeClipboardEvent(packet.sequence, Now).wire == packet.wire);
        CHECK(store.record().generation == maximum - 1);
        rejects<Error>(ErrorCode::Overflow, [&] { f.journal(0).resumeClipboardEvent(packet.sequence, Now); });
        CHECK(store.attempts() == 3);
        f.journal(0).discardClipboardEvent(packet.sequence, Now);
        CHECK(store.record().generation == maximum && !f.journal(0).inspect().pendingEvent);
    });
#ifdef __linux__
    test("reopened encrypted journal reconstructs heads for signing and authenticated reading", [] {
        Fixture f;
        const auto first = f.sign(0, 1);
        const auto accepted = f.admit(1);
        char pattern[] = "/tmp/cqs-signed-history-XXXXXX";
        const auto *made = ::mkdtemp(pattern);
        CHECK(made);
        const std::filesystem::path path(made);
        struct Cleanup {
            std::filesystem::path path;
            ~Cleanup() { std::error_code error; std::filesystem::remove_all(path, error); }
        } cleanup{path};
        const auto binding = TrustJournal::binding(f.genesis, f.member(1));
        const Bytes credential(32, 0x47); // Public test key.
        Bytes child;
        {
            st::FileStore store(path, binding, credential);
            TrustJournal::initialize(store, f.genesis, f.member(1), Now);
            TrustJournal journal(store, f.genesis, f.member(1));
            CHECK(journal.observe(accepted, Now) == ObserveResult::Applied);
            child = journal.prepareClipboardEvent(*f.identities[1], *f.key,
                {f.parent(0, 1, first)}, {"Yg=="}, Now).wire;
        }
        st::FileStore store(path, binding, credential);
        TrustJournal reopened(store, f.genesis, f.member(1));
        CHECK(reopened.resumeClipboardEvent(1, Now).wire == child);
        const auto history = reopened.readSignedHistory(*f.key, {f.envelope(1, 1, child), f.envelope(0, 1, first)}, Now);
        CHECK(history.graph.isAncestor(f.id(0, 1), f.id(1, 1)));
        CHECK(history.graph.tips() == std::vector<std::string>{f.id(1, 1)});
    });
#endif
    std::cout << cases << " device signed history test cases passed\n";
}
