// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_signed_event.h"
#include "device_trust_journal.h"
#include "test_check.h"

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <numeric>
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
    explicit MemoryStore(tx::Record value) : record_(std::move(value)) {}

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
        record_ = replacement;
    }

private:
    struct Held final : Lease {
        explicit Held(bool &leased) : leased_(leased) {}
        ~Held() override { leased_ = false; }
        bool &leased_;
    };

    bool leased_ = false;
    tx::Record record_;
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
        return journal(author).signClipboardEvent(*identities[author], *key, sequence, parents, items, Now);
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
        const auto first = f.sign(0, 1, {}, firstItems);
        const auto parent = f.parent(0, 1, first);
        const auto child = f.sign(1, 1, {parent}, {});
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
        const auto genesisEvent = f.sign(0, 1);
        f.admit(1);
        const auto firstAdd = f.sign(0, 2, {f.parent(0, 1, genesisEvent)});
        f.admit(2);
        const auto catchUp = f.journal(0).prepareCatchUp(f.member(1).id, *f.identities[0], *f.key, Now);
        f.journal(1).installDelivery(catchUp, *f.identities[1], Now);
        f.reopen(1);
        auto received = f.journal(1).loadInstalledKey(*f.identities[1], Now);
        CHECK(received->sameKey(*f.key));
        const auto child = f.journal(1).signClipboardEvent(*f.identities[1], *received, 1,
            {f.parent(0, 2, firstAdd)}, {"Yg=="}, Now);
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
            f.journal(0).signClipboardEvent(*f.identities[1], *f.key, 1, {}, {"YQ=="}, Now);
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
        rejects<EnvelopeError>(EnvelopeCode::KeyMismatch, [&] { f.sign(0, 1); });
        rejects<Error>(ErrorCode::Stale, [&] {
            f.journal(0).readSignedHistory(*next, {f.envelope(2, 1, oldPacket)}, Now);
        });
        rejects<Error>(ErrorCode::NotMember, [&] {
            f.journal(2).signClipboardEvent(*f.identities[2], *next, 2, {}, {"YQ=="}, Now);
        });
        const auto forged = SignedEventCodec::seal(f.context(0, 2), *f.identities[2], *next, 2, {}, {"YQ=="});
        rejects<Error>(ErrorCode::NotMember, [&] {
            f.journal(0).readSignedHistory(*next, {f.envelope(2, 2, forged)}, Now);
        });
        const auto fresh = f.journal(0).signClipboardEvent(*f.identities[0], *next, 1, {}, {"Yg=="}, Now);
        rejects<Error>(ErrorCode::NotMember, [&] {
            f.journal(2).readSignedHistory(*next, {f.envelope(0, 1, fresh)}, Now);
        });
        CHECK(f.journal(1).readSignedHistory(*next, {f.envelope(0, 1, fresh)}, Now).graph.size() == 1);
    });
    test("a persisted membership fork blocks both signed reading and signing", [] {
        Fixture f;
        const auto sibling = f.add(2);
        f.admit(1);
        const auto packet = f.sign(0, 1);
        // Simulate compromised signing authority at the old parent.
        const Certificate fork{sibling, {{f.member(0).id, f.identities[0]->sign(
            approvalBytes(sibling, f.member(0)))}}};
        CHECK(f.journal(0).observe(fork, Now) == ObserveResult::ForkDetected);
        f.reopen(0);
        rejects<Error>(ErrorCode::Forked, [&] { f.sign(0, 2); });
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
        {
            st::FileStore store(path, binding, credential);
            TrustJournal::initialize(store, f.genesis, f.member(1), Now);
            TrustJournal journal(store, f.genesis, f.member(1));
            CHECK(journal.observe(accepted, Now) == ObserveResult::Applied);
        }
        st::FileStore store(path, binding, credential);
        TrustJournal reopened(store, f.genesis, f.member(1));
        const auto child = reopened.signClipboardEvent(*f.identities[1], *f.key, 1,
            {f.parent(0, 1, first)}, {"Yg=="}, Now);
        const auto history = reopened.readSignedHistory(*f.key, {f.envelope(1, 1, child), f.envelope(0, 1, first)}, Now);
        CHECK(history.graph.isAncestor(f.id(0, 1), f.id(1, 1)));
        CHECK(history.graph.tips() == std::vector<std::string>{f.id(1, 1)});
    });
#endif
    std::cout << cases << " device signed history test cases passed\n";
}
