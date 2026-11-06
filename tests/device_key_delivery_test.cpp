// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_identity_vault.h"
#include "device_key_envelope.h"
#include "device_trust_journal.h"
#include "test_check.h"

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <utility>
#include <vector>
#ifdef __linux__
#include <fstream>
#include <unistd.h>
#endif

using namespace cqs::trust;
namespace st = cqs::state;
namespace tx = cqs::transaction;
using cqs::crypto::Bytes;

namespace {
int cases = 0;
void test(const char *name, const std::function<void()> &body)
{
    body();
    ++cases;
    std::cout << "PASS " << name << '\n';
}

template<class Failure, class Code, class Fn>
void rejects(Code expected, Fn &&action)
{
    bool caught = false;
    try {
        action();
    } catch (const Failure &error) {
        caught = true;
        CHECK(error.code() == expected);
    }
    CHECK(caught);
}

Token token(std::uint32_t value)
{
    Token bytes{};
    for (unsigned i = 0; i < 4; ++i)
        bytes[31 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    return bytes;
}

bool contains(const Bytes &bytes, const Bytes &expected)
{
    return std::search(bytes.begin(), bytes.end(), expected.begin(), expected.end()) != bytes.end();
}

Bytes &payload(tx::Record &record)
{
    return record.local->front().begin()->second;
}

// Disposable fault injector for the journal Store contract. The disk case
// separately exercises encrypted FileStore provisioning and reopening.
class MemoryStore final : public tx::Store {
public:
    enum class Failure { None, Before, After };
    explicit MemoryStore(tx::Record initial) : record(std::move(initial)) {}

    tx::Record record;
    Failure failure = Failure::None;
    unsigned commits = 0;

    std::unique_ptr<Lease> lock() override
    {
        if (leased_) return {};
        leased_ = true;
        return std::make_unique<Held>(leased_);
    }

    tx::Record load() override
    {
        CHECK(leased_);
        return record;
    }

    void commit(const tx::Record &expected, const tx::Record &replacement) override
    {
        CHECK(leased_);
        CHECK(st::serialize(expected) == st::serialize(record));
        CHECK(replacement.generation == record.generation + 1);
        ++commits;
        const auto fail = std::exchange(failure, Failure::None);
        if (fail == Failure::Before) throw st::Error(st::ErrorCode::Io, "Synthetic write failure");
        record = replacement;
        if (fail == Failure::After)
            throw st::Error(st::ErrorCode::CommitUnconfirmed, "Synthetic lost acknowledgement");
    }

private:
    struct Held final : Lease {
        explicit Held(bool &leased) : leased_(leased) {}
        ~Held() override { leased_ = false; }
        bool &leased_;
    };
    bool leased_ = false;
};

struct Fixture {
    static constexpr std::uint64_t Start = 100;
    static constexpr std::uint64_t Until = 1000;

    std::unique_ptr<SyncKey> initialKey = SyncKey::generate();
    std::vector<std::unique_ptr<Identity>> identities;
    Genesis genesis;
    std::vector<std::unique_ptr<MemoryStore>> stores;
    std::vector<std::unique_ptr<TrustJournal>> journals;
    std::uint32_t request = 0;

    explicit Fixture(std::size_t count = 4)
    {
        for (std::size_t i = 0; i < count; ++i) identities.push_back(Identity::generate());
        const auto group = token(900);
        genesis = {group, member(0), token(901), initialKey->commitment(group, 0)};
        for (std::size_t i = 0; i < count; ++i) {
            stores.push_back(std::make_unique<MemoryStore>(
                TrustJournal::initialRecord(genesis, member(i), Start)));
            journals.push_back(std::make_unique<TrustJournal>(*stores[i], genesis, member(i)));
        }
    }

    const Member &member(std::size_t i) const { return identities[i]->member(); }
    TrustJournal &journal(std::size_t i) const { return *journals[i]; }
    MemoryStore &store(std::size_t i) const { return *stores[i]; }

    void reopen(std::size_t i)
    {
        journals[i] = std::make_unique<TrustJournal>(store(i), genesis, member(i));
    }

    Proposal add(std::size_t applicant, std::size_t author = 0, std::uint64_t now = Start)
    {
        ++request;
        return journal(author).propose(Operation::Add, member(applicant), token(1000 + request),
                                       token(2000 + request), now, Until);
    }

    Proposal remove(std::size_t target, const SyncKey &key, std::size_t author = 0,
                    std::uint64_t now = Start)
    {
        ++request;
        const auto next = journal(author).inspect().state.keyGeneration + 1;
        return journal(author).propose(Operation::Remove, member(target), token(1000 + request),
                                       token(2000 + request), now, Until, key.commitment(genesis.group, next));
    }

    Certificate certificate(const Proposal &proposal, std::initializer_list<std::size_t> signers,
                            std::uint64_t now = Start)
    {
        Certificate result{proposal, {}};
        for (auto i : signers) {
            result.approvals.push_back(journal(i).approve(
                proposal, *identities[i], verificationDigest(proposal, member(i)), now));
        }
        return result;
    }

    void applyAll(const Certificate &certificate, std::uint64_t now = Start)
    {
        for (auto &item : journals) CHECK(item->observe(certificate, now) == ObserveResult::Applied);
    }

    void admitTwo() { applyAll(certificate(add(1), {0})); }
    void admitThree()
    {
        admitTwo();
        applyAll(certificate(add(2), {0, 1}));
    }

    Bytes prepare(std::size_t sender, std::size_t recipient, const SyncKey &key,
                  std::uint64_t now = Start)
    {
        return journal(sender).prepareDelivery(member(recipient).id, *identities[sender], key, now);
    }

    std::unique_ptr<SyncKey> receive(std::size_t recipient, const Bytes &wire, std::uint64_t now = Start)
    {
        return journal(recipient).receiveDelivery(wire, *identities[recipient], now);
    }

    KeyEnvelopeContext context(std::size_t sender, std::size_t recipient)
    {
        const auto state = journal(recipient).inspect().state;
        return {state.group, state.root, state.digest, state.intent, member(recipient),
                member(sender).id, state.keyGeneration, state.keyCommitment, KeyScope::CurrentGeneration};
    }
};

void number(Bytes &bytes, std::uint64_t value, unsigned width)
{
    for (unsigned i = width; i > 0; --i)
        bytes.push_back(static_cast<std::uint8_t>(value >> (8 * (i - 1))));
}

tx::Record legacy(const Fixture &fixture, const Certificate &accepted)
{
    // Freeze the previous lab format independently from the current writer.
    constexpr char domain[] = "CopyQ-Secure-Sync-trust-journal-lab-v1";
    auto record = TrustJournal::initialRecord(fixture.genesis, fixture.member(0), Fixture::Start);
    Bytes bytes(domain, domain + sizeof(domain));
    number(bytes, 1, 4);
    CHECK(record.keyIdentity.size() == 64);
    for (std::size_t i = 0; i < record.keyIdentity.size(); i += 2)
        bytes.push_back(static_cast<std::uint8_t>(std::stoul(record.keyIdentity.substr(i, 2), nullptr, 16)));
    number(bytes, Fixture::Start, 8);
    number(bytes, Fixture::Start, 8);
    number(bytes, 2, 4);
    const auto entry = [&](std::uint8_t kind, const Bytes &data) {
        bytes.push_back(kind);
        number(bytes, Fixture::Start, 8);
        number(bytes, data.size(), 4);
        bytes.insert(bytes.end(), data.begin(), data.end());
    };
    entry(1, encodeProposal(accepted.proposal));
    entry(2, encodeCertificate(accepted));
    payload(record) = std::move(bytes);
    record.generation = 2;
    return record;
}
} // namespace

int main()
{
    test("genesis, pending admission and outsider cannot deliver", [] {
        Fixture f;
        rejects<JournalError>(JournalCode::Delivery, [&] { f.prepare(0, 1, *f.initialKey); });
        const auto pending = f.certificate(f.add(1), {0});
        rejects<JournalError>(JournalCode::Delivery, [&] { f.prepare(0, 1, *f.initialKey); });
        f.applyAll(pending);
        rejects<Error>(ErrorCode::NotMember, [&] { f.prepare(2, 1, *f.initialKey); });
        rejects<Error>(ErrorCode::NotMember, [&] { f.prepare(0, 2, *f.initialKey); });
    });
    test("accepted Add admits only newcomer delivery with exact pinned identities", [] {
        Fixture f;
        f.admitThree();
        rejects<JournalError>(JournalCode::Delivery, [&] { f.prepare(0, 1, *f.initialKey); });
        rejects<JournalError>(JournalCode::Delivery, [&] { f.prepare(2, 2, *f.initialKey); });
        rejects<JournalError>(JournalCode::WrongPins, [&] {
            f.journal(0).prepareDelivery(f.member(2).id, *f.identities[1], *f.initialKey, Fixture::Start);
        });
        const auto wire = f.prepare(1, 2, *f.initialKey);
        CHECK(f.receive(2, wire)->sameKey(*f.initialKey));
        rejects<JournalError>(JournalCode::WrongPins, [&] {
            f.journal(2).receiveDelivery(wire, *f.identities[1], Fixture::Start);
        });
        rejects<JournalError>(JournalCode::Delivery, [&] { f.receive(0, wire); });
    });
    test("different valid quorum certificate encodings deliver the same accepted intent", [] {
        Fixture f;
        f.admitThree();
        const auto proposal = f.add(3);
        const auto left = f.certificate(proposal, {0, 1});
        const auto right = f.certificate(proposal, {1, 2});
        CHECK(encodeCertificate(left) != encodeCertificate(right));
        CHECK(f.journal(0).observe(left, Fixture::Start) == ObserveResult::Applied);
        CHECK(f.journal(3).observe(right, Fixture::Start) == ObserveResult::Applied);
        CHECK(f.journal(0).inspect().state.digest == f.journal(3).inspect().state.digest);
        CHECK(f.receive(3, f.prepare(0, 3, *f.initialKey))->sameKey(*f.initialKey));
    });
    test("wrong key, malformed wire, tampered signature and signed wrong root refuse", [] {
        Fixture f;
        f.admitTwo();
        const auto wrongKey = SyncKey::generate();
        rejects<EnvelopeError>(EnvelopeCode::KeyMismatch, [&] { f.prepare(0, 1, *wrongKey); });
        const auto wire = f.prepare(0, 1, *f.initialKey);
        const auto saved = st::serialize(f.store(0).record);
        rejects<EnvelopeError>(EnvelopeCode::KeyMismatch, [&] { f.prepare(0, 1, *wrongKey); });
        CHECK(st::serialize(f.store(0).record) == saved);
        auto corrupt = wire;
        corrupt.pop_back();
        rejects<EnvelopeError>(EnvelopeCode::Invalid, [&] { f.receive(1, corrupt); });
        corrupt = wire;
        corrupt.back() ^= 1;
        rejects<EnvelopeError>(EnvelopeCode::BadSignature, [&] { f.receive(1, corrupt); });
        auto otherRoot = KeyEnvelopeCodec::inspect(wire);
        otherRoot.root[0] ^= 1;
        const auto wrongRoot = KeyEnvelopeCodec::seal(otherRoot, *f.identities[0], *f.initialKey);
        rejects<EnvelopeError>(EnvelopeCode::ContextMismatch, [&] { f.receive(1, wrongRoot); });
        CHECK(f.receive(1, wire)->sameKey(*f.initialKey));
    });
    test("Remove delivers a fresh generation only between distinct survivors", [] {
        Fixture f;
        f.admitThree();
        const auto old = f.prepare(1, 2, *f.initialKey);
        auto key = SyncKey::generate();
        f.applyAll(f.certificate(f.remove(0, *key, 1), {1, 2}));
        CHECK(f.journal(1).inspect().state.keyGeneration == 1);
        CHECK(!contains(payload(f.store(1).record), old));
        rejects<EnvelopeError>(EnvelopeCode::ContextMismatch, [&] { f.receive(2, old); });
        rejects<Error>(ErrorCode::NotMember, [&] { f.prepare(0, 1, *key); });
        rejects<Error>(ErrorCode::NotMember, [&] { f.prepare(1, 0, *key); });
        rejects<JournalError>(JournalCode::Delivery, [&] { f.prepare(1, 1, *key); });
        const auto wire = f.prepare(1, 2, *key);
        CHECK(f.receive(2, wire)->sameKey(*key));
        rejects<Error>(ErrorCode::NotMember, [&] { f.receive(0, wire); });
        CHECK(f.receive(1, f.prepare(2, 1, *key))->sameKey(*key));
    });
    test("accepted fresh commitment cannot reauthorize old raw key on either endpoint", [] {
        Fixture f(5);
        f.admitThree();
        auto next = SyncKey::generate();
        f.applyAll(f.certificate(f.remove(2, *next), {0, 1}));
        CHECK(f.receive(1, f.prepare(0, 1, *next))->sameKey(*next));
        f.applyAll(f.certificate(f.add(3), {0, 1}));
        // Reuse a non-genesis prior generation after a further honest rotation.
        auto later = SyncKey::generate();
        f.applyAll(f.certificate(f.remove(3, *later), {0, 1}));
        f.applyAll(f.certificate(f.add(4), {0, 1}));
        f.applyAll(f.certificate(f.remove(4, *next), {0, 1}));
        CHECK(f.journal(0).inspect().state.keyGeneration == 3);
        rejects<JournalError>(JournalCode::KeyReuse, [&] { f.prepare(0, 1, *next); });
        // A malicious current member can call the raw codec, but the receiver
        // checks older generations before returning the recovered key.
        const auto reused = KeyEnvelopeCodec::seal(f.context(0, 1), *f.identities[0], *next);
        rejects<JournalError>(JournalCode::KeyReuse, [&] { f.receive(1, reused); });

        Fixture genesisReuse;
        genesisReuse.admitThree();
        genesisReuse.applyAll(genesisReuse.certificate(genesisReuse.remove(2, *genesisReuse.initialKey), {0, 1}));
        rejects<JournalError>(JournalCode::KeyReuse, [&] { genesisReuse.prepare(0, 1, *genesisReuse.initialKey); });
        const auto original = KeyEnvelopeCodec::seal(genesisReuse.context(0, 1), *genesisReuse.identities[0],
                                                    *genesisReuse.initialKey);
        rejects<JournalError>(JournalCode::KeyReuse, [&] { genesisReuse.receive(1, original); });
    });
    test("cached ciphertext retries exactly and its preparation advances the clock watermark", [] {
        Fixture f;
        f.admitTwo();
        const auto wire = f.prepare(0, 1, *f.initialKey, 110);
        CHECK(contains(payload(f.store(0).record), wire));
        f.reopen(0);
        CHECK(f.prepare(0, 1, *f.initialKey, 111) == wire);
        rejects<JournalError>(JournalCode::ClockRollback, [&] { f.prepare(0, 1, *f.initialKey, 109); });
        const auto earlier = f.add(2, 1, 109);
        rejects<JournalError>(JournalCode::ClockRollback, [&] {
            f.journal(0).approve(earlier, *f.identities[0], verificationDigest(earlier, f.member(0)), 109);
        });
        CHECK(f.receive(1, wire, 111)->sameKey(*f.initialKey));
    });
    test("reopen authenticates cached ciphertext and rejects a different sender's valid package", [] {
        Fixture f;
        f.admitThree();
        const auto wire = f.prepare(0, 2, *f.initialKey);
        const auto otherSender = f.prepare(1, 2, *f.initialKey);
        CHECK(otherSender.size() == wire.size());
        const auto good = f.store(0).record;
        const auto replace = [&](const Bytes &replacement) {
            f.store(0).record = good;
            auto &bytes = payload(f.store(0).record);
            const auto start = std::search(bytes.begin(), bytes.end(), wire.begin(), wire.end());
            CHECK(start != bytes.end());
            std::copy(replacement.begin(), replacement.end(), start);
        };
        auto corrupted = wire;
        corrupted.back() ^= 1;
        replace(corrupted);
        rejects<EnvelopeError>(EnvelopeCode::BadSignature, [&] { f.reopen(0); });
        replace(otherSender);
        rejects<EnvelopeError>(EnvelopeCode::ContextMismatch, [&] { f.reopen(0); });
        f.store(0).record = good;
        f.reopen(0);
        CHECK(f.prepare(0, 2, *f.initialKey) == wire);
    });
    test("new accepted head discards Add outbox and rejects stale ciphertext", [] {
        Fixture f;
        f.admitTwo();
        const auto old = f.prepare(0, 1, *f.initialKey);
        f.applyAll(f.certificate(f.add(2), {0, 1}));
        CHECK(!contains(payload(f.store(0).record), old));
        rejects<JournalError>(JournalCode::Delivery, [&] { f.prepare(0, 1, *f.initialKey); });
        rejects<JournalError>(JournalCode::Delivery, [&] { f.receive(1, old); });
        const auto current = f.prepare(0, 2, *f.initialKey);
        CHECK(current != old);
        rejects<EnvelopeError>(EnvelopeCode::ContextMismatch, [&] { f.receive(2, old); });
        CHECK(f.receive(2, current)->sameKey(*f.initialKey));
    });
    test("authenticated competing head revokes delivery and clears its persisted outbox", [] {
        Fixture f;
        const auto competing = f.add(2);
        f.admitTwo();
        const auto wire = f.prepare(0, 1, *f.initialKey);
        const Certificate fork{competing, {{f.member(0).id, f.identities[0]->sign(
            approvalBytes(competing, f.member(0)))}}};
        CHECK(f.journal(0).observe(fork, 150) == ObserveResult::ForkDetected);
        CHECK(f.journal(1).observe(fork, 150) == ObserveResult::ForkDetected);
        CHECK(!contains(payload(f.store(0).record), wire));
        f.reopen(0);
        f.reopen(1);
        rejects<Error>(ErrorCode::Forked, [&] { f.prepare(0, 1, *f.initialKey, 150); });
        rejects<Error>(ErrorCode::Forked, [&] { f.receive(1, wire, 150); });
    });
    test("precommit failure exposes no package and requires opening the journal again", [] {
        Fixture f;
        f.admitTwo();
        const auto before = st::serialize(f.store(0).record);
        f.store(0).failure = MemoryStore::Failure::Before;
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.prepare(0, 1, *f.initialKey); });
        CHECK(st::serialize(f.store(0).record) == before);
        rejects<JournalError>(JournalCode::Uncertain, [&] { f.prepare(0, 1, *f.initialKey); });
        f.reopen(0);
        CHECK(f.receive(1, f.prepare(0, 1, *f.initialKey))->sameKey(*f.initialKey));
    });
    test("lost commit acknowledgement reopens the durable package without resealing", [] {
        Fixture f;
        f.admitTwo();
        f.store(0).failure = MemoryStore::Failure::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.prepare(0, 1, *f.initialKey); });
        const auto durable = payload(f.store(0).record);
        const auto commits = f.store(0).commits;
        rejects<JournalError>(JournalCode::Uncertain, [&] { f.journal(0).inspect(); });
        f.reopen(0);
        const auto wire = f.prepare(0, 1, *f.initialKey);
        CHECK(contains(durable, wire));
        CHECK(f.store(0).commits == commits + 1);
        CHECK(f.receive(1, wire)->sameKey(*f.initialKey));
    });
    test("version 1 journal retains prior vote and accepted head when adding an outbox", [] {
        Fixture f;
        const auto accepted = f.certificate(f.add(1), {0});
        f.applyAll(accepted);
        f.store(0).record = legacy(f, accepted);
        f.reopen(0);
        const auto prior = f.journal(0).inspect();
        CHECK(prior.reservations == 1);
        CHECK(prior.certificates == std::vector<Bytes>{encodeCertificate(accepted)});
        const auto wire = f.prepare(0, 1, *f.initialKey);
        f.reopen(0);
        CHECK(f.journal(0).inspect().state.digest == prior.state.digest);
        CHECK(f.journal(0).inspect().reservations == prior.reservations);
        CHECK(f.prepare(0, 1, *f.initialKey) == wire);
        CHECK(f.receive(1, wire)->sameKey(*f.initialKey));
    });
#ifdef __linux__
    test("encrypted disk vault and delivery journal recover after closing all sender handles", [] {
        Fixture f;
        char pattern[] = "/tmp/cqs-key-delivery-XXXXXX";
        const auto *made = ::mkdtemp(pattern);
        CHECK(made);
        const std::filesystem::path directory(made);
        struct Cleanup {
            std::filesystem::path path;
            ~Cleanup() { std::error_code error; std::filesystem::remove_all(path, error); }
        } cleanup{directory};
        const auto vault = directory / "vault";
        const auto journalPath = directory / "journal";
        CHECK(std::filesystem::create_directory(vault));
        CHECK(std::filesystem::create_directory(journalPath));
        for (const auto &path : {vault, journalPath})
            std::filesystem::permissions(path, std::filesystem::perms::owner_all);
        const Bytes vaultKey(32, 0x47), journalKey(32, 0x52); // Public test keys.
        const IdentityVaultPins pins{f.genesis.group, f.journal(0).inspect().state.root, f.member(0)};
        const auto binding = TrustJournal::binding(f.genesis, pins.member);
        Bytes wire;
        {
            IdentityVault::initialize(vault, pins, vaultKey, *f.identities[0]);
            st::FileStore disk(journalPath, binding, journalKey);
            TrustJournal::initialize(disk, f.genesis, pins.member, Fixture::Start);
            TrustJournal sender(disk, f.genesis, pins.member);
            const auto proposal = f.add(1);
            const auto vote = sender.approve(proposal, *f.identities[0],
                verificationDigest(proposal, pins.member), Fixture::Start);
            f.applyAll({proposal, {vote}});
            CHECK(sender.observe({proposal, {vote}}, Fixture::Start) == ObserveResult::Applied);
            wire = sender.prepareDelivery(f.member(1).id, *f.identities[0], *f.initialKey, Fixture::Start);
        }
        f.identities[0].reset();
        auto restored = IdentityVault::load(vault, pins, vaultKey);
        CHECK(restored->member() == pins.member);
        st::FileStore disk(journalPath, binding, journalKey);
        TrustJournal reopened(disk, f.genesis, pins.member);
        CHECK(reopened.prepareDelivery(f.member(1).id, *restored, *f.initialKey, Fixture::Start) == wire);
        CHECK(f.receive(1, wire)->sameKey(*f.initialKey));
        std::ifstream input(journalPath / st::FileStore::RecordName, std::ios::binary);
        CHECK(input.good());
        const Bytes ciphertext{std::istreambuf_iterator<char>(input), {}};
        CHECK(!contains(ciphertext, wire));
    });
#endif
    std::cout << cases << " device key delivery test cases passed\n";
}
