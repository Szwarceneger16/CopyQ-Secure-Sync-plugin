// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_identity_vault.h"
#include "device_key_receipt.h"
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
using cqs::crypto::Bytes;
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

template<class Fn>
void refuses(Fn &&action)
{
    bool rejected = false;
    try {
        action();
    } catch (const JournalError &) {
        rejected = true;
    } catch (const Error &) {
        rejected = true;
    } catch (const ReceiptError &) {
        rejected = true;
    } catch (const EnvelopeError &) {
        rejected = true;
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

bool contains(const Bytes &bytes, const Bytes &needle)
{
    return std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end()) != bytes.end();
}

Bytes &payload(tx::Record &record)
{
    CHECK(record.local && record.local->size() == 1 && record.local->front().size() == 1);
    return record.local->front().begin()->second;
}

class MemoryStore final : public tx::Store {
public:
    enum class Failure { None, Before, After };
    explicit MemoryStore(tx::Record value) : record(std::move(value)) {}

    tx::Record record;
    Failure failure = Failure::None;
    unsigned commits = 0;

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
        return record;
    }

    void commit(const tx::Record &expected, const tx::Record &replacement) override
    {
        CHECK(leased_);
        CHECK(st::serialize(record) == st::serialize(expected));
        CHECK(replacement.generation == record.generation + 1);
        ++commits;
        const auto injected = std::exchange(failure, Failure::None);
        if (injected == Failure::Before) throw st::Error(st::ErrorCode::Io, "Synthetic precommit failure");
        record = replacement;
        if (injected == Failure::After)
            throw st::Error(st::ErrorCode::CommitUnconfirmed, "Synthetic lost commit acknowledgement");
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
    std::unique_ptr<SyncKey> key = SyncKey::generate();
    std::vector<std::unique_ptr<Identity>> identities;
    Genesis genesis;
    std::vector<std::unique_ptr<MemoryStore>> stores;
    std::vector<std::unique_ptr<TrustJournal>> journals;
    std::uint32_t sequence = 0;

    explicit Fixture(std::size_t count = 4)
    {
        for (std::size_t i = 0; i < count; ++i) identities.push_back(Identity::generate());
        const auto group = token(500);
        genesis = {group, member(0), token(501), key->commitment(group, 0)};
        for (std::size_t i = 0; i < count; ++i) {
            stores.push_back(std::make_unique<MemoryStore>(TrustJournal::initialRecord(genesis, member(i), Now)));
            journals.push_back(std::make_unique<TrustJournal>(*stores.back(), genesis, member(i)));
        }
    }

    const Member &member(std::size_t i) const { return identities[i]->member(); }
    TrustJournal &journal(std::size_t i) const { return *journals[i]; }
    MemoryStore &store(std::size_t i) const { return *stores[i]; }

    void reopen(std::size_t i)
    {
        journals[i] = std::make_unique<TrustJournal>(store(i), genesis, member(i));
    }

    Proposal add(std::size_t subject)
    {
        ++sequence;
        return journal(0).propose(Operation::Add, member(subject), token(600 + sequence),
                                  token(700 + sequence), Now, 1000);
    }

    Certificate certificate(const Proposal &proposal, std::initializer_list<std::size_t> signers)
    {
        Certificate result{proposal, {}};
        for (const auto signer : signers) {
            result.approvals.push_back(journal(signer).approve(proposal, *identities[signer],
                verificationDigest(proposal, member(signer)), Now));
        }
        return result;
    }

    void apply(const Certificate &certificate)
    {
        for (auto &item : journals) CHECK(item->observe(certificate, Now) == ObserveResult::Applied);
    }

    void admitTwo() { apply(certificate(add(1), {0})); }
    void admitThird() { apply(certificate(add(2), {0, 1})); }

    Bytes prepare(std::size_t sender, std::size_t recipient, const SyncKey &dataKey,
                  std::uint64_t now = Now)
    {
        return journal(sender).prepareDelivery(member(recipient).id, *identities[sender], dataKey, now);
    }

    Bytes catchUp(std::size_t sender, std::size_t recipient)
    {
        return journal(sender).prepareCatchUp(member(recipient).id, *identities[sender], *key, Now);
    }

    Bytes install(std::size_t recipient, const Bytes &wire, std::uint64_t now = Now)
    {
        return journal(recipient).installDelivery(wire, *identities[recipient], now);
    }

    std::unique_ptr<SyncKey> load(std::size_t recipient, std::uint64_t now = Now)
    {
        return journal(recipient).loadInstalledKey(*identities[recipient], now);
    }
};

Token digest(const Bytes &bytes)
{
    const auto hash = cqs::crypto::sha256(bytes);
    Token result{};
    CHECK(hash.size() == result.size());
    std::copy(hash.begin(), hash.end(), result.begin());
    return result;
}

void appendNumber(Bytes &bytes, std::uint64_t value, unsigned width)
{
    for (unsigned i = width; i > 0; --i)
        bytes.push_back(static_cast<std::uint8_t>(value >> (8 * (i - 1))));
}

tx::Record legacyOutbox(const Fixture &fixture, const Certificate &accepted, const Bytes &wire)
{
    // Independent previous schema-2 encoding: reserve, observe, one outbox.
    constexpr char domain[] = "CopyQ-Secure-Sync-trust-journal-lab-v1";
    auto record = TrustJournal::initialRecord(fixture.genesis, fixture.member(0), Now);
    Bytes bytes(domain, domain + sizeof(domain));
    appendNumber(bytes, 2, 4);
    CHECK(record.keyIdentity.size() == 64);
    for (std::size_t i = 0; i < record.keyIdentity.size(); i += 2)
        bytes.push_back(static_cast<std::uint8_t>(std::stoul(record.keyIdentity.substr(i, 2), nullptr, 16)));
    appendNumber(bytes, Now, 8);
    appendNumber(bytes, Now, 8);
    appendNumber(bytes, 2, 4);
    const auto entry = [&](std::uint8_t kind, const Bytes &data) {
        bytes.push_back(kind);
        appendNumber(bytes, Now, 8);
        appendNumber(bytes, data.size(), 4);
        bytes.insert(bytes.end(), data.begin(), data.end());
    };
    entry(1, encodeProposal(accepted.proposal));
    entry(2, encodeCertificate(accepted));
    appendNumber(bytes, 1, 4);
    const auto &recipient = fixture.member(1).id;
    bytes.insert(bytes.end(), recipient.begin(), recipient.end());
    appendNumber(bytes, wire.size(), 4);
    bytes.insert(bytes.end(), wire.begin(), wire.end());
    payload(record) = std::move(bytes);
    record.generation = 3;
    return record;
}

#ifdef __linux__
class TemporaryDirectory final {
public:
    TemporaryDirectory()
    {
        char pattern[] = "/tmp/cqs-key-lifecycle-XXXXXX";
        const auto *made = ::mkdtemp(pattern);
        CHECK(made);
        path_ = made;
    }

    ~TemporaryDirectory()
    {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    std::filesystem::path create(const char *name)
    {
        const auto path = path_ / name;
        CHECK(std::filesystem::create_directory(path));
        std::filesystem::permissions(path, std::filesystem::perms::owner_all);
        return path;
    }

private:
    std::filesystem::path path_;
};
#endif
} // namespace

int main()
{
    test("receipt identifies an exact installed envelope and updates the sender once", [] {
        Fixture f;
        f.admitTwo();
        rejects<JournalError>(JournalCode::MissingKey, [&] { f.load(1); });
        const auto wire = f.prepare(0, 1, *f.key);
        CHECK(f.journal(1).receiveDelivery(wire, *f.identities[1], Now)->sameKey(*f.key));
        CHECK(!f.journal(1).inspect().installedKey);
        CHECK(f.journal(0).inspect().confirmedDeliveries.empty());

        const auto receipt = f.install(1, wire);
        CHECK(f.load(1)->sameKey(*f.key));
        CHECK(f.journal(1).inspect().installedKey);
        CHECK(contains(payload(f.store(1).record), wire));
        auto secret = f.key->exportPrivate();
        const bool storesPlaintext = contains(payload(f.store(1).record), secret);
        cqs::crypto::wipe(secret);
        CHECK(!storesPlaintext);
        const auto info = KeyReceiptCodec::inspect(receipt);
        const auto context = KeyEnvelopeCodec::inspect(wire);
        CHECK(info.group == context.group && info.root == context.root);
        CHECK(info.successor == context.successor && info.proposal == context.proposal);
        CHECK(info.sender == f.member(0).id && info.recipient == f.member(1));
        CHECK(info.generation == context.generation && info.commitment == context.commitment);
        CHECK(info.envelopeDigest == digest(wire) && info.scope == KeyScope::CurrentGeneration);
        CHECK(f.journal(0).recordReceipt(receipt, Now));
        const auto saved = st::serialize(f.store(0).record);
        CHECK(!f.journal(0).recordReceipt(receipt, Now));
        CHECK(st::serialize(f.store(0).record) == saved);
        CHECK(f.journal(0).inspect().confirmedDeliveries == std::vector<Token>{f.member(1).id});
    });
    test("failed key installation returns no receipt and a fresh open still has no key", [] {
        Fixture f;
        f.admitTwo();
        const auto wire = f.prepare(0, 1, *f.key);
        const auto prior = st::serialize(f.store(1).record);
        f.store(1).failure = MemoryStore::Failure::Before;
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.install(1, wire); });
        CHECK(st::serialize(f.store(1).record) == prior);
        rejects<JournalError>(JournalCode::Uncertain, [&] { f.install(1, wire); });
        f.reopen(1);
        CHECK(!f.journal(1).inspect().installedKey);
        rejects<JournalError>(JournalCode::MissingKey, [&] { f.load(1); });
        CHECK(f.journal(0).recordReceipt(f.install(1, wire), Now));
    });
    test("unconfirmed installation returns no receipt and reopens the exact durable package", [] {
        Fixture f;
        f.admitTwo();
        const auto wire = f.prepare(0, 1, *f.key);
        f.store(1).failure = MemoryStore::Failure::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.install(1, wire); });
        rejects<JournalError>(JournalCode::Uncertain, [&] { f.load(1); });
        CHECK(contains(payload(f.store(1).record), wire));
        CHECK(f.journal(0).inspect().confirmedDeliveries.empty());
        f.reopen(1);
        CHECK(f.load(1)->sameKey(*f.key));
        const auto receipt = f.install(1, wire);
        f.reopen(1);
        CHECK(f.install(1, wire) == receipt);
        CHECK(f.journal(0).recordReceipt(receipt, Now));
    });
    test("forged or mismatched receipts leave the current outbox unchanged", [] {
        Fixture f;
        f.admitTwo();
        const auto wire = f.prepare(0, 1, *f.key);
        const auto receipt = f.install(1, wire);
        const auto before = st::serialize(f.store(0).record);

        auto forged = receipt;
        constexpr std::size_t signatureSize = Signature{}.size();
        const auto messageEnd = forged.end() - signatureSize;
        const auto foreignSignature = f.identities[3]->sign(Bytes(forged.begin(), messageEnd));
        std::copy(foreignSignature.begin(), foreignSignature.end(), messageEnd);
        rejects<ReceiptError>(ReceiptCode::BadSignature, [&] { f.journal(0).recordReceipt(forged, Now); });
        auto truncated = receipt;
        truncated.pop_back();
        rejects<ReceiptError>(ReceiptCode::Invalid, [&] { f.journal(0).recordReceipt(truncated, Now); });

        const auto expectRefused = [&](const ReceiptContext &context) {
            const auto signedOther = KeyReceiptCodec::sign(context, *f.identities[1]);
            rejects<ReceiptError>(ReceiptCode::ContextMismatch, [&] { f.journal(0).recordReceipt(signedOther, Now); });
        };
        const auto expected = KeyReceiptCodec::inspect(receipt);
        auto altered = expected;
        altered.sender = f.member(2).id;
        expectRefused(altered);
        altered = expected;
        altered.successor[0] ^= 1;
        expectRefused(altered);
        altered = expected;
        altered.envelopeDigest = digest(KeyEnvelopeCodec::seal(KeyEnvelopeCodec::inspect(wire),
                                                              *f.identities[0], *f.key));
        CHECK(altered.envelopeDigest != expected.envelopeDigest);
        expectRefused(altered);
        altered = expected;
        altered.scope = KeyScope::CatchUp;
        expectRefused(altered);

        CHECK(st::serialize(f.store(0).record) == before);
        CHECK(f.journal(0).recordReceipt(receipt, Now));
    });
    test("unchanged generation carries an installed key while invalidating stale receipts", [] {
        Fixture f;
        f.admitTwo();
        const auto firstWire = f.prepare(0, 1, *f.key);
        const auto firstReceipt = f.install(1, firstWire);
        CHECK(f.journal(0).recordReceipt(firstReceipt, Now));
        f.admitThird();
        f.reopen(1);
        CHECK(f.journal(1).inspect().installedKey);
        CHECK(f.load(1)->sameKey(*f.key));
        CHECK(f.journal(0).inspect().confirmedDeliveries.empty());
        const auto currentWire = f.prepare(0, 2, *f.key);
        rejects<JournalError>(JournalCode::Delivery, [&] { f.journal(0).recordReceipt(firstReceipt, Now); });
        refuses([&] { f.install(1, firstWire); });
        CHECK(f.journal(0).recordReceipt(f.install(2, currentWire), Now));
    });
    test("explicit catch-up reaches the earlier current member who missed the first delivery", [] {
        Fixture f;
        f.admitTwo();
        const auto stale = f.prepare(0, 1, *f.key);
        f.admitThird();
        CHECK(!f.journal(1).inspect().installedKey);
        refuses([&] { f.install(1, stale); });
        refuses([&] { f.prepare(0, 1, *f.key); });
        refuses([&] { f.catchUp(0, 2); });
        refuses([&] { f.catchUp(0, 0); });
        refuses([&] { f.catchUp(0, 3); });
        refuses([&] { f.catchUp(3, 1); });

        const auto wire = f.catchUp(0, 1);
        CHECK(KeyEnvelopeCodec::inspect(wire).scope == KeyScope::CatchUp);
        f.reopen(0);
        CHECK(f.catchUp(0, 1) == wire);
        const auto receipt = f.install(1, wire);
        auto wrongScope = KeyReceiptCodec::inspect(receipt);
        CHECK(wrongScope.scope == KeyScope::CatchUp);
        wrongScope.scope = KeyScope::CurrentGeneration;
        const auto forgedScope = KeyReceiptCodec::sign(wrongScope, *f.identities[1]);
        rejects<ReceiptError>(ReceiptCode::ContextMismatch, [&] { f.journal(0).recordReceipt(forgedScope, Now); });
        CHECK(f.journal(0).recordReceipt(receipt, Now));
        CHECK(f.load(1)->sameKey(*f.key));

        const auto newest = f.prepare(0, 2, *f.key);
        CHECK(KeyEnvelopeCodec::inspect(newest).scope == KeyScope::CurrentGeneration);
        CHECK(f.journal(0).recordReceipt(f.install(2, newest), Now));
    });
    test("another current sender's valid package earns a receipt only after its own commit", [] {
        Fixture f;
        f.admitTwo();
        f.admitThird();
        const auto first = f.prepare(0, 2, *f.key);
        const auto second = f.prepare(1, 2, *f.key);
        const auto firstReceipt = f.install(2, first);
        const auto before = st::serialize(f.store(2).record);
        f.store(2).failure = MemoryStore::Failure::Before;
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.install(2, second); });
        CHECK(st::serialize(f.store(2).record) == before);
        f.reopen(2);
        CHECK(f.load(2)->sameKey(*f.key));
        CHECK(f.install(2, first) == firstReceipt);
        const auto secondReceipt = f.install(2, second);
        CHECK(KeyReceiptCodec::inspect(secondReceipt).envelopeDigest == digest(second));
        CHECK(KeyReceiptCodec::inspect(secondReceipt).sender == f.member(1).id);
        CHECK(f.journal(0).recordReceipt(firstReceipt, Now));
        CHECK(f.journal(1).recordReceipt(secondReceipt, Now));
        CHECK(contains(payload(f.store(2).record), second));
        CHECK(!contains(payload(f.store(2).record), first));
    });
    test("rotation clears the old installed key and admits only current survivors", [] {
        Fixture f;
        f.admitTwo();
        f.install(1, f.prepare(0, 1, *f.key));
        f.admitThird();
        const auto removedWire = f.prepare(0, 2, *f.key);
        const auto oldReceipt = f.install(2, removedWire);
        CHECK(f.load(1)->sameKey(*f.key) && f.load(2)->sameKey(*f.key));

        const auto rotated = SyncKey::generate();
        const auto proposal = f.journal(0).propose(Operation::Remove, f.member(2), token(901), token(902),
                                                  Now, 1000, rotated->commitment(f.genesis.group, 1));
        f.apply(f.certificate(proposal, {0, 1}));
        f.reopen(1);
        f.reopen(2);
        CHECK(!f.journal(1).inspect().installedKey && !f.journal(2).inspect().installedKey);
        rejects<JournalError>(JournalCode::MissingKey, [&] { f.load(1); });
        rejects<Error>(ErrorCode::NotMember, [&] { f.load(2); });
        refuses([&] { f.install(2, removedWire); });
        refuses([&] { f.journal(0).recordReceipt(oldReceipt, Now); });
        refuses([&] { f.catchUp(0, 1); });
        refuses([&] { f.prepare(0, 2, *rotated); });

        const auto fresh = f.prepare(0, 1, *rotated);
        CHECK(KeyEnvelopeCodec::inspect(fresh).generation == 1);
        refuses([&] { f.install(2, fresh); });
        CHECK(f.journal(0).recordReceipt(f.install(1, fresh), Now));
        CHECK(f.load(1)->sameKey(*rotated));
    });
    test("a persisted fork removes installed key access and outstanding confirmations", [] {
        Fixture f;
        const auto sibling = f.add(2);
        f.admitTwo();
        const auto wire = f.prepare(0, 1, *f.key);
        const auto receipt = f.install(1, wire);
        CHECK(f.journal(0).recordReceipt(receipt, Now));
        // Bypass the local vote reservation to model a compromised peer.
        const Certificate fork{sibling, {{f.member(0).id, f.identities[0]->sign(
            approvalBytes(sibling, f.member(0)))}}};
        for (const auto i : {0U, 1U}) {
            CHECK(f.journal(i).observe(fork, Now) == ObserveResult::ForkDetected);
            f.reopen(i);
            CHECK(f.journal(i).inspect().forked);
            CHECK(!f.journal(i).inspect().installedKey);
            CHECK(f.journal(i).inspect().confirmedDeliveries.empty());
        }
        rejects<Error>(ErrorCode::Forked, [&] { f.load(1); });
        rejects<Error>(ErrorCode::Forked, [&] { f.install(1, wire); });
        rejects<Error>(ErrorCode::Forked, [&] { f.journal(0).recordReceipt(receipt, Now); });
    });
    test("receipt acknowledgement survives a lost sender commit response", [] {
        Fixture f;
        f.admitTwo();
        const auto receipt = f.install(1, f.prepare(0, 1, *f.key));
        f.store(0).failure = MemoryStore::Failure::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.journal(0).recordReceipt(receipt, Now); });
        rejects<JournalError>(JournalCode::Uncertain, [&] { f.journal(0).inspect(); });
        f.reopen(0);
        CHECK(f.journal(0).inspect().confirmedDeliveries == std::vector<Token>{f.member(1).id});
        CHECK(!f.journal(0).recordReceipt(receipt, Now));
    });
    test("installation and confirmation preserve their trusted clock watermarks", [] {
        Fixture f;
        f.admitTwo();
        const auto wire = f.prepare(0, 1, *f.key);
        const auto receipt = f.install(1, wire, 120);
        f.reopen(1);
        rejects<JournalError>(JournalCode::ClockRollback, [&] { f.load(1, 119); });
        rejects<JournalError>(JournalCode::ClockRollback, [&] { f.install(1, wire, 119); });
        CHECK(f.load(1, 120)->sameKey(*f.key));
        CHECK(f.journal(0).recordReceipt(receipt, 130));
        f.reopen(0);
        rejects<JournalError>(JournalCode::ClockRollback, [&] { f.journal(0).recordReceipt(receipt, 129); });
        CHECK(!f.journal(0).recordReceipt(receipt, 130));
    });
    test("version 2 prepared package remains available for an exact version 3 receipt", [] {
        Fixture f;
        const auto accepted = f.certificate(f.add(1), {0});
        f.apply(accepted);
        const auto wire = f.prepare(0, 1, *f.key);
        f.store(0).record = legacyOutbox(f, accepted, wire);
        f.reopen(0);
        CHECK(f.prepare(0, 1, *f.key) == wire);
        CHECK(f.journal(0).inspect().confirmedDeliveries.empty());
        CHECK(f.journal(0).recordReceipt(f.install(1, wire), Now));
        f.reopen(0);
        CHECK(f.prepare(0, 1, *f.key) == wire);
        CHECK(f.journal(0).inspect().confirmedDeliveries == std::vector<Token>{f.member(1).id});
    });
#ifdef __linux__
    test("encrypted sender and recipient journals retain exact packages, installed key and receipts", [] {
        Fixture f;
        TemporaryDirectory directory;
        const auto senderPath = directory.create("sender");
        const auto recipientPath = directory.create("recipient");
        const auto vaultPath = directory.create("identity");
        const Bytes senderKey(32, 0x41), recipientKey(32, 0x52), vaultKey(32, 0x63); // Public test keys.
        const auto senderBinding = TrustJournal::binding(f.genesis, f.member(0));
        const auto recipientBinding = TrustJournal::binding(f.genesis, f.member(1));
        const IdentityVaultPins pins{f.genesis.group, f.journal(0).inspect().state.root, f.member(1)};
        const auto accepted = f.certificate(f.add(1), {0});
        Bytes wire, receipt;
        {
            IdentityVault::initialize(vaultPath, pins, vaultKey, *f.identities[1]);
            st::FileStore senderStore(senderPath, senderBinding, senderKey);
            st::FileStore recipientStore(recipientPath, recipientBinding, recipientKey);
            TrustJournal::initialize(senderStore, f.genesis, f.member(0), Now);
            TrustJournal::initialize(recipientStore, f.genesis, pins.member, Now);
            TrustJournal sender(senderStore, f.genesis, f.member(0));
            TrustJournal recipient(recipientStore, f.genesis, pins.member);
            CHECK(sender.observe(accepted, Now) == ObserveResult::Applied);
            CHECK(recipient.observe(accepted, Now) == ObserveResult::Applied);
            wire = sender.prepareDelivery(pins.member.id, *f.identities[0], *f.key, Now);
            receipt = recipient.installDelivery(wire, *f.identities[1], Now);
            CHECK(sender.recordReceipt(receipt, Now));
        }
        f.identities[1].reset();
        const auto restored = IdentityVault::load(vaultPath, pins, vaultKey);
        st::FileStore senderStore(senderPath, senderBinding, senderKey);
        st::FileStore recipientStore(recipientPath, recipientBinding, recipientKey);
        TrustJournal sender(senderStore, f.genesis, f.member(0));
        TrustJournal recipient(recipientStore, f.genesis, pins.member);
        CHECK(sender.prepareDelivery(pins.member.id, *f.identities[0], *f.key, Now) == wire);
        CHECK(sender.inspect().confirmedDeliveries == std::vector<Token>{pins.member.id});
        CHECK(!sender.recordReceipt(receipt, Now));
        CHECK(recipient.inspect().installedKey);
        CHECK(recipient.loadInstalledKey(*restored, Now)->sameKey(*f.key));
        CHECK(recipient.installDelivery(wire, *restored, Now) == receipt);
        std::ifstream input(recipientPath / st::FileStore::RecordName, std::ios::binary);
        CHECK(input.good());
        const Bytes ciphertext{std::istreambuf_iterator<char>(input), {}};
        CHECK(!contains(ciphertext, wire));
    });
#endif
    std::cout << cases << " device key lifecycle test cases passed\n";
}
