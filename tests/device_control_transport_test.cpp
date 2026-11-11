// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_key_receipt.h"
#include "device_trust_journal.h"
#include "storage.h"
#include "test_check.h"

#include <functional>
#include <iostream>
#ifdef __linux__
#include <array>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#endif

using cqs::crypto::Bytes;
namespace storage = cqs::storage;

namespace {
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

#ifdef __linux__
namespace fs = std::filesystem;
namespace st = cqs::state;
namespace tx = cqs::transaction;
using namespace cqs::trust;
constexpr std::uint64_t Now = 100;

template<class Fn>
void refusesPacket(Fn &&action)
{
    bool rejected = false;
    try {
        action();
    } catch (const storage::Error &) {
        rejected = true;
    }
    CHECK(rejected);
}

void write(const fs::path &file, const Bytes &bytes)
{
    std::ofstream output(file, std::ios::binary | std::ios::trunc);
    CHECK(output.good());
    output.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output.close();
    CHECK(!output.fail());
    fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write);
}

Bytes read(const fs::path &file)
{
    std::ifstream input(file, std::ios::binary);
    CHECK(input.good());
    return {std::istreambuf_iterator<char>(input), {}};
}

struct stat identity(const fs::path &file)
{
    struct stat data{};
    CHECK(::lstat(file.c_str(), &data) == 0);
    return data;
}

void sameFile(const struct stat &before, const fs::path &file)
{
    const auto after = identity(file);
    CHECK(S_ISREG(after.st_mode) && after.st_nlink == 1);
    CHECK(after.st_dev == before.st_dev && after.st_ino == before.st_ino);
    CHECK(after.st_mtim.tv_sec == before.st_mtim.tv_sec && after.st_mtim.tv_nsec == before.st_mtim.tv_nsec);
}

std::size_t countFiles(const fs::path &directory)
{
    return static_cast<std::size_t>(std::distance(fs::directory_iterator(directory), fs::directory_iterator()));
}

struct TransportTree {
    fs::path base, root, control, events;

    explicit TransportTree(bool createControl = true)
    {
        char pattern[] = "/tmp/cqs-control-transport-XXXXXX";
        const auto *made = ::mkdtemp(pattern);
        CHECK(made);
        base = made;
        root = base / "transport";
        control = root / "control";
        events = root / "events";
        create(root);
        create(events);
        if (createControl) create(control);
    }

    ~TransportTree()
    {
        std::error_code error;
        fs::remove_all(base, error);
    }

    static void create(const fs::path &directory)
    {
        CHECK(fs::create_directory(directory));
        fs::permissions(directory, fs::perms::owner_all);
    }

    fs::path packet(const std::string &address) const { return control / (address + ".cqc"); }
};

Token token(std::uint32_t value)
{
    Token result{};
    for (unsigned i = 0; i < 4; ++i)
        result[31 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    return result;
}

struct Devices {
    TransportTree tree;
    std::unique_ptr<SyncKey> key = SyncKey::generate();
    std::array<std::unique_ptr<Identity>, 3> identities;
    Genesis genesis;
    std::array<fs::path, 3> paths;
    std::array<std::unique_ptr<st::FileStore>, 3> stores;
    std::array<std::unique_ptr<TrustJournal>, 3> journals;
    std::uint32_t sequence = 0;

    Devices()
    {
        for (auto &device : identities) device = Identity::generate();
        const auto group = token(500);
        genesis = {group, member(0), token(501), key->commitment(group, 0)};
        for (std::size_t i = 0; i < identities.size(); ++i) {
            paths[i] = tree.base / ("journal-" + std::to_string(i));
            TransportTree::create(paths[i]);
            openStore(i);
            TrustJournal::initialize(*stores[i], genesis, member(i), Now);
            journals[i] = std::make_unique<TrustJournal>(*stores[i], genesis, member(i));
        }
    }

    const Member &member(std::size_t i) const { return identities[i]->member(); }
    TrustJournal &journal(std::size_t i) const { return *journals[i]; }

    void openStore(std::size_t i)
    {
        // Distinct public test keys, used only with disposable fixture records.
        const Bytes credential(32, static_cast<std::uint8_t>(0x41 + i));
        stores[i] = std::make_unique<st::FileStore>(paths[i], TrustJournal::binding(genesis, member(i)), credential);
    }

    void reopen(std::size_t i)
    {
        journals[i].reset();
        stores[i].reset();
        openStore(i);
        journals[i] = std::make_unique<TrustJournal>(*stores[i], genesis, member(i));
    }

    Proposal add(std::size_t subject)
    {
        ++sequence;
        return journal(0).propose(Operation::Add, member(subject), token(600 + sequence),
                                  token(700 + sequence), Now, 1000);
    }

    Certificate admit(std::size_t subject)
    {
        const auto proposal = add(subject);
        Certificate certificate{proposal, {vote(proposal, 0)}};
        if (subject == 2) certificate.approvals.push_back(vote(proposal, 1));
        for (auto &journal : journals) CHECK(journal->observe(certificate, Now) == ObserveResult::Applied);
        return certificate;
    }

    Approval vote(const Proposal &proposal, std::size_t i)
    {
        return journal(i).approve(proposal, *identities[i], verificationDigest(proposal, member(i)), Now);
    }

    Bytes prepare(std::size_t recipient)
    {
        return journal(0).prepareDelivery(member(recipient).id, *identities[0], *key, Now);
    }
};

class FaultStore final : public tx::Store {
public:
    enum class Failure { None, Before, After };
    explicit FaultStore(tx::Record initial) : record(std::move(initial)) {}

    tx::Record record;
    Failure failure = Failure::None;
    std::function<void()> beforeCommit;
    std::function<void()> beforeUnlock;

    std::unique_ptr<Lease> lock() override
    {
        if (leased_) return {};
        auto lease = std::make_unique<Held>(*this);
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
        CHECK(st::serialize(expected) == st::serialize(record));
        CHECK(replacement.generation == record.generation + 1);
        if (beforeCommit) beforeCommit();
        const auto injected = std::exchange(failure, Failure::None);
        if (injected == Failure::Before) throw st::Error(st::ErrorCode::Io, "Synthetic precommit error");
        record = replacement;
        if (injected == Failure::After) throw st::Error(st::ErrorCode::CommitUnconfirmed, "Synthetic lost commit response");
    }

private:
    struct Held final : Lease {
        explicit Held(FaultStore &store) : store_(store) {}
        ~Held() override
        {
            if (store_.beforeUnlock) store_.beforeUnlock();
            store_.leased_ = false;
        }
        FaultStore &store_;
    };
    bool leased_ = false;
};
#endif
} // namespace

int main()
{
    test("opaque packet address is canonical SHA-256 and has bounded input", [] {
        const Bytes packet{'a', 'b', 'c'};
        const auto address = storage::controlPacketId(packet);
        CHECK(address == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        storage::validateControlPacketId(address);
        for (const auto &bad : {std::string("../events/escape"), std::string(64, 'A'),
                                std::string(63, 'b'), std::string(63, 'c') + '\0'}) {
            rejects<storage::Error>(storage::ErrorCode::InvalidPath, [&] { storage::validateControlPacketId(bad); });
        }
        rejects<storage::Error>(storage::ErrorCode::InvalidLimits, [&] { storage::controlPacketId({}); });
        rejects<storage::Error>(storage::ErrorCode::InvalidLimits, [&] {
            storage::controlPacketId(Bytes(storage::MaxControlPacketBytes + 1, 0x42));
        });
    });
#ifdef __linux__
    test("sender and recipient reopen and exchange exact immutable delivery and receipt files", [] {
        Devices f;
        f.admit(1);
        const auto wire = f.prepare(1);
        std::string deliveryAddress, receiptAddress;
        Bytes receipt;
        {
            storage::Directory directory(f.tree.root);
            deliveryAddress = f.journal(0).publishDelivery(f.member(1).id, directory, Now);
            CHECK(deliveryAddress == storage::controlPacketId(wire));
            CHECK(directory.readControl(deliveryAddress) == wire);
            receipt = f.journal(1).installDelivery(directory.readControl(deliveryAddress), *f.identities[1], Now);
            receiptAddress = f.journal(1).publishReceipt(*f.identities[1], directory, Now);
            CHECK(receiptAddress == storage::controlPacketId(receipt));
            CHECK(directory.readControl(receiptAddress) == receipt);
        }
        const auto deliveryFile = identity(f.tree.packet(deliveryAddress));
        const auto receiptFile = identity(f.tree.packet(receiptAddress));
        f.reopen(0);
        f.reopen(1);
        storage::Directory reopened(f.tree.root);
        CHECK(f.journal(0).publishDelivery(f.member(1).id, reopened, Now) == deliveryAddress);
        CHECK(f.journal(1).publishReceipt(*f.identities[1], reopened, Now) == receiptAddress);
        sameFile(deliveryFile, f.tree.packet(deliveryAddress));
        sameFile(receiptFile, f.tree.packet(receiptAddress));
        CHECK(f.journal(0).recordReceipt(reopened.readControl(receiptAddress), Now));
        f.reopen(0);
        CHECK(f.journal(0).inspect().confirmedDeliveries == std::vector<Token>{f.member(1).id});
        CHECK(!f.journal(0).recordReceipt(reopened.readControl(receiptAddress), Now));
        CHECK(f.journal(1).loadInstalledKey(*f.identities[1], Now)->sameKey(*f.key));
        CHECK(countFiles(f.tree.control) == 2);
        CHECK(fs::is_empty(f.tree.events));
    });
    test("missing outbox and missing installation publish nothing", [] {
        Devices f;
        f.admit(1);
        storage::Directory directory(f.tree.root);
        rejects<JournalError>(JournalCode::Delivery, [&] {
            f.journal(0).publishDelivery(f.member(1).id, directory, Now);
        });
        bool missing = false;
        try {
            f.journal(1).publishReceipt(*f.identities[1], directory, Now);
        } catch (const JournalError &error) {
            missing = error.code() == JournalCode::MissingKey || error.code() == JournalCode::Delivery;
        }
        CHECK(missing);
        CHECK(fs::is_empty(f.tree.control));
    });
    test("new head blocks stale staged delivery and stale receipt even with usable installed key", [] {
        Devices f;
        f.admit(1);
        const auto staged = f.prepare(1);
        f.journal(1).installDelivery(staged, *f.identities[1], Now);
        f.admit(2);
        f.reopen(0);
        f.reopen(1);
        storage::Directory directory(f.tree.root);
        CHECK(f.journal(1).loadInstalledKey(*f.identities[1], Now)->sameKey(*f.key));
        rejects<JournalError>(JournalCode::Delivery, [&] {
            f.journal(0).publishDelivery(f.member(1).id, directory, Now);
        });
        rejects<JournalError>(JournalCode::Delivery, [&] {
            f.journal(1).publishReceipt(*f.identities[1], directory, Now);
        });
        CHECK(fs::is_empty(f.tree.control));

        const auto catchUp = f.journal(0).prepareCatchUp(f.member(1).id, *f.identities[0], *f.key, Now);
        const auto packet = f.journal(0).publishDelivery(f.member(1).id, directory, Now);
        CHECK(directory.readControl(packet) == catchUp);
        f.journal(1).installDelivery(directory.readControl(packet), *f.identities[1], Now);
        const auto ack = f.journal(1).publishReceipt(*f.identities[1], directory, Now);
        CHECK(KeyReceiptCodec::inspect(directory.readControl(ack)).scope == KeyScope::CatchUp);
        CHECK(f.journal(0).recordReceipt(directory.readControl(ack), Now));
    });
    test("authenticated fork prevents publication of an already staged delivery and receipt", [] {
        Devices f;
        const auto sibling = f.add(2);
        f.admit(1);
        f.journal(1).installDelivery(f.prepare(1), *f.identities[1], Now);
        // Raw signing models a compromised peer bypassing its vote reservation.
        const Certificate competing{sibling, {{f.member(0).id, f.identities[0]->sign(
            approvalBytes(sibling, f.member(0)))}}};
        for (const auto i : {0U, 1U}) {
            CHECK(f.journal(i).observe(competing, Now) == ObserveResult::ForkDetected);
            f.reopen(i);
        }
        storage::Directory directory(f.tree.root);
        rejects<Error>(ErrorCode::Forked, [&] { f.journal(0).publishDelivery(f.member(1).id, directory, Now); });
        rejects<Error>(ErrorCode::Forked, [&] { f.journal(1).publishReceipt(*f.identities[1], directory, Now); });
        CHECK(fs::is_empty(f.tree.control));
    });
    test("before and after journal commit errors expose neither delivery nor receipt", [] {
        Devices f;
        const auto admitted = f.admit(1);
        storage::Directory directory(f.tree.root);
        FaultStore sender(TrustJournal::initialRecord(f.genesis, f.member(0), Now));
        FaultStore recipient(TrustJournal::initialRecord(f.genesis, f.member(1), Now));
        Bytes staged;
        {
            TrustJournal journal(sender, f.genesis, f.member(0));
            CHECK(journal.observe(admitted, Now) == ObserveResult::Applied);
            staged = journal.prepareDelivery(f.member(1).id, *f.identities[0], *f.key, Now);
        }
        const auto deliveryAddress = storage::controlPacketId(staged);
        sender.beforeCommit = [&] { CHECK(!fs::exists(f.tree.packet(deliveryAddress))); };
        for (const auto failure : {FaultStore::Failure::Before, FaultStore::Failure::After}) {
            TrustJournal journal(sender, f.genesis, f.member(0));
            sender.failure = failure;
            const auto code = failure == FaultStore::Failure::Before ? st::ErrorCode::Io : st::ErrorCode::CommitUnconfirmed;
            rejects<st::Error>(code, [&] { journal.publishDelivery(f.member(1).id, directory, Now); });
            rejects<JournalError>(JournalCode::Uncertain, [&] { journal.inspect(); });
            CHECK(fs::is_empty(f.tree.control));
        }
        TrustJournal reopenedSender(sender, f.genesis, f.member(0));
        sender.beforeUnlock = [&] { CHECK(read(f.tree.packet(deliveryAddress)) == staged); };
        CHECK(reopenedSender.publishDelivery(f.member(1).id, directory, Now) == deliveryAddress);
        sender.beforeUnlock = {};
        sender.beforeCommit = {};
        Bytes receipt;
        {
            TrustJournal journal(recipient, f.genesis, f.member(1));
            CHECK(journal.observe(admitted, Now) == ObserveResult::Applied);
            receipt = journal.installDelivery(directory.readControl(deliveryAddress), *f.identities[1], Now);
        }
        const auto receiptAddress = storage::controlPacketId(receipt);
        recipient.beforeCommit = [&] { CHECK(!fs::exists(f.tree.packet(receiptAddress))); };
        for (const auto failure : {FaultStore::Failure::Before, FaultStore::Failure::After}) {
            TrustJournal journal(recipient, f.genesis, f.member(1));
            recipient.failure = failure;
            const auto code = failure == FaultStore::Failure::Before ? st::ErrorCode::Io : st::ErrorCode::CommitUnconfirmed;
            rejects<st::Error>(code, [&] { journal.publishReceipt(*f.identities[1], directory, Now); });
            rejects<JournalError>(JournalCode::Uncertain, [&] { journal.inspect(); });
            CHECK(countFiles(f.tree.control) == 1);
        }
        TrustJournal reopenedRecipient(recipient, f.genesis, f.member(1));
        recipient.beforeUnlock = [&] { CHECK(read(f.tree.packet(receiptAddress)) == receipt); };
        CHECK(reopenedRecipient.publishReceipt(*f.identities[1], directory, Now) == receiptAddress);
        recipient.beforeUnlock = {};
        recipient.beforeCommit = {};
        CHECK(reopenedSender.recordReceipt(directory.readControl(receiptAddress), Now));
    });
    test("transport collision leaves journal usable and exact staged ciphertext retryable", [] {
        Devices f;
        f.admit(1);
        const auto staged = f.prepare(1);
        const auto address = storage::controlPacketId(staged);
        const auto path = f.tree.packet(address);
        auto substituted = staged;
        substituted.back() ^= 1;
        write(path, substituted);
        storage::Directory directory(f.tree.root);
        refusesPacket([&] { f.journal(0).publishDelivery(f.member(1).id, directory, Now); });
        CHECK(read(path) == substituted);
        CHECK(f.journal(0).inspect().state.members.size() == 2);
        CHECK(fs::remove(path));
        f.reopen(0);
        CHECK(f.journal(0).publishDelivery(f.member(1).id, directory, Now) == address);
        CHECK(directory.readControl(address) == staged);
    });
    test("substituted bytes fail the address check and a collision never replaces the file", [] {
        TransportTree t;
        const Bytes expected{'p', 'a', 'c', 'k', 'e', 't'};
        const Bytes other{'p', 'a', 'c', 'k', 'e', 'u'};
        const auto address = storage::controlPacketId(expected);
        storage::Directory directory(t.root);
        write(t.packet(address), other);
        const auto before = identity(t.packet(address));
        refusesPacket([&] { directory.readControl(address); });
        refusesPacket([&] { directory.publishControl(expected); });
        sameFile(before, t.packet(address));
        CHECK(read(t.packet(address)) == other);
        CHECK(countFiles(t.control) == 1);
        CHECK(fs::is_empty(t.events));
    });
    test("a packet with a valid address still needs its envelope signature", [] {
        Devices f;
        f.admit(1);
        const auto staged = f.prepare(1);
        auto forged = staged;
        forged.back() ^= 1;
        storage::Directory directory(f.tree.root);
        directory.publishControl(forged);
        const auto addressed = directory.readControl(storage::controlPacketId(forged));
        CHECK(addressed == forged);
        rejects<EnvelopeError>(EnvelopeCode::BadSignature, [&] {
            f.journal(1).installDelivery(addressed, *f.identities[1], Now);
        });
        CHECK(!f.journal(1).inspect().installedKey);
        const auto delivery = f.journal(0).publishDelivery(f.member(1).id, directory, Now);
        CHECK(directory.readControl(delivery) == staged);
        CHECK(countFiles(f.tree.control) == 2);
    });
    test("missing control directory and invalid addresses never create or traverse paths", [] {
        TransportTree t(false);
        storage::Directory directory(t.root);
        const Bytes packet{'a'};
        const auto address = storage::controlPacketId(packet);
        refusesPacket([&] { directory.readControl(address); });
        refusesPacket([&] { directory.publishControl(packet); });
        CHECK(!fs::exists(t.control));
        CHECK(fs::is_empty(t.events));
        TransportTree::create(t.control);
        storage::Directory withControl(t.root);
        rejects<storage::Error>(storage::ErrorCode::InvalidPath, [&] { withControl.readControl("../events/escape"); });
        refusesPacket([&] { withControl.readControl(address); });
        CHECK(fs::is_empty(t.control));
    });
    test("symlink control directory, symlink packet and hardlinked packet are refused", [] {
        const Bytes packet{'p'};
        const auto address = storage::controlPacketId(packet);
        {
            TransportTree t(false);
            const auto outside = t.base / "outside";
            TransportTree::create(outside);
            fs::create_directory_symlink(outside, t.control);
            refusesPacket([&] { storage::Directory directory(t.root); directory.readControl(address); });
            refusesPacket([&] { storage::Directory directory(t.root); directory.publishControl(packet); });
            CHECK(fs::is_empty(outside));
        }
        for (const auto hardLink : {false, true}) {
            TransportTree t;
            const auto outside = t.base / "outside";
            write(outside, packet);
            if (hardLink) fs::create_hard_link(outside, t.packet(address));
            else fs::create_symlink(outside, t.packet(address));
            storage::Directory directory(t.root);
            refusesPacket([&] { directory.readControl(address); });
            refusesPacket([&] { directory.publishControl(packet); });
            CHECK(read(outside) == packet);
            CHECK(countFiles(t.control) == 1);
        }
    });
    test("bounded reads reject oversized files and Linux never uses explicit staging", [] {
        TransportTree t;
        storage::Directory directory(t.root);
        const Bytes limit(storage::MaxControlPacketBytes, 0x35);
        const auto address = storage::controlPacketId(limit);
        const auto staging = t.base / "staging";
        TransportTree::create(staging);
        rejects<storage::Error>(storage::ErrorCode::InvalidPath, [&] { directory.publishControl(limit, staging); });
        CHECK(fs::is_empty(t.control) && fs::is_empty(staging));
        directory.publishControl(limit);
        CHECK(directory.readControl(address) == limit);
        const Bytes oversized(storage::MaxControlPacketBytes + 1, 0x35);
        write(t.packet(address), oversized);
        refusesPacket([&] { directory.readControl(address); });
        refusesPacket([&] { directory.publishControl(limit); });
        CHECK(read(t.packet(address)) == oversized);
        CHECK(countFiles(t.control) == 1);
    });
#endif
    std::cout << cases << " device control transport test cases passed\n";
}
