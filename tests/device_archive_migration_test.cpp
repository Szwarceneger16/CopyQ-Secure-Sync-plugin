// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_archive_migration.h"
#include "device_identity.h"
#include "device_trust_journal.h"
#include "packed_items.h"
#include "storage.h"
#include "test_check.h"

#ifdef __linux__
#include <sodium.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <utility>

namespace {
using namespace cqs::trust;
using cqs::crypto::Bytes;
namespace ev = cqs::events;
namespace fs = std::filesystem;
namespace hist = cqs::history;
namespace st = cqs::state;
namespace storage = cqs::storage;
namespace tx = cqs::transaction;

constexpr std::uint64_t Now = 100;
const std::string Binding = "legacy-test-binding";
const std::string FirstId = "old-device/000000000001";
const std::string TipId = "old-device/000000000002";
int passed = 0;

void test(const char *label, const std::function<void()> &body)
{
    body();
    ++passed;
    std::cout << "PASS " << label << '\n';
}

template<class Failure, class Code, class Fn>
void rejects(Code expected, Fn &&action)
{
    bool caught = false;
    try {
        action();
    } catch (const Failure &error) {
        if (error.code() != expected) std::cerr << "Unexpected failure: " << error.what() << '\n';
        CHECK(error.code() == expected);
        caught = true;
    }
    CHECK(caught);
}

template<class Fn>
void refusesMigration(Fn &&action)
{
    rejects<JournalError>(JournalCode::Migration, std::forward<Fn>(action));
}

std::string read(const fs::path &path)
{
    std::ifstream stream(path, std::ios::binary);
    CHECK(stream.good());
    return {std::istreambuf_iterator<char>(stream), {}};
}

void write(const fs::path &path, const std::string &wire)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    CHECK(stream.good());
    stream.write(wire.data(), static_cast<std::streamsize>(wire.size()));
    stream.close();
    CHECK(stream.good());
}

class Temp final {
public:
    Temp()
    {
        char name[] = "/tmp/cqs-archive-migration-XXXXXX";
        const char *created = ::mkdtemp(name);
        CHECK(created);
        path = created;
    }
    ~Temp()
    {
        std::error_code ignored;
        fs::remove_all(path, ignored);
    }
    fs::path path;
};

class MemoryStore final : public tx::Store {
public:
    enum class Fault { BeforeWrite, AfterWrite };

    explicit MemoryStore(tx::Record initial = {}) : record(std::move(initial)) {}

    std::unique_ptr<Lease> lock() override
    {
        if (leased) return {};
        auto lease = std::make_unique<Held>(leased);
        leased = true;
        return lease;
    }

    tx::Record load() override
    {
        CHECK(leased);
        return record;
    }

    void commit(const tx::Record &expected, const tx::Record &replacement) override
    {
        CHECK(leased);
        CHECK(st::serialize(expected) == st::serialize(record));
        CHECK(replacement.generation == record.generation + 1);
        ++attempts;
        if (onCommit) onCommit();
        if (failure == std::make_pair(attempts, Fault::BeforeWrite))
            throw st::Error(st::ErrorCode::Io, "Synthetic failure before state write");
        record = replacement;
        if (failure == std::make_pair(attempts, Fault::AfterWrite))
            throw st::Error(st::ErrorCode::CommitUnconfirmed, "Synthetic lost state acknowledgement");
    }

    tx::Record record;
    std::optional<std::pair<std::size_t, Fault>> failure;
    std::function<void()> onCommit;
    std::size_t attempts = 0;
    bool leased = false;

private:
    struct Held final : Lease {
        explicit Held(bool &state) : leased(state) {}
        ~Held() override { leased = false; }
        bool &leased;
    };
};

std::string b64(const Bytes &bytes)
{
    std::string result(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    CHECK(sodium_bin2base64(result.data(), result.size(), bytes.data(), bytes.size(),
                           sodium_base64_VARIANT_ORIGINAL) == result.data());
    result.pop_back();
    return result;
}

std::string packed(const Bytes &data)
{
    CHECK(data.size() < 256);
    // One CopyQ 17 QDataStream entry, using MIME prefix 4 for text/plain.
    Bytes wire{255, 255, 255, 254, 0, 0, 0, 1, 0, 0, 0, 2, 0, '4',
               0, 0, 0, 0, static_cast<std::uint8_t>(data.size())};
    wire.insert(wire.end(), data.begin(), data.end());
    return b64(wire);
}

std::string legacyWire(const Bytes &key, unsigned sequence, const std::vector<std::string> &items)
{
    const auto parents = sequence == 1 ? "[]" : "[\"" + FirstId + "\"]";
    const std::string header = "{\"device\":\"old-device\",\"parents\":" + parents +
        ",\"protocol\":\"copyq-secure-sync-v1\",\"seq\":" + std::to_string(sequence) + "}";
    std::string payload = "{\"items\":[";
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i) payload += ',';
        payload += '"' + items[i] + '"';
    }
    payload += "],\"tab\":\"synced_tray\",\"v\":1}";
    constexpr char aadDomain[] = "CopyQ-Secure-Sync-event-v1";
    Bytes aad(aadDomain, aadDomain + sizeof(aadDomain));
    aad.insert(aad.end(), header.begin(), header.end());
    const auto nonce = cqs::crypto::random(12);
    const auto plaintext = cqs::crypto::zlibCompress(Bytes(payload.begin(), payload.end()));
    const auto ciphertext = cqs::crypto::aes256GcmEncrypt(key, nonce, plaintext, aad);
    return "{\"ciphertext\":\"" + b64(ciphertext) + "\",\"header\":" + header +
           ",\"nonce\":\"" + b64(nonce) + "\"}";
}

Token token(std::uint8_t suffix)
{
    Token result{};
    result.back() = suffix;
    return result;
}

struct Fixture {
    Temp temp;
    fs::path legacyRoot = temp.path / "legacy";
    fs::path successorRoot = temp.path / "successor";
    fs::path legacyDevice = legacyRoot / "events" / "old-device";
    fs::path firstPath = legacyDevice / "000000000001.cqs";
    fs::path tipPath = legacyDevice / "000000000002.cqs";
    Bytes oldKey = Bytes(32, 0x47);
    const std::vector<std::string> tipItems{packed({0, 255, 13, 10}), packed({'s', 'y', 'n', 't', 'h'})};
    const std::string firstWire = legacyWire(oldKey, 1, {packed({'a'})});
    const std::string tipWire = legacyWire(oldKey, 2, tipItems);
    std::unique_ptr<Identity> founder = Identity::generate();
    std::unique_ptr<SyncKey> newKey;
    Genesis genesis;
    MemoryStore sourceStore, targetStore;
    std::unique_ptr<TrustJournal> journal;
    std::unique_ptr<storage::Directory> legacy, successor;

    explicit Fixture(bool reuseKey = false) : newKey(reuseKey ? SyncKey::import(oldKey) : SyncKey::generate()),
        genesis{token(1), founder->member(), token(2), newKey->commitment(token(1), 0)},
        targetStore(TrustJournal::initialRecord(genesis, founder->member(), Now))
    {
        fs::create_directories(legacyDevice);
        fs::create_directories(successorRoot / "events");
        write(firstPath, firstWire);
        write(tipPath, tipWire);
        legacy = std::make_unique<storage::Directory>(legacyRoot);
        successor = std::make_unique<storage::Directory>(successorRoot);
        reopen();
        fs::create_directory(successorRoot / storage::signedEventFolderName(scope()));

        const auto history = legacy->scan(oldKey);
        auto &record = sourceStore.record;
        record.schema = 6;
        record.binding = Binding;
        record.generation = 17;
        const auto found = std::find_if(history.events().begin(), history.events().end(), [](const auto &event) {
            return event.revision.id == TipId;
        });
        CHECK(found != history.events().end());
        record.head = tx::Head{*found, cqs::packed::decode(found->items)};
        record.local = record.head->snapshot;
        record.keyIdentity = legacyArchiveKeyIdentity(oldKey);
        record.witnessed = history.fingerprints();
    }

    void reopen()
    {
        journal = std::make_unique<TrustJournal>(targetStore, genesis, founder->member());
    }

    storage::SignedEventScope scope() const
    {
        const auto state = journal->inspect().state;
        return {state.group, state.root, state.keyGeneration};
    }

    LegacyArchiveSource source()
    {
        return {sourceStore, *legacy, oldKey, Binding};
    }

    std::string id(std::uint64_t sequence) const
    {
        return hist::makeId(SignedEventCodec::deviceName(founder->member().id), sequence);
    }

    std::vector<storage::SignedEventPacket> packets() const
    {
        return successor->scanSignedEvents(scope());
    }

    Token preview()
    {
        return journal->previewLegacyMigration(source(), *newKey, Now);
    }

    std::string migrate(const Token &confirmation)
    {
        return journal->migrateLegacyArchive(source(), confirmation, *founder, *newKey, *successor, Now);
    }

    void oldFilesIntact() const
    {
        CHECK(read(firstPath) == firstWire && read(tipPath) == tipWire);
        CHECK(sourceStore.attempts == 0 && !sourceStore.leased);
    }
};

bool containsPacket(const tx::Record &record, const std::string &packet)
{
    const auto &journal = record.local->front().begin()->second;
    const Bytes bytes(packet.begin(), packet.end());
    return std::search(journal.begin(), journal.end(), bytes.begin(), bytes.end()) != journal.end();
}
} // namespace
#endif

int main()
{
#ifdef __linux__
    CHECK(sodium_init() >= 0);
    test("migration preserves exact v1 archive and encrypted state, then supports v2 append", [] {
        Fixture f;
        const auto privateDir = f.temp.path / "legacy-private";
        fs::create_directory(privateDir);
        fs::permissions(privateDir, fs::perms::owner_all);
        st::FileStore disk(privateDir, Binding, Bytes(32, 0x56));
        {
            const auto lease = disk.lock();
            CHECK(lease);
            disk.initialize(f.sourceStore.record);
        }
        const auto privateFile = privateDir / st::FileStore::RecordName;
        const auto saved = read(privateFile);
        const LegacyArchiveSource diskSource{disk, *f.legacy, f.oldKey, Binding};
        const auto confirmation = f.journal->previewLegacyMigration(diskSource, *f.newKey, Now);
        CHECK(confirmation == f.preview());
        CHECK(f.packets().empty() && !f.journal->inspect().migration);
        const auto newRoot = f.journal->migrateLegacyArchive(diskSource, confirmation, *f.founder,
                                                           *f.newKey, *f.successor, Now);
        CHECK(newRoot == f.id(1));
        CHECK(read(privateFile) == saved);
        f.oldFilesIntact();
        const auto status = f.journal->inspect();
        CHECK(status.migration && status.migration->completed && status.migration->sequence == 1);
        CHECK(!status.pendingEvent && status.eventWitnesses == 1 && status.eventEncryptionAttempts == 1);
        const auto accepted = f.journal->scanClipboardEvents(*f.newKey, *f.successor, Now);
        CHECK(accepted.graph.tips() == std::vector<std::string>{newRoot});
        CHECK(accepted.events.size() == 1 && accepted.events.front().items == f.tipItems);
        CHECK(accepted.events.front().revision.parents.empty());
        CHECK(f.successor->scan(f.oldKey).graph().size() == 0);
        const auto child = f.journal->prepareClipboardEvent(*f.founder, *f.newKey,
            {{newRoot, accepted.wireDigests.at(newRoot)}}, f.tipItems, Now);
        const auto appended = f.journal->publishClipboardEvent(child.sequence, *f.newKey, *f.successor, Now);
        f.reopen();
        CHECK(f.journal->scanClipboardEvents(*f.newKey, *f.successor, Now).graph.isAncestor(newRoot, appended));
        CHECK(f.migrate(confirmation) == newRoot);
        CHECK(read(privateFile) == saved && f.packets().size() == 2);
    });
    test("confirmation binds the complete source state and destination before any write", [] {
        Fixture f;
        const auto confirmed = f.preview();
        auto wrong = confirmed;
        wrong.back() ^= 1;
        rejects<JournalError>(JournalCode::Confirmation, [&] { f.migrate(wrong); });
        ++f.sourceStore.record.generation;
        CHECK(f.preview() != confirmed);
        rejects<JournalError>(JournalCode::Confirmation, [&] { f.migrate(confirmed); });
        Fixture other;
        rejects<JournalError>(JournalCode::Confirmation, [&] { other.migrate(f.preview()); });
        CHECK(f.targetStore.attempts == 0 && other.targetStore.attempts == 0 && f.packets().empty());
        f.oldFilesIntact();
    });
    test("a valid legacy key cannot be reused as the new group key", [] {
        Fixture f(true);
        refusesMigration([&] { f.preview(); });
        refusesMigration([&] { f.migrate(token(9)); });
        CHECK(f.targetStore.attempts == 0 && f.packets().empty());
        f.oldFilesIntact();
    });
    test("migration refuses local changes, unverified MIME data, and unwitnessed ancestors", [] {
        Fixture f;
        const auto original = f.sourceStore.record;
        f.sourceStore.record.local = tx::Snapshot{};
        refusesMigration([&] { f.preview(); });
        f.sourceStore.record = original;
        f.sourceStore.record.local = tx::Snapshot{};
        f.sourceStore.record.head->snapshot = {};
        refusesMigration([&] { f.preview(); });
        f.sourceStore.record = original;
        f.sourceStore.record.witnessed.erase(FirstId);
        refusesMigration([&] { f.preview(); });
        f.sourceStore.record = original;
        f.sourceStore.record.schema = 5;
        f.sourceStore.record.witnessed.clear();
        refusesMigration([&] { f.preview(); });
        CHECK(f.targetStore.attempts == 0 && f.packets().empty());
        f.oldFilesIntact();
    });
    test("a witnessed v1 envelope must still contain valid CopyQ MIME data", [] {
        Fixture f;
        const auto malformed = legacyWire(f.oldKey, 2, {"YQ=="});
        write(f.tipPath, malformed);
        auto &record = f.sourceStore.record;
        record.head->event = ev::decode(f.oldKey, {TipId, malformed});
        record.witnessed.at(TipId) = tx::eventFingerprint(record.head->event);
        bool caught = false;
        try {
            f.preview();
        } catch (const cqs::packed::Error &) {
            caught = true;
        }
        CHECK(caught);
        CHECK(f.targetStore.attempts == 0 && f.packets().empty());
        write(f.tipPath, f.tipWire);
        f.oldFilesIntact();
    });
    test("an oversized signed successor is refused before any migration state is reserved", [] {
        Fixture f;
        const std::vector<std::string> items(6000, packed(Bytes(250, 0x26)));
        const auto oversized = legacyWire(f.oldKey, 2, items);
        write(f.tipPath, oversized);
        auto &record = f.sourceStore.record;
        record.head = tx::Head{ev::decode(f.oldKey, {TipId, oversized}), cqs::packed::decode(items)};
        record.local = record.head->snapshot;
        record.witnessed.at(TipId) = tx::eventFingerprint(record.head->event);
        rejects<ev::Error>(ev::ErrorCode::SizeLimit, [&] { f.migrate(f.preview()); });
        CHECK(f.targetStore.attempts == 0 && f.packets().empty());
        write(f.tipPath, f.tipWire);
        f.oldFilesIntact();
    });
    test("the source scan rejects removed and re-encrypted legacy witnesses", [] {
        Fixture f;
        CHECK(fs::remove(f.tipPath));
        rejects<tx::Error>(tx::ErrorCode::MissingHead, [&] { f.preview(); });
        write(f.tipPath, f.tipWire);
        write(f.firstPath, legacyWire(f.oldKey, 1, {packed({'b'})}));
        rejects<tx::Error>(tx::ErrorCode::Equivocation, [&] { f.preview(); });
        CHECK(f.targetStore.attempts == 0 && f.packets().empty());
        write(f.firstPath, f.firstWire);
        f.oldFilesIntact();
    });
    test("existing signed packets block migration before the first reservation", [] {
        Fixture f;
        const auto confirmed = f.preview();
        const auto state = f.journal->inspect().state;
        const SignedEventContext context{state.group, state.root, state.digest, state.keyCommitment,
                                         f.founder->member().id, state.keyGeneration};
        const auto wire = SignedEventCodec::seal(context, *f.founder, *f.newKey, 9, {}, f.tipItems);
        const std::string_view bytes(reinterpret_cast<const char *>(wire.data()), wire.size());
        f.successor->publishSignedEvent(f.scope(), {f.id(9), bytes});
        refusesMigration([&] { f.migrate(confirmed); });
        CHECK(f.targetStore.attempts == 0 && f.packets().size() == 1);
        f.oldFilesIntact();
    });
    test("a signed Add approval makes the destination ineligible even before observation", [] {
        Fixture f;
        const auto confirmed = f.preview();
        const auto peer = Identity::generate();
        const auto proposal = f.journal->propose(Operation::Add, peer->member(), token(3), token(4), Now, Now + 30);
        const auto vote = f.journal->approve(proposal, *f.founder,
                                             verificationDigest(proposal, f.founder->member()), Now);
        CHECK(vote.signer == f.founder->member().id);
        f.reopen();
        CHECK(f.journal->inspect().state.epoch == 0 && f.journal->inspect().reservations == 1);
        const auto attempts = f.targetStore.attempts;
        refusesMigration([&] { f.preview(); });
        refusesMigration([&] { f.migrate(confirmed); });
        CHECK(f.targetStore.attempts == attempts && f.packets().empty());
        f.oldFilesIntact();
    });
    test("before and after each migration commit exact retries preserve source and never duplicate the root", [] {
        for (std::size_t barrier = 1; barrier <= 4; ++barrier) {
            for (const auto fault : {MemoryStore::Fault::BeforeWrite, MemoryStore::Fault::AfterWrite}) {
                Fixture f;
                const auto confirmed = f.preview();
                const auto source = st::serialize(f.sourceStore.record);
                f.targetStore.onCommit = [&] { CHECK(f.sourceStore.leased); };
                f.targetStore.failure = std::make_pair(barrier, fault);
                const bool after = fault == MemoryStore::Fault::AfterWrite;
                rejects<st::Error>(after ? st::ErrorCode::CommitUnconfirmed : st::ErrorCode::Io,
                                   [&] { f.migrate(confirmed); });
                rejects<JournalError>(JournalCode::Uncertain, [&] { f.journal->inspect(); });
                f.reopen();
                const auto beforeRetry = f.journal->inspect();
                const auto delivered = f.packets();
                const bool firstRecorded = after || barrier > 1;
                const bool burned = (barrier == 1 && after) || (barrier == 2 && !after);
                CHECK(bool(beforeRetry.migration) == firstRecorded);
                CHECK(delivered.size() == (barrier == 4 ? 1 : 0));
                if (barrier == 4) {
                    CHECK(delivered.front().id == f.id(1));
                    if (!after) CHECK(containsPacket(f.targetStore.record, delivered.front().wire));
                }
                const auto retained = f.targetStore.record;
                const auto root = f.migrate(confirmed);
                CHECK(root == f.id(burned ? 2 : 1));
                const auto completed = f.journal->inspect();
                CHECK(completed.migration && completed.migration->completed && !completed.pendingEvent);
                CHECK(completed.eventEncryptionAttempts == (burned ? 2 : 1));
                const auto finalPackets = f.packets();
                CHECK(finalPackets.size() == 1 && finalPackets.front().id == root);
                if (barrier == 4) CHECK(finalPackets.front().wire == delivered.front().wire);
                if ((barrier == 2 && after) || barrier == 3)
                    CHECK(containsPacket(retained, finalPackets.front().wire));
                CHECK(st::serialize(f.sourceStore.record) == source);
                f.oldFilesIntact();
            }
        }
    });
    test("interrupted migration requires the same archive and rejects generic Seed or discard", [] {
        Fixture f;
        const auto confirmed = f.preview();
        f.targetStore.failure = std::make_pair(2, MemoryStore::Fault::AfterWrite);
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.migrate(confirmed); });
        f.reopen();
        const auto staged = f.journal->inspect();
        CHECK(staged.migration && !staged.migration->completed);
        CHECK(staged.pendingEvent && staged.pendingEvent->ready);
        refusesMigration([&] {
            f.journal->publishClipboardEvent(staged.migration->sequence, *f.newKey, *f.successor, Now,
                                            ClipboardPublication::Seed);
        });
        refusesMigration([&] { f.journal->resumeClipboardEvent(staged.migration->sequence, Now); });
        refusesMigration([&] { f.journal->discardClipboardEvent(staged.migration->sequence, Now); });
        const auto originalGeneration = f.sourceStore.record.generation;
        ++f.sourceStore.record.generation;
        refusesMigration([&] { f.migrate(confirmed); });
        CHECK(f.packets().empty() && f.journal->inspect().pendingEvent->ready);
        f.sourceStore.record.generation = originalGeneration;
        CHECK(f.migrate(confirmed) == f.id(1));
        f.oldFilesIntact();
    });
    test("an incomplete migration withholds local approvals and key release and refuses retry after Add", [] {
        Fixture f;
        const auto confirmed = f.preview();
        const auto peer = Identity::generate();
        const auto proposal = f.journal->propose(Operation::Add, peer->member(), token(3), token(4), Now, Now + 30);
        f.targetStore.failure = std::make_pair(2, MemoryStore::Fault::AfterWrite);
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.migrate(confirmed); });
        f.reopen();
        const auto beforeApproval = f.targetStore.attempts;
        refusesMigration([&] {
            f.journal->approve(proposal, *f.founder, verificationDigest(proposal, f.founder->member()), Now);
        });
        CHECK(f.targetStore.attempts == beforeApproval);
        // Simulate a valid certificate arriving from outside the coordinator.
        const Approval external{f.founder->member().id,
                                f.founder->sign(approvalBytes(proposal, f.founder->member()))};
        CHECK(f.journal->observe({proposal, {external}}, Now) == ObserveResult::Applied);
        f.reopen();
        CHECK(f.journal->inspect().state.epoch == 1);
        const auto beforeRelease = f.targetStore.attempts;
        refusesMigration([&] { f.journal->prepareDelivery(peer->member().id, *f.founder, *f.newKey, Now); });
        refusesMigration([&] { f.migrate(confirmed); });
        CHECK(f.targetStore.attempts == beforeRelease && f.packets().empty());
        CHECK(f.journal->inspect().pendingEvent->ready);
        f.oldFilesIntact();
    });
    test("the journal refuses malformed migration metadata after reopening", [] {
        Fixture f;
        CHECK(f.migrate(f.preview()) == f.id(1));
        const auto good = f.targetStore.record;
        constexpr auto markerSize = Token{}.size() + 8 + 1;
        for (std::size_t mutation = 0; mutation < 4; ++mutation) {
            auto invalid = good;
            auto &log = invalid.local->front().begin()->second;
            const auto start = log.size() - markerSize;
            switch (mutation) {
            case 0: std::fill_n(log.begin() + static_cast<std::ptrdiff_t>(start), Token{}.size(), 0); break;
            case 1: log[log.size() - 2] = 2; break;
            case 2: log.back() = 2; break;
            case 3: log.pop_back(); break;
            }
            f.targetStore.record = std::move(invalid);
            rejects<JournalError>(JournalCode::Invalid, [&] { f.reopen(); });
        }
        f.targetStore.record = good;
        f.reopen();
        CHECK(f.journal->inspect().migration->completed && f.packets().size() == 1);
        f.oldFilesIntact();
    });
    std::cout << passed << " archive migration scenarios passed\n";
#else
    std::cout << "Archive migration fixture requires Linux filesystem integration\n";
#endif
}
