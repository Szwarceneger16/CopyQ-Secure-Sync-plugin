// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_join.h"
#include "device_join_wizard.h"
#include "device_key_receipt.h"
#include "device_trust_journal.h"
#include "packed_items.h"
#include "signed_join_checkpoint.h"
#include "storage.h"
#include "test_check.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string_view>
#include <utility>
#ifdef __linux__
#include <unistd.h>
#endif
#ifdef CQS_TEST_NATIVE_SIGNED_JOIN
#include "signed_join_wizard.h"
#include <QAbstractButton>
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QTimer>
#endif

using namespace cqs::trust;
using cqs::crypto::Bytes;
namespace st = cqs::state;
namespace tx = cqs::transaction;
namespace storage = cqs::storage;

namespace {
constexpr std::uint64_t Now = 100;
constexpr std::uint64_t Expires = 200;
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
        CHECK(error.code() == expected);
        rejected = true;
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
    } catch (const st::Error &) {
        rejected = true;
    } catch (const storage::Error &) {
        rejected = true;
    } catch (const cqs::events::Error &) {
        rejected = true;
    } catch (const cqs::packed::Error &) {
        rejected = true;
    }
    CHECK(rejected);
}

Token token(unsigned value)
{
    Token result{};
    result.back() = static_cast<std::uint8_t>(value);
    return result;
}

std::string hex(const Token &digest, bool grouped = false, bool uppercase = false)
{
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < digest.size(); ++i) {
        if (grouped && i && i % 4 == 0) result.push_back('-');
        result.push_back(digits[digest[i] >> 4]);
        result.push_back(digits[digest[i] & 0xf]);
    }
    return result;
}

class MemoryStore final : public tx::Store {
public:
    enum class Fault { None, Before, After };
    explicit MemoryStore(tx::Record initial) : record(std::move(initial)) {}

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
        auto fault = Fault::None;
        if (deferredCommits)
            --deferredCommits;
        else
            fault = std::exchange(failure, Fault::None);
        if (fault == Fault::Before) throw st::Error(st::ErrorCode::Io, "Injected before commit");
        record = replacement;
        if (onCommit) onCommit();
        if (fault == Fault::After) throw st::Error(st::ErrorCode::CommitUnconfirmed, "Injected after commit");
    }

    tx::Record record;
    Fault failure = Fault::None;
    unsigned deferredCommits = 0;
    std::function<void()> onCommit;

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
    std::array<std::unique_ptr<Identity>, 4> identities;
    Genesis genesis;
    std::array<std::unique_ptr<MemoryStore>, 4> stores;
    std::array<std::unique_ptr<TrustJournal>, 4> journals;

    Fixture()
    {
        for (auto &identity : identities) identity = Identity::generate();
        genesis = {token(1), member(0), token(2), key->commitment(token(1), 0)};
        for (std::size_t i = 0; i < journals.size(); ++i) {
            stores[i] = std::make_unique<MemoryStore>(TrustJournal::initialRecord(genesis, member(i), Now));
            reopen(i);
        }
    }

    const Member &member(std::size_t i) const { return identities[i]->member(); }
    TrustJournal &journal(std::size_t i) const { return *journals[i]; }
    MemoryStore &store(std::size_t i) const { return *stores[i]; }

    void reopen(std::size_t i)
    {
        journals[i] = std::make_unique<TrustJournal>(store(i), genesis, member(i));
    }

    JoinRequest request(std::size_t applicant)
    {
        return journal(applicant).beginJoin(*identities[applicant], Now);
    }

    Proposal proposal(const JoinRequest &request)
    {
        return journal(0).proposeJoin(request, Now, Expires);
    }

    Certificate certificate(const Proposal &proposal, std::initializer_list<std::size_t> signers)
    {
        Certificate result{proposal, {}};
        for (const auto signer : signers) {
            const auto review = journal(signer).reviewJoinApproval(proposal, Now);
            CHECK(review.approvers.size() == 1);
            CHECK(review.approvers.front().member == member(signer));
            result.approvals.push_back(journal(signer).approve(proposal, *identities[signer],
                                                              review.approvers.front().digest, Now));
        }
        return result;
    }

    Certificate enrollFirst()
    {
        const auto requested = proposal(request(1));
        const auto certificate = this->certificate(requested, {0});
        CHECK(journal(1).acceptJoin(certificate, confirmations(journal(1).reviewJoin(requested, {member(0).id}, Now)),
                                    Now) == ObserveResult::Applied);
        CHECK(journal(0).observe(certificate, Now) == ObserveResult::Applied);
        return certificate;
    }

    static std::vector<JoinConfirmation> confirmations(const JoinReview &review)
    {
        std::vector<JoinConfirmation> result;
        for (const auto &peer : review.approvers) result.push_back({peer.member.id, peer.digest});
        return result;
    }
};

#ifdef __linux__
class Transport final {
public:
    explicit Transport(const State &state)
    {
        char path[] = "/tmp/cqs-device-join-XXXXXX";
        const char *directory = ::mkdtemp(path);
        CHECK(directory);
        root = std::filesystem::path(directory) / "transport";
        std::filesystem::create_directories(root / "events");
        scope = {state.group, state.root, state.keyGeneration};
        signedFolder = root / storage::signedEventFolderName(scope);
        std::filesystem::create_directory(signedFolder);
        directory_ = std::make_unique<storage::Directory>(root);
    }

    ~Transport()
    {
        directory_.reset();
        std::error_code ignored;
        std::filesystem::remove_all(root.parent_path(), ignored);
    }

    const storage::Directory &directory() const { return *directory_; }

    std::filesystem::path root, signedFolder;
    storage::SignedEventScope scope;

private:
    std::unique_ptr<storage::Directory> directory_;
};

// One CopyQ 17 QDataStream text/plain MIME item with value "abc".
const std::vector<std::string> ValidItems{"/////gAAAAEAAAACADQAAAAAA2FiYw=="};
const std::string Binding = "detached-copyq-profile";

std::string seed(Fixture &f, const Transport &transport, const std::vector<std::string> &items = ValidItems)
{
    const auto prepared = f.journal(0).prepareClipboardEvent(*f.identities[0], *f.key, {}, items, Now);
    return f.journal(0).publishClipboardEvent(prepared.sequence, *f.key, transport.directory(), Now,
                                              ClipboardPublication::Seed);
}

Bytes install(Fixture &f, std::size_t recipient = 1)
{
    const auto package = f.journal(0).prepareDelivery(f.member(recipient).id, *f.identities[0], *f.key, Now);
    const auto receipt = f.journal(recipient).installDelivery(package, *f.identities[recipient], Now);
    CHECK(f.journal(0).recordReceipt(receipt, Now));
    return receipt;
}

std::filesystem::path privateCheckpoint(const Transport &transport, const std::string &name = "signed-checkpoint")
{
    const auto path = transport.root.parent_path() / name;
    CHECK(std::filesystem::create_directory(path));
    std::filesystem::permissions(path, std::filesystem::perms::owner_all);
    return path;
}

std::string readCheckpointBytes(const std::filesystem::path &path)
{
    std::ifstream input(path, std::ios::binary);
    CHECK(input.is_open());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

State enrollReplicas(Fixture &fixture)
{
    const auto first = fixture.enrollFirst();
    CHECK(!install(fixture, 1).empty());
    CHECK(fixture.journal(2).observe(first, Now) == ObserveResult::Applied);
    const auto proposal = fixture.proposal(fixture.request(2));
    const auto second = fixture.certificate(proposal, {0, 1});
    const auto reviewed = fixture.journal(2).reviewJoin(proposal, {fixture.member(0).id, fixture.member(1).id}, Now);
    CHECK(fixture.journal(2).acceptJoin(second, Fixture::confirmations(reviewed), Now) == ObserveResult::Applied);
    CHECK(fixture.journal(0).observe(second, Now) == ObserveResult::Applied);
    CHECK(fixture.journal(1).observe(second, Now) == ObserveResult::Applied);
    CHECK(!install(fixture, 2).empty());
    return fixture.journal(0).inspect().state;
}

tx::Snapshot textSnapshot(std::string_view text)
{
    return {{{"text/plain", Bytes(text.begin(), text.end())}}};
}

struct JoinedReplica {
    JoinedReplica(Fixture &fixture, const Transport &transport, std::size_t member)
        : fixture(fixture), transport(transport), member(member),
          activation(fixture.journal(member).preflightJoinActivation(
              *fixture.identities[member], transport.directory(), Binding, Now)),
          checkpoint(privateCheckpoint(transport, "replica-" + std::to_string(member)),
                     Bytes(32, static_cast<std::uint8_t>(member)), Binding)
    {
        fixture.journal(member).applyJoinActivation(*fixture.identities[member], transport.directory(), activation, Now,
            [&](const JoinActivation &verified, const cqs::events::Event &tip, const tx::Snapshot &snapshot) {
                checkpoint.apply(verified, tip, snapshot);
            });
    }

    SignedReplicaResult sync(const SignedReplicaWriter &beforeWrite = {},
                             const std::function<bool()> &canProceed = {})
    {
        auto mounted = checkpoint.mount(activation);
        const auto local = mounted->snapshot();
        return fixture.journal(member).synchronizeReplica(*fixture.identities[member], transport.directory(),
            activation, mounted->replica(), local, Now,
            [&](const SignedReplicaState &state, const tx::Snapshot &snapshot) {
                rejects<JournalError>(JournalCode::Busy, [&] { (void)fixture.journal(member).inspect(); });
                if (beforeWrite) beforeWrite(state, snapshot);
                mounted->updateReplica(state, snapshot, mounted->generation());
            }, {}, {}, canProceed);
    }

    std::optional<SignedReplicaConflict> reviewConflict()
    {
        const auto mounted = mount();
        return fixture.journal(member).reviewReplicaConflict(*fixture.identities[member], transport.directory(),
            activation, mounted->replica(), mounted->snapshot(), Now);
    }

    SignedReplicaResult resolveConflict(const SignedReplicaConflict &review, const std::string &selected,
        const SignedReplicaWriter &beforeWrite = {}, const SignedReplicaTargetValidator &validate = {})
    {
        auto mounted = mount();
        const auto local = mounted->snapshot();
        return fixture.journal(member).resolveReplicaConflict(*fixture.identities[member], transport.directory(),
            activation, mounted->replica(), local, review, selected, Now,
            [&](const SignedReplicaState &state, const tx::Snapshot &snapshot) {
                if (beforeWrite) beforeWrite(state, snapshot);
                mounted->updateReplica(state, snapshot, mounted->generation());
            }, {}, [&](const tx::Snapshot &before, const tx::Snapshot &after) {
                if (validate) validate(before, after);
                if (!mounted->replica().pending) mounted->checkConflictBackupCapacity(after);
            });
    }

    SignedReplicaRecovery recoverRotation(const SignedReplicaWriter &beforeWrite = {})
    {
        auto mounted = checkpoint.mount(activation);
        const auto local = mounted->snapshot();
        return fixture.journal(member).recoverRotatedReplica(*fixture.identities[member], activation,
            mounted->replica(), local, Now, [&](const SignedReplicaState &state, const tx::Snapshot &snapshot) {
                if (beforeWrite) beforeWrite(state, snapshot);
                mounted->updateReplica(state, snapshot, mounted->generation());
            });
    }

    void edit(const tx::Snapshot &snapshot)
    {
        auto mounted = checkpoint.mount(activation);
        mounted->save(snapshot, mounted->generation());
    }

    std::unique_ptr<SignedJoinCheckpoint::Mounted> mount() { return checkpoint.mount(activation); }

    Fixture &fixture;
    const Transport &transport;
    std::size_t member;
    const JoinActivation activation;
    SignedJoinCheckpoint checkpoint;
};

struct ReplicaPair {
    Fixture fixture;
    Transport transport{enrollReplicas(fixture)};
    std::string initialTip = seed(fixture, transport);
    JoinedReplica first{fixture, transport, 1};
    JoinedReplica second{fixture, transport, 2};

    std::vector<storage::SignedEventPacket> packets() const
    {
        return transport.directory().scanSignedEvents(transport.scope);
    }
};

void rotateReplicaKey(ReplicaPair &pair, std::size_t removed)
{
    auto &fixture = pair.fixture;
    const auto rotated = SyncKey::generate();
    const auto proposal = fixture.journal(0).propose(Operation::Remove, fixture.member(removed), token(31), token(32),
        Now, Expires, rotated->commitment(fixture.genesis.group, 1));
    Certificate removal{proposal, {}};
    for (std::size_t signer : {0u, removed == 1 ? 2u : 1u}) {
        removal.approvals.push_back(fixture.journal(signer).approve(proposal, *fixture.identities[signer],
            verificationDigest(proposal, fixture.member(signer)), Now));
    }
    CHECK(fixture.journal(1).observe(removal, Now) == ObserveResult::Applied);
    CHECK(fixture.journal(1).inspect().state.keyGeneration == 1);
}

const storage::SignedEventPacket &packet(const std::vector<storage::SignedEventPacket> &packets,
                                         const std::string &id)
{
    const auto found = std::find_if(packets.begin(), packets.end(), [&](const auto &entry) { return entry.id == id; });
    CHECK(found != packets.end());
    return *found;
}

#ifdef CQS_TEST_NATIVE_SIGNED_JOIN
enum class WizardActivation { NoCallback, Accept, Decline, AdvanceTip };

void exerciseNativeConflictWizard()
{
    ReplicaPair pair;
    const auto local = textSnapshot("local version retained in an encrypted backup");
    const auto remote = textSnapshot("explicitly selected signed remote version");
    pair.first.edit(local);
    pair.second.edit(remote);
    CHECK(pair.second.sync() == SignedReplicaResult::Published);
    bool selected = false;
    bool confirmed = false;
    bool completed = false;
    QTimer::singleShot(0, [&] {
        auto *wizard = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        CHECK(wizard);
        const auto buttons = wizard->findChildren<QPushButton *>();
        const auto resolve = std::find_if(buttons.begin(), buttons.end(), [](const auto *button) {
            return button->text() == QStringLiteral("Resolve signed conflict");
        });
        CHECK(resolve != buttons.end());
        QTimer respond;
        QObject::connect(&respond, &QTimer::timeout, [&] {
            auto *active = QApplication::activeModalWidget();
            if (auto *input = qobject_cast<QInputDialog *>(active)) {
                CHECK(!selected && !confirmed);
                auto *choices = input->findChild<QComboBox *>();
                CHECK(choices && choices->count() == 2);
                choices->setCurrentIndex(1);
                selected = true;
                input->accept();
            } else if (auto *message = qobject_cast<QMessageBox *>(active)) {
                CHECK(selected && !completed);
                if (auto *yes = message->button(QMessageBox::Yes)) {
                    CHECK(!confirmed && message->text().contains(QStringLiteral("exact signed versions")));
                    confirmed = true;
                    yes->click();
                    return;
                }
                CHECK(confirmed && message->text().startsWith(QStringLiteral("The signed resolution was published.")));
                completed = true;
                message->accept();
            }
        });
        respond.start(2);
        (*resolve)->click();
        wizard->reject();
    });
    const auto prepare = [&]() -> std::optional<cqs::native::SignedReplicaRequest> {
        return cqs::native::SignedReplicaRequest{pair.first.activation, 100, true, [] { return true; },
            [&](const auto &before, const auto &after) { return before == local && after == remote; }};
    };
    cqs::native::runSignedJoinWizard(nullptr, pair.fixture.journal(1), *pair.fixture.identities[1],
        pair.transport.directory(), pair.first.checkpoint, Binding, nullptr, {}, {}, {}, QStringLiteral("synthetic"), prepare);
    CHECK(selected && confirmed && completed);
    const auto mounted = pair.first.mount();
    CHECK(mounted->snapshot() == remote && mounted->conflictBackupCount() == 1 && mounted->conflictBackup(0) == local);
    CHECK(pair.packets().size() == 3 && !mounted->replica().pending);
}

void exerciseNativeWizard(WizardActivation choice)
{
    Fixture f;
    f.enrollFirst();
    Transport transport(f.journal(0).inspect().state);
    CHECK(!seed(f, transport).empty() && !install(f).empty());
    const auto directory = privateCheckpoint(transport);
    const auto record = directory / st::FileStore::RecordName;
    const auto expected = f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
    const auto snapshot = cqs::packed::decode(ValidItems);
    SignedJoinCheckpoint checkpoint(directory, Bytes(32, 0x44), Binding);
    bool checkpointConfirmed = false;
    bool activationReviewed = false;
    bool completed = false;
    unsigned activationCalls = 0;
    std::function<bool(const JoinActivation &)> activate;
    if (choice != WizardActivation::NoCallback) {
        activate = [&](const JoinActivation &actual) {
            CHECK(checkpointConfirmed && activationReviewed && !completed);
            CHECK(actual.profileBinding == expected.profileBinding && actual.group == expected.group &&
                  actual.root == expected.root && actual.head == expected.head && actual.member == expected.member &&
                  actual.generation == expected.generation && actual.tipId == expected.tipId &&
                  actual.tipDigest == expected.tipDigest);
            const auto mounted = checkpoint.mount(actual);
            CHECK(mounted->generation() == 2 && mounted->snapshot() == snapshot);
            ++activationCalls;
            return true;
        };
    }

    QTimer::singleShot(0, [&] {
        auto *wizard = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        CHECK(wizard);
        const auto buttons = wizard->findChildren<QPushButton *>();
        const auto write = std::find_if(buttons.begin(), buttons.end(), [](const QPushButton *button) {
            return button->text().startsWith(QStringLiteral("5. "));
        });
        CHECK(write != buttons.end());
        QTimer respond;
        QObject::connect(&respond, &QTimer::timeout, [&] {
            auto *message = qobject_cast<QMessageBox *>(QApplication::activeModalWidget());
            if (!message) return;
            if (auto *yes = message->button(QMessageBox::Yes)) {
                if (!checkpointConfirmed) {
                    CHECK(message->text().startsWith(QStringLiteral("Write this verified history")));
                    CHECK(!std::filesystem::exists(record) && activationCalls == 0);
                    checkpointConfirmed = true;
                    yes->click();
                    return;
                }
                CHECK(!activationReviewed && choice != WizardActivation::NoCallback && activationCalls == 0);
                CHECK(message->text().startsWith(QStringLiteral("The encrypted signed checkpoint was verified.")));
                {
                    const auto mounted = checkpoint.mount(expected);
                    CHECK(mounted->generation() == 1 && mounted->snapshot() == snapshot);
                }
                activationReviewed = true;
                if (choice == WizardActivation::AdvanceTip) {
                    const std::vector<SignedEventParent> parents{{expected.tipId, expected.tipDigest}};
                    const auto prepared = f.journal(0).prepareClipboardEvent(*f.identities[0], *f.key, parents, ValidItems, Now);
                    CHECK(!f.journal(0).publishClipboardEvent(prepared.sequence, *f.key, transport.directory(), Now).empty());
                }
                auto *answer = choice == WizardActivation::Decline ? message->button(QMessageBox::No) : yes;
                CHECK(answer);
                answer->click();
                return;
            }

            CHECK(checkpointConfirmed && !completed);
            switch (choice) {
            case WizardActivation::Accept:
                CHECK(message->text().startsWith(QStringLiteral("Create the signed_sync tab")));
                break;
            case WizardActivation::AdvanceTip:
                CHECK(message->icon() == QMessageBox::Warning &&
                      message->text().startsWith(QStringLiteral("The operation failed or its durable outcome is unconfirmed.")));
                break;
            case WizardActivation::NoCallback:
            case WizardActivation::Decline:
                CHECK(message->text() == QStringLiteral("Encrypted signed checkpoint verified."));
                break;
            }
            completed = true;
            message->accept();
        });
        respond.start(2);
        (*write)->click();
        wizard->reject();
    });
    cqs::native::runSignedJoinWizard(nullptr, f.journal(1), *f.identities[1], transport.directory(),
                                     checkpoint, Binding, nullptr, {}, {}, activate);
    CHECK(checkpointConfirmed && completed && activationReviewed == (choice != WizardActivation::NoCallback));
    CHECK(activationCalls == (choice == WizardActivation::Accept ? 1u : 0u));
    const auto mounted = checkpoint.mount(expected);
    CHECK(mounted->generation() == (choice == WizardActivation::Accept ? 2u : 1u));
    CHECK(mounted->snapshot() == snapshot);
    CHECK(std::filesystem::is_empty(transport.root / "events"));
}

void exerciseNativeReplicaWizard(JoinedReplica &replica, const tx::Snapshot &local,
                                 const tx::Snapshot &remote, bool allowImport)
{
    bool confirmed = false;
    bool completed = false;
    unsigned prepared = 0;
    unsigned sourceChecks = 0;
    unsigned protectionChecks = 0;
    QTimer::singleShot(0, [&] {
        auto *wizard = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        CHECK(wizard);
        const auto buttons = wizard->findChildren<QPushButton *>();
        const auto sync = std::find_if(buttons.begin(), buttons.end(), [](const QPushButton *button) {
            return button->text() == QStringLiteral("Synchronize signed_sync");
        });
        CHECK(sync != buttons.end());
        QTimer respond;
        QObject::connect(&respond, &QTimer::timeout, [&] {
            auto *message = qobject_cast<QMessageBox *>(QApplication::activeModalWidget());
            if (!message) return;
            if (auto *yes = message->button(QMessageBox::Yes)) {
                CHECK(!confirmed && prepared == 0 && message->text().startsWith(QStringLiteral("Use this folder")));
                confirmed = true;
                yes->click();
                return;
            }
            CHECK(confirmed && !completed && prepared == 1);
            if (allowImport) {
                CHECK(message->icon() == QMessageBox::Information &&
                      message->text().startsWith(QStringLiteral("Verified history saved.")));
            } else {
                CHECK(message->icon() == QMessageBox::Warning &&
                      message->text().contains(QStringLiteral("would change pinned or locked items")));
            }
            completed = true;
            message->accept();
        });
        respond.start(2);
        (*sync)->click();
        wizard->reject();
    });
    cqs::native::runSignedJoinWizard(nullptr, replica.fixture.journal(replica.member),
        *replica.fixture.identities[replica.member], replica.transport.directory(), replica.checkpoint,
        Binding, nullptr, {}, {}, {}, QString::fromStdString(replica.transport.root.string()),
        [&]() -> std::optional<cqs::native::SignedReplicaRequest> {
            CHECK(confirmed && !completed);
            ++prepared;
            return cqs::native::SignedReplicaRequest{replica.activation, 100, true,
                [&] { ++sourceChecks; return true; },
                [&](const tx::Snapshot &before, const tx::Snapshot &after) {
                    CHECK(before == local && after == remote);
                    ++protectionChecks;
                    return allowImport;
                }};
        });
    CHECK(confirmed && completed && prepared == 1 && protectionChecks == 1);
    CHECK(sourceChecks == (allowImport ? 2u : 1u));
}

void clickNativeWizardAction(const QString &name, const std::function<void(QMessageBox &)> &respond)
{
    auto *wizard = qobject_cast<QDialog *>(QApplication::activeModalWidget());
    CHECK(wizard);
    const auto buttons = wizard->findChildren<QPushButton *>();
    const auto button = std::find_if(buttons.begin(), buttons.end(), [&](const QPushButton *candidate) {
        return candidate->text() == name;
    });
    CHECK(button != buttons.end());
    QTimer timer;
    QObject::connect(&timer, &QTimer::timeout, [&] {
        if (auto *message = qobject_cast<QMessageBox *>(QApplication::activeModalWidget())) respond(*message);
    });
    timer.start(2);
    (*button)->click();
    if (wizard->isVisible()) wizard->reject();
}

void exerciseNativeBackgroundConsent(ReplicaPair &pair, bool accept)
{
    const auto source = QString::fromStdString(pair.transport.root.string());
    bool prompted = false;
    unsigned armCalls = 0;
    QTimer::singleShot(0, [&] {
        clickNativeWizardAction(QStringLiteral("Start signed background synchronization"), [&](QMessageBox &message) {
            CHECK(!prompted && armCalls == 0 && message.icon() == QMessageBox::Question);
            CHECK(message.textFormat() == Qt::PlainText && message.text().contains(source));
            CHECK(message.text().contains(QStringLiteral("while signed_sync is unloaded")));
            CHECK(message.defaultButton() == message.button(QMessageBox::No));
            prompted = true;
            auto *answer = message.button(accept ? QMessageBox::Yes : QMessageBox::No);
            CHECK(answer);
            answer->click();
        });
    });
    cqs::native::runSignedJoinWizard(nullptr, pair.fixture.journal(1), *pair.fixture.identities[1],
        pair.transport.directory(), pair.first.checkpoint, Binding, nullptr, {}, {}, {}, source, {}, [&] {
            CHECK(accept && prompted && armCalls == 0);
            ++armCalls;
            return true;
        });
    CHECK(prompted && armCalls == (accept ? 1u : 0u));
}

void exerciseNativeRotationRecovery(ReplicaPair &pair)
{
    bool confirmed = false;
    bool completed = false;
    unsigned sourceChecks = 0;
    QTimer::singleShot(0, [&] {
        clickNativeWizardAction(QStringLiteral("Recover pending publication after key rotation"), [&](QMessageBox &message) {
            if (auto *yes = message.button(QMessageBox::Yes)) {
                CHECK(!confirmed && !completed && sourceChecks == 0);
                CHECK(message.defaultButton() == message.button(QMessageBox::No));
                CHECK(message.text().contains(QStringLiteral("working copy stays encrypted")));
                confirmed = true;
                yes->click();
                return;
            }
            CHECK(confirmed && !completed && sourceChecks == 1);
            CHECK(message.icon() == QMessageBox::Information);
            CHECK(message.text().contains(QStringLiteral("An earlier publication may have reached transport")));
            completed = true;
            message.accept();
        });
    });
    cqs::native::runSignedJoinWizard(nullptr, pair.fixture.journal(1), *pair.fixture.identities[1],
        pair.transport.directory(), pair.first.checkpoint, Binding, nullptr, {}, {}, {},
        QString::fromStdString(pair.transport.root.string()), [&]() -> std::optional<cqs::native::SignedReplicaRequest> {
            CHECK(!confirmed && !completed);
            return cqs::native::SignedReplicaRequest{pair.first.activation, 100, true,
                [&] { CHECK(confirmed); ++sourceChecks; return true; }, {}};
        });
    CHECK(confirmed && completed && sourceChecks == 1);
}
#endif
#endif
} // namespace

int main(int argc, char **argv)
{
#ifdef CQS_TEST_NATIVE_SIGNED_JOIN
    QApplication app(argc, argv);
#else
    (void)argc;
    (void)argv;
#endif
    test("join challenges are per applicant, durable, and never returned before the commit barrier", [] {
        Fixture f;
        refuses([&] { f.journal(1).beginJoin(*f.identities[2], Now); });
        f.store(1).failure = MemoryStore::Fault::Before;
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.request(1); });
        CHECK(f.store(1).record.generation == 0);
        f.reopen(1);
        f.store(1).failure = MemoryStore::Fault::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.request(1); });
        CHECK(f.store(1).record.generation == 1);
        f.reopen(1);
        const auto one = f.request(1);
        CHECK(one.applicant == f.member(1) && one.request != Token{});
        f.reopen(1);
        CHECK(f.request(1).request == one.request);
        CHECK(f.request(2).request != one.request);
        CHECK(f.journal(1).inspect().state.epoch == 0);
    });
    test("both sides derive the same full digest from their pinned group and intended applicant", [] {
        Fixture f;
        const auto proposal = f.proposal(f.request(1));
        const auto applicant = f.journal(1).reviewJoin(proposal, {f.member(0).id}, Now);
        const auto founder = f.journal(0).reviewJoinApproval(proposal, Now);
        CHECK(applicant.group == f.genesis.group && applicant.root == f.journal(0).inspect().state.root);
        CHECK(applicant.applicant == f.member(1) && applicant.expires == Expires);
        CHECK(applicant.approvers.size() == 1 && founder.approvers.size() == 1);
        CHECK(applicant.approvers[0].member == f.member(0));
        CHECK(applicant.approvers[0].digest == founder.approvers[0].digest);
        CHECK(applicant.approvers[0].digest == verificationDigest(proposal, f.member(0)));
        for (unsigned part = 0; part < 4; ++part) {
            auto substituted = proposal;
            if (part == 0) substituted.request = token(91);
            if (part == 1) substituted.root[0] ^= 1;
            if (part == 2) substituted.subject.encryptionKey = f.member(2).encryptionKey;
            if (part == 3) substituted.parent[0] ^= 1;
            refuses([&] { f.journal(1).reviewJoin(substituted, {f.member(0).id}, Now); });
        }
        refuses([&] { f.journal(1).reviewJoin(proposal, {f.member(2).id}, Now); });
        refuses([&] { f.journal(1).reviewJoin(proposal, {f.member(0).id}, Expires); });
        CHECK(f.journal(1).inspect().state.epoch == 0);
    });
    test("acceptance requires the reviewed signatures and keeps an ambiguous exact retry idempotent", [] {
        Fixture f;
        const auto proposal = f.proposal(f.request(1));
        const auto proof = Fixture::confirmations(f.journal(1).reviewJoin(proposal, {f.member(0).id}, Now));
        const auto certificate = f.certificate(proposal, {0});
        auto altered = certificate;
        altered.approvals[0].signature[0] ^= 1;
        refuses([&] { f.journal(1).acceptJoin(altered, proof, Now); });
        refuses([&] { f.journal(1).observe(certificate, Now); });
        refuses([&] { f.journal(1).acceptJoin(certificate, {}, Now); });
        refuses([&] { f.journal(1).acceptJoin(certificate, proof, Expires); });
        CHECK(f.journal(1).inspect().state.epoch == 0);

        f.store(1).failure = MemoryStore::Fault::Before;
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.journal(1).acceptJoin(certificate, proof, Now); });
        f.reopen(1);
        CHECK(f.journal(1).inspect().state.epoch == 0);
        f.store(1).failure = MemoryStore::Fault::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.journal(1).acceptJoin(certificate, proof, Now); });
        f.reopen(1);
        CHECK(f.journal(1).acceptJoin(certificate, proof, Expires) == ObserveResult::AlreadyKnown);
        CHECK(f.journal(1).inspect().state.epoch == 1);
        CHECK(f.journal(1).inspect().verifiedJoin);
        CHECK(f.journal(1).inspect().certificates.size() == 1);
        refuses([&] { f.journal(1).acceptJoin(altered, proof, Expires); });
    });
    test("malformed enrollment metadata cannot turn an outstanding request into a verified Join", [] {
        Fixture f;
        f.request(1);
        const auto before = f.store(1).record;
        auto &log = f.store(1).record.local->front().begin()->second;
        CHECK(log.size() >= 2 * Token{}.size());
        log.back() ^= 1; // Nonzero admission intent without a matching accepted Add.
        rejects<JournalError>(JournalCode::Invalid, [&] { f.reopen(1); });
        f.store(1).record = before;
        f.reopen(1);
        CHECK(!f.journal(1).inspect().verifiedJoin);
    });
    test("a later Add matches every certificate signer against the applicant's observed chain", [] {
        Fixture f;
        const auto first = f.enrollFirst();
        CHECK(f.journal(2).observe(first, Now) == ObserveResult::Applied);
        const auto proposal = f.proposal(f.request(2));
        const std::vector<Token> approvers{f.member(0).id, f.member(1).id};
        auto proof = Fixture::confirmations(f.journal(2).reviewJoin(proposal, approvers, Now));
        CHECK(proof.size() == 2 && proof[0].digest != proof[1].digest);
        const auto certificate = f.certificate(proposal, {0, 1});
        refuses([&] { f.journal(2).reviewJoin(proposal, {f.member(0).id}, Now); });
        refuses([&] { f.journal(2).reviewJoin(proposal, {f.member(0).id, f.member(0).id}, Now); });
        refuses([&] { f.journal(2).reviewJoin(proposal, {f.member(0).id, f.member(3).id}, Now); });
        auto duplicate = proof;
        duplicate[1] = duplicate[0];
        refuses([&] { f.journal(2).acceptJoin(certificate, duplicate, Now); });
        auto swapped = proof;
        std::swap(swapped[0].digest, swapped[1].digest);
        refuses([&] { f.journal(2).acceptJoin(certificate, swapped, Now); });
        auto extra = proof;
        extra.push_back({f.member(3).id, token(90)});
        refuses([&] { f.journal(2).acceptJoin(certificate, extra, Now); });
        CHECK(f.journal(2).inspect().state.epoch == 1);
        CHECK(f.journal(2).acceptJoin(certificate, proof, Now) == ObserveResult::Applied);
        CHECK(f.journal(2).inspect().state.epoch == 2);
    });
    test("trusted terminal prompts require full independent values and recheck the clock", [] {
        Fixture f;
        const auto proposal = f.proposal(f.request(1));
        const auto expected = verificationDigest(proposal, f.member(0));
        const auto fixedTime = [] { return Now; };
        std::ostringstream screen;
        const auto applicantGeneration = f.store(1).record.generation;
        CHECK(showJoinApplicantReview(f.journal(1), proposal, {f.member(0).id}, screen, Now));
        CHECK(f.store(1).record.generation == applicantGeneration);
        CHECK(screen.str().find(hex(expected, true)) != std::string::npos);
        std::istringstream partial(hex(expected).substr(0, 63) + "\n");
        CHECK(!runJoinApprovalWizard(f.journal(0), *f.identities[0], proposal, partial, screen, fixedTime));
        CHECK(f.journal(0).inspect().reservations == 0);
        std::istringstream trailing(hex(expected) + "0\n");
        CHECK(!runJoinApprovalWizard(f.journal(0), *f.identities[0], proposal, trailing, screen, fixedTime));
        CHECK(f.journal(0).inspect().reservations == 0);
        std::istringstream answer(hex(expected, true, true) + "\r\n");
        const auto approval = runJoinApprovalWizard(f.journal(0), *f.identities[0], proposal, answer, screen, fixedTime);
        CHECK(approval);
        CHECK(screen.str().find(hex(f.genesis.group, true)) != std::string::npos);
        CHECK(screen.str().find("synchronized clipboard history") != std::string::npos);

        const Certificate certificate{proposal, {*approval}};
        std::istringstream wrong(hex(token(90)) + "\n");
        CHECK(!runJoinApplicantWizard(f.journal(1), certificate, wrong, screen, fixedTime));
        CHECK(f.journal(1).inspect().state.epoch == 0);
        unsigned calls = 0;
        std::istringstream expired(hex(expected) + "\n");
        refuses([&] {
            runJoinApplicantWizard(f.journal(1), certificate, expired, screen, [&] {
                return calls++ ? Expires : Now;
            });
        });
        CHECK(calls == 2 && f.journal(1).inspect().state.epoch == 0);
        std::istringstream confirmed(hex(expected) + "\n");
        const auto joined = runJoinApplicantWizard(f.journal(1), certificate, confirmed, screen, fixedTime);
        CHECK(joined && *joined == ObserveResult::Applied);
        f.reopen(1);
        std::istringstream empty;
        std::ostringstream noPrompt;
        const auto retried = runJoinApplicantWizard(f.journal(1), certificate, empty, noPrompt, [] { return Expires; });
        CHECK(retried && *retried == ObserveResult::AlreadyKnown && noPrompt.str().empty());
    });
#ifdef __linux__
    test("a reopened encrypted FileStore retains the verified enrollment and sealed key", [] {
        Fixture f;
        Transport transport(f.journal(0).inspect().state);
        const auto privateDirectory = transport.root.parent_path() / "private";
        CHECK(std::filesystem::create_directory(privateDirectory));
        std::filesystem::permissions(privateDirectory, std::filesystem::perms::owner_all);
        const auto binding = TrustJournal::binding(f.genesis, f.member(1));
        const Bytes credential(32, 0x24);
        Token initialChallenge{};
        {
            st::FileStore store(privateDirectory, binding, credential);
            TrustJournal::initialize(store, f.genesis, f.member(1), Now);
            TrustJournal applicant(store, f.genesis, f.member(1));
            initialChallenge = applicant.beginJoin(*f.identities[1], Now).request;
        }
        {
            st::FileStore store(privateDirectory, binding, credential);
            TrustJournal applicant(store, f.genesis, f.member(1));
            const auto request = applicant.beginJoin(*f.identities[1], Now);
            CHECK(request.request == initialChallenge);
            const auto proposal = f.proposal(request);
            const auto confirmed = Fixture::confirmations(applicant.reviewJoin(proposal, {f.member(0).id}, Now));
            const auto certificate = f.certificate(proposal, {0});
            CHECK(applicant.acceptJoin(certificate, confirmed, Now) == ObserveResult::Applied);
            CHECK(f.journal(0).observe(certificate, Now) == ObserveResult::Applied);
            const auto package = f.journal(0).prepareDelivery(f.member(1).id, *f.identities[0], *f.key, Now);
            CHECK(f.journal(0).recordReceipt(applicant.installDelivery(package, *f.identities[1], Now), Now));
        }
        const auto tip = seed(f, transport);
        st::FileStore store(privateDirectory, binding, credential);
        TrustJournal applicant(store, f.genesis, f.member(1));
        CHECK(applicant.inspect().verifiedJoin && applicant.inspect().installedKey);
        const auto result = applicant.preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
        CHECK(result.tipId == tip && result.member == f.member(1).id);
    });
    test("activation binds the verified signed tip after durable enrollment and key delivery", [] {
        Fixture f;
        f.enrollFirst();
        Transport transport(f.journal(0).inspect().state);
        const auto tip = seed(f, transport);
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(!install(f).empty());
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[2], transport.directory(), Binding, Now); });
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), "bad/binding", Now); });
        f.store(1).failure = MemoryStore::Fault::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] {
            f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
        });
        f.reopen(1);
        const auto result = f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
        const auto state = f.journal(1).inspect().state;
        const auto files = transport.directory().scanSignedEvents(transport.scope);
        CHECK(files.size() == 1 && files.front().id == tip);
        CHECK(result.profileBinding == Binding && result.group == state.group && result.root == state.root);
        CHECK(result.head == state.digest && result.generation == state.keyGeneration && result.tipId == tip);
        CHECK(result.tipDigest == SignedEventCodec::digest(files.front().wire));
        CHECK(f.journal(1).inspect().eventWitnesses == 1);
        const auto onlyFile = std::filesystem::directory_iterator(transport.signedFolder);
        CHECK(onlyFile != std::filesystem::directory_iterator{});
        CHECK(std::filesystem::remove(onlyFile->path()));
        f.reopen(1);
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(f.journal(1).inspect().eventWitnesses == 1);
    });
    test("a low-level observed Add cannot authorize profile activation even with a valid package", [] {
        Fixture f;
        const auto proposal = f.proposal({f.member(1), token(20)});
        const auto certificate = f.certificate(proposal, {0});
        CHECK(f.journal(0).observe(certificate, Now) == ObserveResult::Applied);
        CHECK(f.journal(1).observe(certificate, Now) == ObserveResult::Applied);
        Transport transport(f.journal(0).inspect().state);
        CHECK(!seed(f, transport).empty() && !install(f).empty());
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(f.journal(1).inspect().eventWitnesses == 0);
    });
    test("activation refuses empty history, unsupported MIME, and a witnessed fork", [] {
        Fixture f;
        const auto sibling = f.proposal({f.member(3), token(20)});
        f.enrollFirst();
        Transport transport(f.journal(0).inspect().state);
        CHECK(!install(f).empty());
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(!seed(f, transport, {"YQ=="}).empty());
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(f.journal(1).inspect().eventWitnesses == 0);
        const Approval external{f.member(0).id, f.identities[0]->sign(approvalBytes(sibling, f.member(0)))};
        CHECK(f.journal(1).observe({sibling, {external}}, Now) == ObserveResult::ForkDetected);
        f.reopen(1);
        CHECK(f.journal(1).inspect().forked);
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
    });
    test("activation refuses multiple signed tips instead of selecting a branch", [] {
        Fixture f;
        f.enrollFirst();
        Transport transport(f.journal(0).inspect().state);
        CHECK(!install(f).empty());
        const auto tip = seed(f, transport);
        const auto files = transport.directory().scanSignedEvents(transport.scope);
        CHECK(files.size() == 1);
        const std::vector<SignedEventParent> parents{{tip, SignedEventCodec::digest(files[0].wire)}};
        for (unsigned i = 0; i < 2; ++i) {
            const auto prepared = f.journal(0).prepareClipboardEvent(*f.identities[0], *f.key, parents, ValidItems, Now);
            CHECK(!f.journal(0).publishClipboardEvent(prepared.sequence, *f.key, transport.directory(), Now).empty());
        }
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(f.journal(1).inspect().eventWitnesses == 0);
    });
    test("reviewed activation commits an encrypted checkpoint and retries the exact verified snapshot", [] {
        Fixture f;
        f.enrollFirst();
        Transport transport(f.journal(0).inspect().state);
        const auto tip = seed(f, transport);
        CHECK(!install(f).empty());
        const auto directory = privateCheckpoint(transport);
        const auto record = directory / st::FileStore::RecordName;
        const Bytes credential(32, 0x42);
        const auto expected = f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
        CHECK(expected.tipId == tip && !std::filesystem::exists(record));
        unsigned calls = 0;
        const auto apply = [&](SignedJoinCheckpoint &checkpoint) {
            f.journal(1).applyJoinActivation(*f.identities[1], transport.directory(), expected, Now,
                [&](const JoinActivation &verified, const cqs::events::Event &event, const tx::Snapshot &snapshot) {
                    ++calls;
                    rejects<JournalError>(JournalCode::Busy, [&] { (void)f.journal(1).inspect(); });
                    CHECK(verified.tipDigest == expected.tipDigest && event.revision.id == tip);
                    CHECK(snapshot == cqs::packed::decode(ValidItems));
                    checkpoint.apply(verified, event, snapshot);
                });
        };
        {
            SignedJoinCheckpoint checkpoint(directory, credential, Binding);
            f.store(1).failure = MemoryStore::Fault::After;
            rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { apply(checkpoint); });
            CHECK(calls == 0 && !std::filesystem::exists(record));
            f.reopen(1);
            apply(checkpoint);
            CHECK(checkpoint.read(expected) == cqs::packed::decode(ValidItems));
        }
        CHECK(calls == 1);
        f.reopen(1);
        SignedJoinCheckpoint reopened(directory, credential, Binding);
        apply(reopened);
        CHECK(calls == 2 && reopened.read(expected) == cqs::packed::decode(ValidItems));
        CHECK(std::filesystem::is_empty(transport.root / "events"));
        st::FileStore legacy(directory, Binding, credential);
        refuses([&] { (void)legacy.load(); });
    });
    test("activation rechecks both the reviewed tip and membership before calling the writer", [] {
        for (const bool advanceTip : {false, true}) {
            Fixture f;
            f.enrollFirst();
            Transport transport(f.journal(0).inspect().state);
            const auto tip = seed(f, transport);
            CHECK(!install(f).empty());
            const auto expected = f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
            if (advanceTip) {
                const std::vector<SignedEventParent> parents{{tip, expected.tipDigest}};
                const auto prepared = f.journal(0).prepareClipboardEvent(*f.identities[0], *f.key, parents, ValidItems, Now);
                CHECK(!f.journal(0).publishClipboardEvent(prepared.sequence, *f.key, transport.directory(), Now).empty());
            } else {
                const auto later = f.certificate(f.proposal(f.request(2)), {0, 1});
                CHECK(f.journal(1).observe(later, Now) == ObserveResult::Applied);
            }
            bool called = false;
            rejects<JournalError>(JournalCode::HistoryChanged, [&] {
                f.journal(1).applyJoinActivation(*f.identities[1], transport.directory(), expected, Now,
                    [&](const JoinActivation &, const cqs::events::Event &, const tx::Snapshot &) { called = true; });
            });
            CHECK(!called);
        }
    });
    test("a busy or tampered checkpoint cannot be replaced by a revalidated signed Join", [] {
        Fixture f;
        f.enrollFirst();
        Transport transport(f.journal(0).inspect().state);
        CHECK(!seed(f, transport).empty() && !install(f).empty());
        const auto directory = privateCheckpoint(transport);
        const auto record = directory / st::FileStore::RecordName;
        const Bytes credential(32, 0x43);
        const auto expected = f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
        SignedJoinCheckpoint checkpoint(directory, credential, Binding);
        const auto apply = [&] {
            f.journal(1).applyJoinActivation(*f.identities[1], transport.directory(), expected, Now,
                [&](const JoinActivation &verified, const cqs::events::Event &event, const tx::Snapshot &snapshot) {
                    checkpoint.apply(verified, event, snapshot);
                });
        };
        {
            st::FileStore session(directory, Binding, Bytes(32), {}, st::Protection::Key, st::LeaseKind::Session);
            const auto lease = session.lock();
            CHECK(lease);
            rejects<st::Error>(st::ErrorCode::Busy, apply);
            CHECK(!std::filesystem::exists(record));
        }
        apply();
        auto damaged = readCheckpointBytes(record);
        CHECK(!damaged.empty());
        damaged.back() ^= 1;
        {
            std::ofstream output(record, std::ios::binary | std::ios::trunc);
            output.write(damaged.data(), static_cast<std::streamsize>(damaged.size()));
            output.close();
            CHECK(output);
        }
        rejects<st::Error>(st::ErrorCode::AuthenticationFailed, apply);
        CHECK(readCheckpointBytes(record) == damaged);
    });
    test("two joined checkpoints publish and fast-forward exact signed descendants", [] {
        ReplicaPair pair;
        const auto initial = cqs::packed::decode(ValidItems);
        CHECK(pair.first.sync() == SignedReplicaResult::UpToDate);
        const auto firstEdit = textSnapshot("edited on first device");
        pair.first.edit(firstEdit);
        CHECK(pair.first.sync() == SignedReplicaResult::Published);
        pair.fixture.reopen(1);
        pair.fixture.reopen(2);
        CHECK(pair.first.sync() == SignedReplicaResult::UpToDate);
        CHECK(pair.second.sync() == SignedReplicaResult::Pulled);
        const auto firstCursor = pair.first.mount()->replica().cursor;
        {
            const auto second = pair.second.mount();
            CHECK(second->snapshot() == firstEdit && !second->replica().pending);
            CHECK(second->replica().cursor.id == firstCursor.id && second->replica().cursor.digest == firstCursor.digest);
        }
        const auto files = pair.packets();
        CHECK(files.size() == 2);
        const auto &published = packet(files, firstCursor.id);
        CHECK(SignedEventCodec::digest(published.wire) == firstCursor.digest);
        const auto header = SignedEventCodec::inspect(published.wire);
        CHECK(header.context.author == pair.fixture.member(1).id && header.parents.size() == 1);
        CHECK(header.parents.front().id == pair.initialTip &&
              header.parents.front().digest == pair.first.activation.tipDigest);

        const auto secondEdit = textSnapshot("edited on second device");
        pair.second.edit(secondEdit);
        CHECK(pair.second.sync() == SignedReplicaResult::Published);
        CHECK(pair.first.sync() == SignedReplicaResult::Pulled);
        CHECK(pair.first.mount()->snapshot() == secondEdit);
        CHECK(pair.first.checkpoint.read(pair.first.activation) == initial);
        CHECK(pair.second.checkpoint.read(pair.second.activation) == initial);
        CHECK(pair.packets().size() == 3);
        CHECK(std::filesystem::is_empty(pair.transport.root / "events"));
    });
    test("dirty replicas and authenticated forks retain local data without publishing", [] {
        ReplicaPair pair;
        const auto firstEdit = textSnapshot("first branch");
        const auto secondEdit = textSnapshot("unsent second branch");
        pair.first.edit(firstEdit);
        pair.second.edit(secondEdit);
        CHECK(pair.first.sync() == SignedReplicaResult::Published);
        const auto secondGeneration = pair.second.mount()->generation();
        CHECK(pair.second.sync() == SignedReplicaResult::Conflict);
        {
            const auto second = pair.second.mount();
            CHECK(second->generation() == secondGeneration && second->snapshot() == secondEdit);
            CHECK(second->replica().cursor.id == pair.initialTip && !second->replica().pending);
        }
        CHECK(pair.packets().size() == 2);
        CHECK(pair.fixture.journal(2).inspect().allocatedEventSequence == 0);

        auto &founder = pair.fixture.journal(0);
        const auto sibling = founder.prepareClipboardEvent(*pair.fixture.identities[0], *pair.fixture.key,
            {{pair.initialTip, pair.first.activation.tipDigest}}, ValidItems, Now);
        CHECK(!founder.publishClipboardEvent(sibling.sequence, *pair.fixture.key, pair.transport.directory(), Now).empty());
        const auto firstGeneration = pair.first.mount()->generation();
        CHECK(pair.first.sync() == SignedReplicaResult::Conflict);
        const auto first = pair.first.mount();
        CHECK(first->generation() == firstGeneration && first->snapshot() == firstEdit);
        CHECK(pair.packets().size() == 3);
    });
    test("a reviewed remote choice archives local changes before publishing the exact signed resolution", [] {
        ReplicaPair pair;
        const auto local = textSnapshot("local draft kept in private backup");
        const auto remote = textSnapshot("reviewed remote version");
        CHECK(!pair.first.reviewConflict());
        pair.first.edit(local);
        pair.second.edit(remote);
        CHECK(pair.second.sync() == SignedReplicaResult::Published);
        const auto review = pair.first.reviewConflict();
        CHECK(review && review->tips.size() == 1);
        const auto selected = review->tips.front().id;
        bool checkedPolicy = false;
        rejects<st::Error>(st::ErrorCode::InvalidRecord, [&] {
            pair.first.resolveConflict(*review, selected, {}, [&](const auto &before, const auto &after) {
                checkedPolicy = true;
                CHECK(before == local && after == remote);
                throw st::Error(st::ErrorCode::InvalidRecord, "Synthetic protected-item refusal");
            });
        });
        CHECK(checkedPolicy && pair.packets().size() == 2 && !pair.first.mount()->replica().pending);
        CHECK(pair.first.resolveConflict(*review, selected) == SignedReplicaResult::Published);
        const auto mounted = pair.first.mount();
        CHECK(mounted->snapshot() == remote && mounted->conflictBackupCount() == 1 && mounted->conflictBackup(0) == local);
        CHECK(!mounted->replica().pending);
        const auto files = pair.packets();
        CHECK(files.size() == 3);
        const auto header = SignedEventCodec::inspect(packet(files, mounted->replica().cursor.id).wire);
        CHECK(header.parents.size() == 1 && header.parents[0].id == selected &&
              header.parents[0].digest == review->tips.front().digest);
        CHECK(pair.second.sync() == SignedReplicaResult::Pulled && pair.second.mount()->snapshot() == remote);
    });
    test("an explicit local resolution signs both exact fork parents and retains all branch packets", [] {
        ReplicaPair pair;
        const auto local = textSnapshot("chosen local fork resolution");
        pair.first.edit(local);
        CHECK(pair.first.sync() == SignedReplicaResult::Published);
        auto &founder = pair.fixture.journal(0);
        const auto sibling = founder.prepareClipboardEvent(*pair.fixture.identities[0], *pair.fixture.key,
            {{pair.initialTip, pair.first.activation.tipDigest}}, ValidItems, Now);
        CHECK(!founder.publishClipboardEvent(sibling.sequence, *pair.fixture.key, pair.transport.directory(), Now).empty());
        const auto before = pair.packets();
        const auto review = pair.first.reviewConflict();
        CHECK(review && review->tips.size() == 2 && before.size() == 3);
        auto substituted = *review;
        substituted.tips.front().digest.front() ^= 1;
        rejects<JournalError>(JournalCode::HistoryChanged, [&] { pair.first.resolveConflict(substituted, {}); });
        CHECK(pair.packets().size() == 3);
        CHECK(pair.first.resolveConflict(*review, {}) == SignedReplicaResult::Published);
        const auto mounted = pair.first.mount();
        CHECK(mounted->snapshot() == local && mounted->conflictBackupCount() == 0 && !mounted->replica().pending);
        const auto after = pair.packets();
        CHECK(after.size() == before.size() + 1);
        for (const auto &file : before) CHECK(packet(after, file.id).wire == file.wire);
        const auto header = SignedEventCodec::inspect(packet(after, mounted->replica().cursor.id).wire);
        CHECK(header.parents.size() == review->tips.size());
        for (std::size_t i = 0; i < header.parents.size(); ++i) {
            CHECK(header.parents[i].id == review->tips[i].id && header.parents[i].digest == review->tips[i].digest);
        }
        CHECK(pair.second.sync() == SignedReplicaResult::Pulled && pair.second.mount()->snapshot() == local);
    });
    test("a changed local review or a peer append during resolution cannot authorize a stale publication", [] {
        ReplicaPair pair;
        const auto original = textSnapshot("original reviewed local");
        const auto newer = textSnapshot("new local edit after review");
        pair.first.edit(original);
        pair.second.edit(textSnapshot("remote edit"));
        CHECK(pair.second.sync() == SignedReplicaResult::Published);
        const auto stale = pair.first.reviewConflict();
        CHECK(stale && stale->tips.size() == 1);
        pair.first.edit(newer);
        rejects<JournalError>(JournalCode::HistoryChanged, [&] { pair.first.resolveConflict(*stale, {}); });
        CHECK(pair.packets().size() == 2);
        const auto review = pair.first.reviewConflict();
        CHECK(review);
        bool advanced = false;
        CHECK(pair.first.resolveConflict(*review, {}, [&](const SignedReplicaState &state, const tx::Snapshot &) {
            if (!state.pending) return;
            CHECK(!advanced);
            advanced = true;
            pair.second.edit(textSnapshot("peer edit after intent"));
            CHECK(pair.second.sync() == SignedReplicaResult::Published);
        }) == SignedReplicaResult::Conflict);
        const auto mounted = pair.first.mount();
        CHECK(advanced && pair.packets().size() == 3);
        CHECK(mounted->snapshot() == newer && !mounted->replica().pending);
        CHECK(!pair.fixture.journal(1).inspect().pendingEvent);
    });
    test("a resolved packet interrupted before checkpoint finalization preserves later local edits", [] {
        ReplicaPair pair;
        const auto local = textSnapshot("initial backup");
        const auto remote = textSnapshot("chosen branch");
        const auto later = textSnapshot("newer local edit");
        pair.first.edit(local);
        pair.second.edit(remote);
        CHECK(pair.second.sync() == SignedReplicaResult::Published);
        const auto review = pair.first.reviewConflict();
        CHECK(review);
        rejects<st::Error>(st::ErrorCode::Io, [&] {
            pair.first.resolveConflict(*review, review->tips.front().id, [&](const auto &state, const auto &) {
                if (!state.pending) throw st::Error(st::ErrorCode::Io, "Injected before resolution checkpoint commit");
            });
        });
        const auto pending = pair.first.mount()->replica().pending;
        CHECK(pending && pending->mergeParents.size() == 1 && pair.first.mount()->conflictBackupCount() == 1);
        const auto files = pair.packets();
        CHECK(files.size() == 3);
        pair.first.edit(later);
        rejects<JournalError>(JournalCode::EventPending, [&] { pair.first.sync({}, [] { return true; }); });
        CHECK(pair.first.sync() == SignedReplicaResult::Published);
        const auto mounted = pair.first.mount();
        CHECK(mounted->snapshot() == later && !mounted->replica().pending);
        CHECK(mounted->conflictBackupCount() == 1 && mounted->conflictBackup(0) == local);
        CHECK(pair.packets().size() == 3 && packet(pair.packets(), mounted->replica().cursor.id).wire ==
              packet(files, mounted->replica().cursor.id).wire);
    });
    test("background cancellation at the last journal barrier preserves the unsent slot for explicit recovery", [] {
        ReplicaPair pair;
        const auto local = textSnapshot("authorized automatic payload");
        pair.first.edit(local);
        auto &store = pair.fixture.store(1);
        bool allow = true;
        unsigned commits = 0;
        rejects<JournalError>(JournalCode::EventPublication, [&] {
            pair.first.sync([&](const auto &state, const auto &) {
                CHECK(state.pending);
                store.onCommit = [&] { if (++commits == 3) allow = false; };
            }, [&] { return allow; });
        });
        store.onCommit = {};
        CHECK(!allow && commits == 4 && pair.packets().size() == 1);
        const auto pending = pair.fixture.journal(1).inspect().pendingEvent;
        CHECK(pending && !pending->publicationAttempted && pending->ready);
        rejects<JournalError>(JournalCode::EventPending, [&] { pair.first.sync({}, [] { return true; }); });
        const auto later = textSnapshot("newer edit replaces the definitely unsent slot");
        pair.first.edit(later);
        CHECK(pair.first.sync() == SignedReplicaResult::Published && pair.packets().size() == 2);
        CHECK(pair.second.sync() == SignedReplicaResult::Pulled && pair.second.mount()->snapshot() == later);
    });
    test("a peer advancing during reservation prevents an unattempted first append", [] {
        ReplicaPair pair;
        const auto local = textSnapshot("local edit stays private");
        const auto remote = textSnapshot("concurrent peer edit");
        pair.first.edit(local);
        pair.second.edit(remote);
        bool intervened = false;
        CHECK(pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
            if (!state.pending || intervened) return;
            intervened = true;
            CHECK(pair.second.sync() == SignedReplicaResult::Published);
        }) == SignedReplicaResult::Conflict);
        CHECK(intervened && pair.packets().size() == 2);
        CHECK(pair.first.sync() == SignedReplicaResult::Conflict);
        const auto mounted = pair.first.mount();
        CHECK(mounted->snapshot() == local && mounted->replica().cursor.id == pair.initialTip);
        CHECK(!pair.fixture.journal(1).inspect().pendingEvent);
        CHECK(pair.packets().size() == 2);
    });
    test("a published replica packet is recovered byte-for-byte while a newer local edit remains dirty", [] {
        ReplicaPair pair;
        const auto firstEdit = textSnapshot("publish once");
        const auto nextEdit = textSnapshot("keep local edit made after interruption");
        pair.first.edit(firstEdit);
        bool persistedIntent = false;
        rejects<st::Error>(st::ErrorCode::Io, [&] {
            pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
                if (state.pending) {
                    persistedIntent = true;
                    return;
                }
                CHECK(persistedIntent && pair.packets().size() == 2);
                throw st::Error(st::ErrorCode::Io, "Injected before checkpoint finalization");
            });
        });
        const auto intent = pair.first.mount()->replica().pending;
        CHECK(intent && intent->sequence == 1 && pair.first.mount()->snapshot() == firstEdit);
        const auto firstId = cqs::history::makeId(SignedEventCodec::deviceName(pair.fixture.member(1).id), intent->sequence);
        const auto published = packet(pair.packets(), firstId);
        CHECK(pair.packets().size() == 2 && !pair.fixture.journal(1).inspect().pendingEvent);
        pair.first.edit(nextEdit);
        pair.fixture.reopen(1);
        CHECK(pair.first.sync() == SignedReplicaResult::Published);
        {
            const auto recovered = pair.first.mount();
            CHECK(!recovered->replica().pending && recovered->replica().cursor.id == firstId);
            CHECK(recovered->snapshot() == nextEdit);
        }
        CHECK(pair.packets().size() == 2 && packet(pair.packets(), firstId).wire == published.wire);
        CHECK(pair.second.sync() == SignedReplicaResult::Pulled && pair.second.mount()->snapshot() == firstEdit);
        CHECK(pair.first.sync() == SignedReplicaResult::Published && pair.packets().size() == 3);
        CHECK(pair.second.sync() == SignedReplicaResult::Pulled && pair.second.mount()->snapshot() == nextEdit);
    });
    test("an irrevocable replica attempt recovers its exact slot and reports a newly visible fork", [] {
        ReplicaPair pair;
        const auto firstEdit = textSnapshot("first committed intent");
        const auto secondEdit = textSnapshot("peer appended while intent was interrupted");
        pair.first.edit(firstEdit);
        auto &store = pair.fixture.store(1);
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] {
            pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
                CHECK(state.pending);
                store.deferredCommits = 2; // Burn, seal, then durably mark the publication attempted.
                store.failure = MemoryStore::Fault::After;
            });
        });
        CHECK(pair.packets().size() == 1);
        pair.fixture.reopen(1);
        const auto attempted = pair.fixture.journal(1).inspect().pendingEvent;
        CHECK(attempted && attempted->ready && attempted->publicationAttempted);
        pair.second.edit(secondEdit);
        CHECK(pair.second.sync() == SignedReplicaResult::Published && pair.packets().size() == 2);
        CHECK(pair.first.sync() == SignedReplicaResult::Conflict);
        const auto first = pair.first.mount();
        CHECK(!first->replica().pending && first->snapshot() == firstEdit);
        const auto firstId = cqs::history::makeId(SignedEventCodec::deviceName(pair.fixture.member(1).id), attempted->sequence);
        const auto files = pair.packets();
        CHECK(files.size() == 3 && first->replica().cursor.id == firstId);
        CHECK(SignedEventCodec::digest(packet(files, firstId).wire) == first->replica().cursor.digest);
        CHECK(pair.fixture.journal(1).inspect().eventEncryptionAttempts == 1);
        CHECK(pair.second.sync() == SignedReplicaResult::Conflict && pair.second.mount()->snapshot() == secondEdit);
    });
    test("an edited ready slot is retired without publishing the superseded clipboard contents", [] {
        ReplicaPair pair;
        pair.first.edit(textSnapshot("withdraw before publication"));
        auto &store = pair.fixture.store(1);
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] {
            pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
                CHECK(state.pending);
                store.deferredCommits = 1; // Interrupt after sealing, before publication is attempted.
                store.failure = MemoryStore::Fault::After;
            });
        });
        pair.fixture.reopen(1);
        const auto prior = pair.fixture.journal(1).inspect().pendingEvent;
        CHECK(prior && prior->ready && !prior->publicationAttempted && prior->sequence == 1);
        const auto latest = textSnapshot("latest edit authorized for publication");
        pair.first.edit(latest);
        CHECK(pair.first.sync() == SignedReplicaResult::Published && pair.second.sync() == SignedReplicaResult::Pulled);
        CHECK(pair.second.mount()->snapshot() == latest);
        const auto files = pair.packets();
        CHECK(files.size() == 2);
        const auto device = SignedEventCodec::deviceName(pair.fixture.member(1).id);
        CHECK(std::none_of(files.begin(), files.end(), [&](const auto &file) {
            return file.id == cqs::history::makeId(device, prior->sequence);
        }));
        CHECK(packet(files, cqs::history::makeId(device, 2)).id == pair.first.mount()->replica().cursor.id);
        CHECK(pair.fixture.journal(1).inspect().eventEncryptionAttempts == 2);
    });
    test("replica intent survives interrupted sequence burn, packet preparation and attempted publication", [] {
        for (const unsigned journalCommit : {0u, 1u, 2u, 3u, 4u}) {
            ReplicaPair pair;
            const auto local = textSnapshot("durable publication payload");
            pair.first.edit(local);
            auto &store = pair.fixture.store(1);
            bool faultArmed = false;
            const auto expectedError = journalCommit == 0 ? st::ErrorCode::Io : st::ErrorCode::CommitUnconfirmed;
            rejects<st::Error>(expectedError, [&] {
                pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
                    if (!state.pending || faultArmed) return;
                    faultArmed = true;
                    store.deferredCommits = journalCommit ? journalCommit - 1 : 0;
                    store.failure = journalCommit ? MemoryStore::Fault::After : MemoryStore::Fault::Before;
                });
            });
            {
                const auto interrupted = pair.first.mount();
                CHECK(faultArmed && interrupted->replica().pending && interrupted->snapshot() == local);
            }
            const auto beforeRetry = pair.packets();
            CHECK(beforeRetry.size() == (journalCommit == 4 ? 2u : 1u));
            pair.fixture.reopen(1);
            auto &journal = pair.fixture.journal(1);
            const auto interrupted = journal.inspect();
            CHECK(interrupted.allocatedEventSequence == (journalCommit ? 1u : 0u));
            if (journalCommit > 0 && journalCommit < 4) {
                CHECK(interrupted.pendingEvent && interrupted.pendingEvent->ready == (journalCommit >= 2));
                CHECK(interrupted.pendingEvent->publicationAttempted == (journalCommit == 3));
                refuses([&] { journal.resumeClipboardEvent(1, Now); });
                refuses([&] { journal.discardClipboardEvent(1, Now); });
                refuses([&] { journal.publishClipboardEvent(1, *pair.fixture.key, pair.transport.directory(), Now); });
            } else {
                CHECK(!interrupted.pendingEvent);
            }
            CHECK(pair.first.sync() == SignedReplicaResult::Published);
            const auto finished = pair.first.mount();
            CHECK(!finished->replica().pending && finished->snapshot() == local);
            const auto afterRetry = pair.packets();
            CHECK(afterRetry.size() == 2);
            const auto &published = packet(afterRetry, finished->replica().cursor.id);
            if (beforeRetry.size() == 2) CHECK(packet(beforeRetry, published.id).wire == published.wire);
            const auto &revision = SignedEventCodec::inspect(published.wire).revision;
            CHECK(revision.sequence == (journalCommit == 1 ? 2u : 1u));
            CHECK(pair.fixture.journal(1).inspect().eventEncryptionAttempts == revision.sequence);
            CHECK(pair.second.sync() == SignedReplicaResult::Pulled && pair.second.mount()->snapshot() == local);
        }
    });
    test("replica synchronization refuses substituted provenance and an unrelated journal slot", [] {
        ReplicaPair pair;
        const auto local = textSnapshot("preserve this edit");
        pair.first.edit(local);
        const auto original = pair.first.mount()->replica();
        const auto checkpointGeneration = pair.first.mount()->generation();
        auto &journal = pair.fixture.journal(1);
        const auto reject = [&](const JoinActivation &activation, const SignedReplicaState &state) {
            refuses([&] {
                journal.synchronizeReplica(*pair.fixture.identities[1], pair.transport.directory(), activation, state,
                    local, Now, [](const SignedReplicaState &, const tx::Snapshot &) { CHECK(false); });
            });
        };
        auto changed = pair.first.activation;
        changed.generation++;
        reject(changed, original);
        changed = pair.first.activation;
        changed.tipDigest.front() ^= 1;
        reject(changed, original);
        auto changedCursor = original;
        changedCursor.cursor.digest.front() ^= 1;
        reject(pair.first.activation, changedCursor);
        const auto unrelated = journal.prepareClipboardEvent(*pair.fixture.identities[1], *pair.fixture.key,
            {{pair.initialTip, pair.first.activation.tipDigest}}, ValidItems, Now);
        reject(pair.first.activation, original);
        auto mismatched = original;
        mismatched.pending = SignedReplicaIntent{unrelated.sequence, token(91)};
        reject(pair.first.activation, mismatched);
        CHECK(journal.resumeClipboardEvent(unrelated.sequence, Now).wire == unrelated.wire);
        const auto mounted = pair.first.mount();
        CHECK(mounted->generation() == checkpointGeneration && mounted->snapshot() == local);
        CHECK(pair.packets().size() == 1);
    });
    test("post-rotation recovery retires the exact intent without writing the old transport", [] {
        for (const unsigned barrier : {0u, 1u, 2u, 3u, 4u, 5u}) {
            ReplicaPair pair;
            const auto original = textSnapshot("old pending contents");
            const auto latest = textSnapshot("keep these newer local edits after rotation");
            pair.first.edit(original);
            auto &store = pair.fixture.store(1);
            const bool beforeCommit = barrier == 0 || barrier == 5;
            rejects<st::Error>(beforeCommit ? st::ErrorCode::Io : st::ErrorCode::CommitUnconfirmed, [&] {
                pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
                    CHECK(state.pending);
                    store.deferredCommits = barrier == 5 ? 3 : (barrier ? barrier - 1 : 0);
                    store.failure = beforeCommit ? MemoryStore::Fault::Before : MemoryStore::Fault::After;
                });
            });
            pair.fixture.reopen(1);
            const auto reserved = pair.fixture.journal(1).inspect();
            CHECK(reserved.allocatedEventSequence == (barrier ? 1u : 0u));
            CHECK(pair.first.mount()->replica().pending);
            pair.first.edit(latest);
            rotateReplicaKey(pair, 2);
            pair.fixture.reopen(1);
            const auto files = pair.packets();
            CHECK(files.size() == (barrier >= 4 ? 2u : 1u));

            if (reserved.pendingEvent) {
                const auto mounted = pair.first.mount();
                auto substituted = mounted->replica();
                substituted.pending->payload.front() ^= 1;
                rejects<JournalError>(JournalCode::EventReservation, [&] {
                    pair.fixture.journal(1).recoverRotatedReplica(*pair.fixture.identities[1], pair.first.activation,
                        substituted, latest, Now, [](const SignedReplicaState &, const tx::Snapshot &) { CHECK(false); });
                });
            }
            if (reserved.pendingEvent) {
                store.failure = MemoryStore::Fault::After;
                rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { pair.first.recoverRotation(); });
                pair.fixture.reopen(1);
                const auto mounted = pair.first.mount();
                auto substituted = mounted->replica();
                substituted.pending->payload.front() ^= 1;
                rejects<JournalError>(JournalCode::EventReservation, [&] {
                    pair.fixture.journal(1).recoverRotatedReplica(*pair.fixture.identities[1], pair.first.activation,
                        substituted, latest, Now, [](const SignedReplicaState &, const tx::Snapshot &) { CHECK(false); });
                });
            }
            rejects<st::Error>(st::ErrorCode::Io, [&] {
                pair.first.recoverRotation([&](const SignedReplicaState &state, const tx::Snapshot &snapshot) {
                    CHECK(!state.pending && snapshot == latest && state.cursor.id == pair.initialTip);
                    throw st::Error(st::ErrorCode::Io, "Injected before checkpoint retirement");
                });
            });
            CHECK(pair.first.mount()->replica().pending);
            const auto expected = barrier < 3 ? SignedReplicaRecovery::RetiredUnattempted :
                (barrier == 4 ? SignedReplicaRecovery::RetiredConfirmedPublished : SignedReplicaRecovery::RetiredPossiblyPublished);
            CHECK(pair.first.recoverRotation() == expected);
            CHECK(pair.first.recoverRotation() == SignedReplicaRecovery::NothingPending);
            {
                const auto mounted = pair.first.mount();
                CHECK(mounted->snapshot() == latest && !mounted->replica().pending);
                CHECK(mounted->replica().cursor.id == pair.initialTip);
                CHECK(mounted->replica().cursor.digest == pair.first.activation.tipDigest);
            }
            const auto recovered = pair.fixture.journal(1).inspect();
            CHECK(!recovered.pendingEvent && recovered.allocatedEventSequence == reserved.allocatedEventSequence);
            CHECK(recovered.eventEncryptionAttempts == 0);
            CHECK(pair.packets().size() == files.size());
            for (const auto &file : files) CHECK(packet(pair.packets(), file.id).wire == file.wire);
            refuses([&] { pair.first.sync(); });
        }
    });
    test("post-rotation recovery refuses removed members, membership forks and unrelated slots", [] {
        {
            ReplicaPair pair;
            const auto local = textSnapshot("removed device keeps local data");
            pair.first.edit(local);
            auto &store = pair.fixture.store(1);
            rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] {
                pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
                    CHECK(state.pending);
                    store.failure = MemoryStore::Fault::After;
                });
            });
            pair.fixture.reopen(1);
            rotateReplicaKey(pair, 1);
            const auto prior = st::serialize(store.record);
            refuses([&] {
                pair.first.recoverRotation([](const SignedReplicaState &, const tx::Snapshot &) { CHECK(false); });
            });
            CHECK(st::serialize(store.record) == prior && pair.packets().size() == 1);
            const auto mounted = pair.first.mount();
            CHECK(mounted->snapshot() == local && mounted->replica().pending);
        }
        {
            ReplicaPair pair;
            auto &fixture = pair.fixture;
            auto &journal = fixture.journal(1);
            const auto otherKey = SyncKey::generate();
            const auto sibling = fixture.journal(0).propose(Operation::Remove, fixture.member(1), token(41), token(42),
                Now, Expires, otherKey->commitment(fixture.genesis.group, 1));
            Certificate fork{sibling, {}};
            for (std::size_t signer : {0u, 2u}) {
                fork.approvals.push_back({fixture.member(signer).id,
                    fixture.identities[signer]->sign(approvalBytes(sibling, fixture.member(signer)))});
            }
            rotateReplicaKey(pair, 2);
            CHECK(journal.observe(fork, Now) == ObserveResult::ForkDetected);
            const auto prior = st::serialize(fixture.store(1).record);
            refuses([&] {
                pair.first.recoverRotation([](const SignedReplicaState &, const tx::Snapshot &) { CHECK(false); });
            });
            CHECK(st::serialize(fixture.store(1).record) == prior && pair.packets().size() == 1);
        }
        {
            ReplicaPair pair;
            auto &journal = pair.fixture.journal(1);
            const auto unrelated = journal.prepareClipboardEvent(*pair.fixture.identities[1], *pair.fixture.key,
                {{pair.initialTip, pair.first.activation.tipDigest}}, ValidItems, Now);
            rotateReplicaKey(pair, 2);
            auto mounted = pair.first.mount();
            auto falseIntent = mounted->replica();
            falseIntent.pending = SignedReplicaIntent{unrelated.sequence, token(91)};
            const auto prior = st::serialize(pair.fixture.store(1).record);
            rejects<JournalError>(JournalCode::EventReservation, [&] {
                journal.recoverRotatedReplica(*pair.fixture.identities[1], pair.first.activation, falseIntent,
                    mounted->snapshot(), Now, [](const SignedReplicaState &, const tx::Snapshot &) { CHECK(false); });
            });
            CHECK(st::serialize(pair.fixture.store(1).record) == prior && pair.packets().size() == 1);
        }
    });
    test("older rotated journals with no attempt evidence report a possible publication", [] {
        ReplicaPair pair;
        const auto local = textSnapshot("legacy rotated pending data");
        pair.first.edit(local);
        auto &store = pair.fixture.store(1);
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] {
            pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
                CHECK(state.pending);
                store.deferredCommits = 2;
                store.failure = MemoryStore::Fault::After;
            });
        });
        pair.fixture.reopen(1);
        rotateReplicaKey(pair, 2);

        // Reconstruct the v8 shape emitted when older code applied rotation
        // and discarded the old ledger without saving its attempt evidence.
        auto &wire = store.record.local->front().begin()->second;
        constexpr char domain[] = "CopyQ-Secure-Sync-trust-journal-lab-v1";
        constexpr auto version = sizeof(domain) + 3;
        constexpr auto evidenceBytes = Token{}.size() + sizeof(std::uint64_t) + 1;
        const auto flag = wire.size() - evidenceBytes - Token{}.size() - 1;
        CHECK(wire[version] == 9 && wire[flag] == 1);
        wire[version] = 8;
        wire.resize(wire.size() - evidenceBytes);
        wire.erase(wire.begin() + static_cast<std::ptrdiff_t>(flag));
        pair.fixture.reopen(1);

        CHECK(pair.first.recoverRotation() == SignedReplicaRecovery::RetiredPossiblyPublished);
        const auto mounted = pair.first.mount();
        CHECK(mounted->snapshot() == local && !mounted->replica().pending && pair.packets().size() == 1);
    });
    test("a locally accepted removal and key rotation stops the old generation", [] {
        ReplicaPair pair;
        const auto local = textSnapshot("stay local after rotation");
        pair.first.edit(local);
        const auto previous = pair.first.mount()->generation();
        rotateReplicaKey(pair, 2);
        refuses([&] { pair.first.sync(); });
        const auto mounted = pair.first.mount();
        CHECK(mounted->generation() == previous && mounted->snapshot() == local && !mounted->replica().pending);
        CHECK(pair.packets().size() == 1);
    });
#ifdef CQS_TEST_NATIVE_SIGNED_JOIN
    test("the native wizard confirms the exact signed conflict choice and archives the previous local copy", [] {
        exerciseNativeConflictWizard();
    });
    test("the native wizard confirms and writes the signed checkpoint without a legacy write", [] {
        exerciseNativeWizard(WizardActivation::NoCallback);
    });
    test("the native wizard activates only after a separate confirmation and fresh checkpoint verification", [] {
        exerciseNativeWizard(WizardActivation::Accept);
    });
    test("declining native tab activation keeps the verified signed checkpoint", [] {
        exerciseNativeWizard(WizardActivation::Decline);
    });
    test("a new signed tip during native tab confirmation refuses activation and keeps the checkpoint", [] {
        exerciseNativeWizard(WizardActivation::AdvanceTip);
    });
    test("the native Sync wizard preserves protected rows and pulls only after permission", [] {
        ReplicaPair pair;
        const auto local = cqs::packed::decode(ValidItems);
        const auto remote = textSnapshot("remote edit offered in native wizard");
        pair.first.edit(remote);
        CHECK(pair.first.sync() == SignedReplicaResult::Published);
        const auto generation = pair.second.mount()->generation();
        exerciseNativeReplicaWizard(pair.second, local, remote, false);
        {
            const auto second = pair.second.mount();
            CHECK(second->generation() == generation && second->snapshot() == local);
            CHECK(second->replica().cursor.id == pair.initialTip);
        }
        exerciseNativeReplicaWizard(pair.second, local, remote, true);
        const auto second = pair.second.mount();
        CHECK(second->generation() == generation + 1 && second->snapshot() == remote);
        CHECK(second->replica().cursor.id == pair.first.mount()->replica().cursor.id);
        CHECK(pair.packets().size() == 2);
    });
    test("the native wizard arms signed background synchronization only after explicit consent", [] {
        ReplicaPair pair;
        const auto generation = pair.first.mount()->generation();
        exerciseNativeBackgroundConsent(pair, false);
        exerciseNativeBackgroundConsent(pair, true);
        CHECK(pair.first.mount()->generation() == generation && pair.packets().size() == 1);
    });
    test("the native wizard reports uncertain old publication and preserves local edits after rotation", [] {
        ReplicaPair pair;
        pair.first.edit(textSnapshot("old native pending contents"));
        auto &store = pair.fixture.store(1);
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] {
            pair.first.sync([&](const SignedReplicaState &state, const tx::Snapshot &) {
                CHECK(state.pending);
                store.deferredCommits = 2;
                store.failure = MemoryStore::Fault::After;
            });
        });
        pair.fixture.reopen(1);
        const auto latest = textSnapshot("new local edit before using native recovery");
        pair.first.edit(latest);
        rotateReplicaKey(pair, 2);
        CHECK(pair.first.mount()->replica().pending);
        exerciseNativeRotationRecovery(pair);
        const auto mounted = pair.first.mount();
        CHECK(mounted->snapshot() == latest && !mounted->replica().pending);
        CHECK(mounted->replica().cursor.id == pair.initialTip && pair.packets().size() == 1);
        CHECK(!pair.fixture.journal(1).inspect().pendingEvent);
    });
#endif
#endif
    std::cout << cases << " device Join test cases passed\n";
}
