// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_generation_wizard.h"
#include "signed_setup.h"
#include "signed_join_checkpoint.h"
#include "packed_items.h"
#include "storage.h"
#include "test_check.h"
#include <QAbstractButton>
#include <QApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QTimer>
#include <QtEndian>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <utility>
#include <vector>
#ifdef _WIN32
#include "windows_test_acl.h"
#endif

namespace {
using namespace cqs::trust;
using cqs::crypto::Bytes;
namespace fs = std::filesystem;
namespace tx = cqs::transaction;
namespace state = cqs::state;
namespace storage = cqs::storage;
namespace native = cqs::native;

fs::path path(const QString &value) {
#ifdef _WIN32
    return fs::path(value.toStdWString());
#else
    return fs::u8path(value.toUtf8().toStdString());
#endif
}
QString text(const fs::path &value) {
#ifdef _WIN32
    return QDir::fromNativeSeparators(QString::fromStdWString(value.wstring()));
#else
    const auto bytes = value.u8string();
    return QString::fromUtf8(bytes.data(), qsizetype(bytes.size()));
#endif
}
void directory(const fs::path &value) {
#ifdef _WIN32
    cqs::testing::directory(value);
#else
    CHECK(fs::create_directory(value));
    fs::permissions(value, fs::perms::owner_all);
#endif
}
void write(const fs::path &value, const std::string &bytes) {
#ifdef _WIN32
    cqs::testing::write(value, bytes);
#else
    std::ofstream output(value, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), std::streamsize(bytes.size()));
    output.close();
    CHECK(output);
    fs::permissions(value, fs::perms::owner_read | fs::perms::owner_write);
#endif
}
std::string read(const fs::path &value) {
    std::ifstream input(value, std::ios::binary);
    CHECK(input.is_open());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
Token token(unsigned value) {
    Token result{};
    result.back() = std::uint8_t(value);
    return result;
}
tx::Snapshot snapshot(const std::string &value, std::size_t count = 1) {
    return tx::Snapshot(count, {{"text/plain", Bytes(value.begin(), value.end())}});
}

class MemoryStore final : public tx::Store {
public:
    explicit MemoryStore(tx::Record initial) : record(std::move(initial)) {}
    std::unique_ptr<Lease> lock() override {
        if (held_) return {};
        struct Held final : Lease {
            explicit Held(bool &held) : held(held) { held = true; }
            ~Held() override { held = false; }
            bool &held;
        };
        return std::make_unique<Held>(held_);
    }
    tx::Record load() override { CHECK(held_); return record; }
    void commit(const tx::Record &before, const tx::Record &after) override {
        CHECK(held_ && state::serialize(record) == state::serialize(before));
        CHECK(after.generation == before.generation + 1);
        record = after;
    }
    tx::Record record;
private:
    bool held_ = false;
};

struct Fixture {
    const std::uint64_t now = std::uint64_t(QDateTime::currentSecsSinceEpoch());
    std::unique_ptr<SyncKey> key = SyncKey::generate();
    std::array<std::unique_ptr<Identity>, 3> identities;
    Genesis genesis;
    std::array<std::unique_ptr<MemoryStore>, 3> stores;
    std::array<std::unique_ptr<TrustJournal>, 3> journals;
    const fs::path root = SignedSetup::createPrivateRoot(fs::temp_directory_path());
    const fs::path transportRoot = root / "transport";
    fs::path staging;
    std::unique_ptr<storage::Directory> transport;

    Fixture() {
        CHECK(now > 0);
        for (auto &identity : identities) identity = Identity::generate();
        genesis = {token(1), identities[0]->member(), token(2), key->commitment(token(1), 0)};
        for (std::size_t i = 0; i < stores.size(); ++i) {
            stores[i] = std::make_unique<MemoryStore>(TrustJournal::initialRecord(genesis, identities[i]->member(), now));
            journals[i] = std::make_unique<TrustJournal>(*stores[i], genesis, identities[i]->member());
        }
        enroll(1, {0});
        install(*key);
        enroll(2, {0, 1});
        directory(transportRoot);
        directory(transportRoot / "events");
        scope();
#ifdef _WIN32
        staging = root / "staging";
        directory(staging);
#endif
        transport = std::make_unique<storage::Directory>(transportRoot);
    }
    ~Fixture() {
        transport.reset();
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }
    TrustJournal &journal(std::size_t i) { return *journals[i]; }
    void enroll(std::size_t applicant, const std::vector<std::size_t> &signers) {
        const auto requested = journal(applicant).beginJoin(*identities[applicant], now);
        const auto proposal = journal(0).proposeJoin(requested, now, now + 600);
        Certificate certificate{proposal, {}};
        std::vector<Token> selected;
        for (const auto signer : signers) {
            selected.push_back(identities[signer]->member().id);
            const auto review = journal(signer).reviewJoinApproval(proposal, now);
            certificate.approvals.push_back(journal(signer).approve(proposal, *identities[signer], review.approvers.front().digest, now));
        }
        const auto review = journal(applicant).reviewJoin(proposal, selected, now);
        std::vector<JoinConfirmation> confirmed;
        for (const auto &approver : review.approvers) confirmed.push_back({approver.member.id, approver.digest});
        CHECK(journal(applicant).acceptJoin(certificate, confirmed, now) == ObserveResult::Applied);
        for (std::size_t i = 0; i < journals.size(); ++i)
            if (i != applicant) CHECK(journal(i).observe(certificate, now) == ObserveResult::Applied);
    }
    void install(const SyncKey &current) {
        const auto wire = journal(0).prepareDelivery(identities[1]->member().id, *identities[0], current, now);
        CHECK(journal(0).recordReceipt(journal(1).installDelivery(wire, *identities[1], now), now));
    }
    storage::SignedEventScope scope() {
        const auto current = journal(0).inspect().state;
        const storage::SignedEventScope result{current.group, current.root, current.keyGeneration};
        directory(transportRoot / storage::signedEventFolderName(result));
        return result;
    }
    void seed(const SyncKey &current, const tx::Snapshot &value) {
        const auto event = journal(0).prepareClipboardEvent(*identities[0], current, {}, cqs::packed::encode(value), now);
        CHECK(!journal(0).publishClipboardEvent(event.sequence, current, *transport, now, ClipboardPublication::Seed, staging).empty());
    }
    std::unique_ptr<SyncKey> rotate() {
        auto current = SyncKey::generate();
        const auto proposal = journal(0).propose(Operation::Remove, identities[2]->member(), token(3), token(4),
            now, now + 600, current->commitment(genesis.group, 1));
        Certificate certificate{proposal, {}};
        for (const auto signer : {0u, 1u})
            certificate.approvals.push_back(journal(signer).approve(proposal, *identities[signer],
                verificationDigest(proposal, identities[signer]->member()), now));
        for (std::size_t i = 0; i < journals.size(); ++i) CHECK(journal(i).observe(certificate, now) == ObserveResult::Applied);
        install(*current);
        scope();
        return current;
    }
};
}

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    Fixture fixture;
    const auto sourcePath = SignedSetup::createPrivateRoot(fixture.root);
    const auto destination = SignedSetup::createPrivateRoot(fixture.root);
    const auto journalPath = SignedSetup::createPrivateRoot(fixture.root);
    const auto credentialPath = fixture.root / "checkpoint.key";
    const Bytes credential(32, 0x71);
    write(credentialPath, std::string(credential.begin(), credential.end()));
    const auto settingsPath = fixture.root / "profile.ini";
    QSettings settings(text(settingsPath), QSettings::IniFormat);
    settings.setValue("Options/maxitems", 100);
    settings.sync();
    CHECK(settings.status() == QSettings::NoError);
    const auto settingsFile = QFileInfo(text(settingsPath)).canonicalFilePath();
    const auto journalBinding = TrustJournal::binding(fixture.genesis, fixture.identities[1]->member());
    const auto binding = native::signedTabBinding(settingsFile, text(sourcePath), journalBinding);
    fixture.seed(*fixture.key, snapshot("original signed view"));
    const auto proof = fixture.journal(1).preflightJoinActivation(*fixture.identities[1], *fixture.transport, binding, fixture.now);
    SignedJoinCheckpoint source(sourcePath, credential, binding);
    fixture.journal(1).applyJoinActivation(*fixture.identities[1], *fixture.transport, proof, fixture.now,
        [&](const auto &verified, const auto &tip, const auto &value) { source.apply(verified, tip, value); });
    const auto local = snapshot("protected local row");
    {
        auto mounted = source.mount(proof);
        mounted->save(local, mounted->generation());
    }
    const auto sourceBytes = read(sourcePath / state::FileStore::RecordName);
    const auto rotated = fixture.rotate();
    const auto remote = snapshot("different remote generation", 2);
    fixture.seed(*rotated, remote);
    const native::SignedTabConfiguration current{text(sourcePath), text(credentialPath), proof};
    const native::SignedReplicaSource replicaSource{text(fixture.transportRoot), text(journalPath)};
    const auto encoded = native::encodeSignedTab(current, journalBinding);
    const auto pin = native::signedReplicaSourcePin(proof.profileBinding, replicaSource);
    CHECK(native::decodeSignedTab(settingsFile, encoded) && pin.size() == 32);
    settings.setValue("Plugins/securesync/active_signed_tab", encoded);
    settings.setValue("Plugins/securesync/signed_replica_source", pin);
    settings.setValue("Plugins/securesync/signed_generation_destination", QJsonDocument(QJsonObject{
        {"active", QString::fromLatin1(encoded.toBase64())}, {"destination", text(destination)}
    }).toJson(QJsonDocument::Compact));
    settings.sync();
    app.setProperty("CopyQ_item_data_path", text(fixture.root / "items"));
    QByteArray marker = native::SignedTabPreamble + QByteArrayLiteral("CQSSGN01") + native::signedTabMarkerIdentity(proof);
    const auto generation = qToBigEndian<quint64>(source.mount(proof)->generation());
    marker.append(reinterpret_cast<const char *>(&generation), sizeof(generation));
    write(path(native::signedTabCachePath()), marker.toStdString());

    unsigned validationCalls = 0;
    for (const auto mode : {0u, 1u, 2u}) {
        unsigned confirmations = 0;
        QTimer responder;
        QObject::connect(&responder, &QTimer::timeout, [&] {
            auto *message = qobject_cast<QMessageBox *>(QApplication::activeModalWidget());
            if (!message) return;
            CHECK(message->windowTitle().contains(confirmations == 0 ? QStringLiteral("resume generation") : QStringLiteral("activate accepted")));
            CHECK(confirmations < 2);
            if (confirmations == 1) CHECK(message->defaultButton() == message->button(QMessageBox::No) && message->textFormat() == Qt::PlainText);
            ++confirmations;
            CHECK(message->button(QMessageBox::Yes));
            message->button(QMessageBox::Yes)->click();
        });
        responder.start(2);
        const auto beforeCalls = validationCalls;
        const native::SignedReplicaRequest request{proof, mode == 1 ? 1 : 100, true,
            [&] { return native::confirmSignedReplicaSource(settingsFile, encoded, pin, false); },
            [&](const auto &before, const auto &after) {
                CHECK(before == local && after == remote);
                ++validationCalls;
                return mode == 2;
            }};
        bool refused = false;
        bool activated = false;
        try {
            activated = native::runSignedGenerationWizard(nullptr, fixture.journal(1), *fixture.identities[1],
                *fixture.transport, source, credential, settingsFile, journalBinding, replicaSource, request,
                fixture.staging, [] { return true; });
        } catch (const JournalError &error) {
            CHECK(error.code() == JournalCode::Enrollment && mode != 2);
            refused = true;
        }
        CHECK(confirmations == 2 && read(sourcePath / state::FileStore::RecordName) == sourceBytes);
        CHECK(validationCalls == beforeCalls + (mode == 1 ? 0u : 1u));
        CHECK(read(path(native::signedTabCachePath())) == marker.toStdString());
        CHECK(!fixture.journal(1).inspect().pendingEvent);
        if (mode != 2) {
            CHECK(refused && !activated && !fs::exists(destination / state::FileStore::RecordName));
            CHECK(settings.value("Plugins/securesync/active_signed_tab").toByteArray() == encoded);
            CHECK(settings.value("Plugins/securesync/signed_replica_source").toByteArray() == pin);
            CHECK(source.mount(proof)->snapshot() == local);
        } else {
            CHECK(activated && !refused);
            const auto successor = native::decodeSignedTab(settingsFile, settings.value("Plugins/securesync/active_signed_tab").toByteArray());
            CHECK(successor && successor->checkpointDirectory == text(destination));
            SignedJoinCheckpoint checkpoint(destination, credential, successor->expected.profileBinding);
            const auto mounted = checkpoint.mount(successor->expected);
            CHECK(mounted->snapshot() == remote && mounted->conflictBackupCount() == 1 && mounted->conflictBackup(0) == local);
        }
    }
    std::cout << "Native signed generation policy checks passed\n";
}
