// SPDX-License-Identifier: GPL-3.0-or-later
// Disposable qualification fixtures. Never accepts a real user profile.
#include "device_identity_vault.h"
#include "device_key_envelope.h"
#include "device_trust_journal.h"
#include "key_reader.h"
#include "packed_items.h"
#include "signed_join_checkpoint.h"
#include "signed_tab_activation.h"
#include "storage.h"
#include "test_check.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QTemporaryDir>
#include <algorithm>
#include <array>
#include <filesystem>
#include <iostream>
#ifdef Q_OS_WIN
#include "windows_test_acl.h"
#else
#include <sys/stat.h>
#endif

namespace {
using namespace cqs::trust;
using cqs::crypto::Bytes;
namespace fs = std::filesystem;
namespace state = cqs::state;
namespace tx = cqs::transaction;
namespace storage = cqs::storage;
constexpr auto Manifest = "signed-fixture.json";

fs::path path(const QString &text) {
#ifdef Q_OS_WIN
    return fs::path(text.toStdWString());
#else
    return fs::u8path(text.toUtf8().toStdString());
#endif
}
std::uint64_t now() { return std::uint64_t(QDateTime::currentSecsSinceEpoch()); }
void protect(const QString &name) {
#ifdef Q_OS_WIN
    cqs::testing::WindowsAcl{}.apply(path(name));
#else
    CHECK(::chmod(QFile::encodeName(name).constData(), 0700) == 0);
#endif
}
void directory(const QString &name) {
#ifdef Q_OS_WIN
    cqs::testing::directory(path(name));
#else
    CHECK(QDir().mkdir(name));
    protect(name);
#endif
}
void write(const QString &name, const QByteArray &bytes) {
#ifdef Q_OS_WIN
    cqs::testing::write(path(name), bytes.toStdString());
#else
    QFile file(name);
    CHECK(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    CHECK(file.write(bytes) == bytes.size());
    file.close();
    CHECK(::chmod(QFile::encodeName(name).constData(), 0600) == 0);
#endif
}
QByteArray read(const QString &name) {
    QFile file(name);
    CHECK(file.open(QIODevice::ReadOnly));
    CHECK(file.size() <= 32 * 1024 * 1024);
    return file.readAll();
}
QByteArray bytes(const Bytes &value) {
    return QByteArray(reinterpret_cast<const char *>(value.data()), qsizetype(value.size()));
}
QString hex(const Token &value) {
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(value.data()), value.size()).toHex());
}
Token token(const QString &value) {
    const auto encoded = value.toLatin1();
    const auto raw = QByteArray::fromHex(encoded);
    CHECK(raw.size() == 32 && raw.toHex() == encoded);
    Token result{};
    std::copy(raw.begin(), raw.end(), result.begin());
    return result;
}
Token randomToken() {
    const auto raw = cqs::crypto::random(32);
    Token result{};
    std::copy(raw.begin(), raw.end(), result.begin());
    return result;
}
QJsonObject memberJson(const Member &m) {
    return {{"id", hex(m.id)}, {"signing", hex(m.signingKey)}, {"encryption", hex(m.encryptionKey)}};
}
Member member(const QJsonObject &m) {
    return {token(m.value("id").toString()), token(m.value("signing").toString()), token(m.value("encryption").toString())};
}
QJsonObject genesisJson(const Genesis &g) {
    return {{"group", hex(g.group)}, {"founder", memberJson(g.founder)}, {"recovery", hex(g.recovery)},
            {"commitment", hex(g.initialKeyCommitment)}};
}
Genesis genesis(const QJsonObject &g) {
    return {token(g.value("group").toString()), member(g.value("founder").toObject()),
            token(g.value("recovery").toString()), token(g.value("commitment").toString())};
}
tx::Snapshot snapshot(const QString &label) {
    const auto text = QStringLiteral("CQS_SIGNED_QUALIFICATION_") + label;
    const auto raw = text.toUtf8();
    return {{{"text/plain", Bytes(raw.begin(), raw.end())}}};
}
std::vector<JoinConfirmation> confirmations(const JoinReview &review) {
    std::vector<JoinConfirmation> result;
    for (const auto &peer : review.approvers) result.push_back({peer.member.id, peer.digest});
    return result;
}
fs::path staging(const QString &root) {
#ifdef Q_OS_WIN
    return path(root + "/staging");
#else
    Q_UNUSED(root)
    return {};
#endif
}
QJsonObject manifest(const QString &root) {
    CHECK(QFileInfo(root).fileName().startsWith("cqs-signed-") && QFileInfo(root).isDir() && !QFileInfo(root).isSymLink());
    const auto data = QJsonDocument::fromJson(read(root + '/' + Manifest)).object();
    CHECK(data.value("format").toString() == "copyq-signed-qualification-v1");
    return data;
}

struct Device {
    QString folder, settings;
    Genesis pins;
    Member local;
    Bytes vaultKey, journalKey, checkpointKey;
    std::unique_ptr<Identity> identity;
    std::unique_ptr<state::FileStore> store;
    std::unique_ptr<TrustJournal> journal;
    std::unique_ptr<storage::Directory> transport;
    std::optional<cqs::native::SignedTabConfiguration> configuration;
    std::unique_ptr<SignedJoinCheckpoint> checkpoint;

    Device(const QString &root, const QString &name) {
        CHECK(name == "a" || name == "b");
        const auto data = manifest(root);
        folder = root + '/' + name;
        pins = genesis(data.value("genesis").toObject());
        const auto own = data.value(name).toObject();
        local = member(own.value("member").toObject());
        settings = own.value("settings").toString();
        vaultKey = cqs::native::readKeyStrict(path(folder + "/credentials/identity.key"));
        journalKey = cqs::native::readKeyStrict(path(folder + "/credentials/journal.key"));
        checkpointKey = cqs::native::readKeyStrict(path(folder + "/credentials/checkpoint.key"));
        const Membership initial(pins.group, pins.founder, pins.recovery, pins.initialKeyCommitment);
        identity = IdentityVault::load(path(folder + "/identity"), {pins.group, initial.current().root, local}, vaultKey);
        store = std::make_unique<state::FileStore>(path(folder + "/journal"), TrustJournal::binding(pins, local), journalKey);
        journal = std::make_unique<TrustJournal>(*store, pins, local);
        transport = std::make_unique<storage::Directory>(path(folder + "/transport"));
        QSettings profile(settings, QSettings::IniFormat);
        configuration = cqs::native::decodeSignedTab(settings, profile.value("Plugins/securesync/active_signed_tab").toByteArray());
        CHECK(configuration);
        checkpoint = std::make_unique<SignedJoinCheckpoint>(path(folder + "/checkpoint"), checkpointKey,
                                                           configuration->expected.profileBinding);
    }
    ~Device() {
        cqs::crypto::wipe(vaultKey);
        cqs::crypto::wipe(journalKey);
        cqs::crypto::wipe(checkpointKey);
    }
    SignedReplicaResult sync() {
        auto mounted = checkpoint->mount(configuration->expected);
        const auto localCopy = mounted->snapshot();
        return journal->synchronizeReplica(*identity, *transport, configuration->expected, mounted->replica(), localCopy, now(),
            [&](const SignedReplicaState &replica, const tx::Snapshot &contents) {
                mounted->updateReplica(replica, contents, mounted->generation());
            }, staging(folder));
    }
    void verify(const QString &label) {
        const auto mounted = checkpoint->mount(configuration->expected);
        CHECK(mounted->snapshot() == snapshot(label));
    }
    void edit(const QString &label) {
        const auto mounted = checkpoint->mount(configuration->expected);
        mounted->save(snapshot(label), mounted->generation());
    }
};

void seed(const QString &root, const QString &settingsA, const QString &settingsB) {
    CHECK(QFileInfo(root).fileName().startsWith("cqs-signed-") && QFileInfo(root).isDir() &&
          !QFileInfo(root).isSymLink() && !QFile::exists(root + '/' + Manifest));
    protect(root);
    const auto key = SyncKey::generate();
    std::array<std::unique_ptr<Identity>, 3> identities;
    for (auto &identity : identities) identity = Identity::generate();
    const auto group = randomToken();
    const Genesis pins{group, identities[0]->member(), randomToken(), key->commitment(group, 0)};
    const Membership initial(pins.group, pins.founder, pins.recovery, pins.initialKeyCommitment);
    std::array<Bytes, 3> journalKeys, vaultKeys, checkpointKeys;
    std::array<std::unique_ptr<state::FileStore>, 3> stores;
    std::array<std::unique_ptr<TrustJournal>, 3> journals;
    QJsonObject data{{"format", "copyq-signed-qualification-v1"}, {"genesis", genesisJson(pins)}};
    const std::array<QString, 3> names{"founder", "a", "b"};
    for (std::size_t i = 0; i < names.size(); ++i) {
        const auto folder = root + '/' + names[i];
        directory(folder);
        directory(folder + "/journal");
        journalKeys[i] = cqs::crypto::random(32);
        stores[i] = std::make_unique<state::FileStore>(path(folder + "/journal"), TrustJournal::binding(pins, identities[i]->member()), journalKeys[i]);
        TrustJournal::initialize(*stores[i], pins, identities[i]->member(), now());
        journals[i] = std::make_unique<TrustJournal>(*stores[i], pins, identities[i]->member());
        if (!i) continue;
        for (const auto &child : {"identity", "checkpoint", "credentials", "transport", "staging"}) directory(folder + '/' + child);
        directory(folder + "/transport/events");
        directory(folder + "/transport/control");
        vaultKeys[i] = cqs::crypto::random(32);
        checkpointKeys[i] = cqs::crypto::random(32);
        IdentityVault::initialize(path(folder + "/identity"), {pins.group, initial.current().root, identities[i]->member()}, vaultKeys[i], *identities[i]);
        write(folder + "/credentials/identity.key", bytes(vaultKeys[i]));
        write(folder + "/credentials/journal.key", bytes(journalKeys[i]));
        write(folder + "/credentials/checkpoint.key", bytes(checkpointKeys[i]));
    }
    for (std::size_t applicant : {1u, 2u}) {
        if (applicant == 2) {
            const auto status = journals[0]->inspect();
            for (const auto &wire : status.certificates) journals[2]->observe(decodeCertificate(wire), now());
        }
        const auto request = journals[applicant]->beginJoin(*identities[applicant], now());
        const auto proposal = journals[0]->proposeJoin(request, now(), now() + 900);
        Certificate certificate{proposal, {}};
        std::vector<Token> signers;
        for (std::size_t signer = 0; signer < applicant; ++signer) {
            const auto review = journals[signer]->reviewJoinApproval(proposal, now());
            certificate.approvals.push_back(journals[signer]->approve(proposal, *identities[signer], review.approvers.front().digest, now()));
            signers.push_back(identities[signer]->member().id);
        }
        const auto review = journals[applicant]->reviewJoin(proposal, signers, now());
        journals[applicant]->acceptJoin(certificate, confirmations(review), now());
        for (std::size_t observer = 0; observer < applicant; ++observer) journals[observer]->observe(certificate, now());
        // Install at the accepted membership head. The prior installed key
        // remains valid after later Add with the same generation.
        const auto package = journals[0]->prepareDelivery(identities[applicant]->member().id, *identities[0], *key, now());
        const auto receipt = journals[applicant]->installDelivery(package, *identities[applicant], now());
        CHECK(journals[0]->recordReceipt(receipt, now()));
    }
    const auto status = journals[0]->inspect();
    const storage::SignedEventScope scope{status.state.group, status.state.root, status.state.keyGeneration};
    for (std::size_t i : {1u, 2u}) directory(root + '/' + names[i] + "/transport/" + QString::fromStdString(storage::signedEventFolderName(scope)));
    storage::Directory first(path(root + "/a/transport")), second(path(root + "/b/transport"));
    const auto prepared = journals[0]->prepareClipboardEvent(*identities[0], *key, {}, cqs::packed::encode(snapshot("SEED")), now());
    journals[0]->publishClipboardEvent(prepared.sequence, *key, first, now(), ClipboardPublication::Seed, staging(root + "/a"));
    for (const auto &packet : first.scanSignedEvents(scope)) second.publishSignedEvent(scope, {packet.id, packet.wire}, staging(root + "/b"));
    const std::array<QString, 3> settings{"", settingsA, settingsB};
    for (std::size_t i : {1u, 2u}) {
        CHECK(QDir().mkpath(QFileInfo(settings[i]).absolutePath()));
        QSettings profile(settings[i], QSettings::IniFormat);
        profile.setValue("Options/encrypt_tabs", true);
        profile.setValue("Options/tabs", QStringList{"clipboard"});
        profile.setValue("Options/clipboard_tab", "clipboard");
        profile.setValue("Options/maxitems", 100);
        profile.setValue("plugin_priority", QStringList{"securesync"});
        profile.setValue("Plugins/securesync/enabled", true);
        profile.sync();
        CHECK(profile.status() == QSettings::NoError);
        const auto canonical = QFileInfo(settings[i]).canonicalFilePath();
        const auto folder = root + '/' + names[i];
        const auto binding = TrustJournal::binding(pins, identities[i]->member());
        const auto profileBinding = cqs::native::signedTabBinding(canonical, QFileInfo(folder + "/checkpoint").canonicalFilePath(), binding);
        const auto &transport = i == 1 ? first : second;
        const auto expected = journals[i]->preflightJoinActivation(*identities[i], transport, profileBinding, now());
        SignedJoinCheckpoint checkpoint(path(folder + "/checkpoint"), checkpointKeys[i], profileBinding);
        journals[i]->applyJoinActivation(*identities[i], transport, expected, now(),
            [&](const JoinActivation &verified, const cqs::events::Event &event, const tx::Snapshot &contents) { checkpoint.apply(verified, event, contents); });
        const cqs::native::SignedTabConfiguration configuration{QFileInfo(folder + "/checkpoint").canonicalFilePath(),
                                                               QFileInfo(folder + "/credentials/checkpoint.key").canonicalFilePath(), expected};
        profile.setValue("Plugins/securesync/active_signed_tab", cqs::native::encodeSignedTab(configuration, binding));
        profile.setValue("Plugins/securesync/signed_replica_source", cqs::native::signedReplicaSourcePin(profileBinding,
            {QFileInfo(folder + "/transport").canonicalFilePath(), QFileInfo(folder + "/journal").canonicalFilePath()}));
        profile.sync();
        CHECK(profile.status() == QSettings::NoError);
        data.insert(names[i], QJsonObject{{"member", memberJson(identities[i]->member())}, {"settings", canonical}});
    }
    write(root + '/' + Manifest, QJsonDocument(data).toJson(QJsonDocument::Compact));
    for (auto &value : vaultKeys) cqs::crypto::wipe(value);
    for (auto &value : journalKeys) cqs::crypto::wipe(value);
    for (auto &value : checkpointKeys) cqs::crypto::wipe(value);
}

void deliver(const QString &root, bool latestOnly = false) {
    Device a(root, "a"), b(root, "b");
    const auto status = a.journal->inspect();
    const storage::SignedEventScope scope{status.state.group, status.state.root, status.state.keyGeneration};
    const auto first = a.transport->scanSignedEvents(scope), second = b.transport->scanSignedEvents(scope);
    if (latestOnly) {
        const auto author = SignedEventCodec::deviceName(a.local.id);
        const storage::SignedEventPacket *latest = nullptr;
        for (const auto &packet : first) if (packet.id.substr(0, author.size()) == author && (!latest || latest->id < packet.id)) latest = &packet;
        CHECK(latest);
        b.transport->publishSignedEvent(scope, {latest->id, latest->wire}, staging(b.folder));
        return;
    }
    for (const auto &packet : first) b.transport->publishSignedEvent(scope, {packet.id, packet.wire}, staging(b.folder));
    for (const auto &packet : second) a.transport->publishSignedEvent(scope, {packet.id, packet.wire}, staging(a.folder));
}

void resolve(const QString &root, const QString &name) {
    Device device(root, name);
    auto mounted = device.checkpoint->mount(device.configuration->expected);
    const auto contents = mounted->snapshot();
    const auto review = device.journal->reviewReplicaConflict(*device.identity, *device.transport, device.configuration->expected,
        mounted->replica(), contents, now());
    CHECK(review);
    const auto other = std::find_if(review->tips.begin(), review->tips.end(), [&](const auto &tip) { return tip.id != mounted->replica().cursor.id; });
    CHECK(other != review->tips.end());
    CHECK(device.journal->resolveReplicaConflict(*device.identity, *device.transport, device.configuration->expected,
        mounted->replica(), contents, *review, other->id, now(), [&](const auto &replica, const auto &selected) {
            mounted->updateReplica(replica, selected, mounted->generation());
        }, staging(device.folder), [&](const auto &, const auto &selected) {
            if (!mounted->replica().pending) mounted->checkConflictBackupCapacity(selected);
        }) == SignedReplicaResult::Published);
    CHECK(mounted->conflictBackupCount() == 1);
}

void selfTest() {
    QTemporaryDir root(QDir::tempPath() + "/cqs-signed-two-XXXXXX");
    CHECK(root.isValid());
    seed(root.path(), root.filePath("profile-a.ini"), root.filePath("profile-b.ini"));
    { Device a(root.path(), "a"); a.edit("A"); CHECK(a.sync() == SignedReplicaResult::Published); }
    deliver(root.path());
    { Device b(root.path(), "b"); CHECK(b.sync() == SignedReplicaResult::Pulled); b.verify("A"); b.edit("B"); CHECK(b.sync() == SignedReplicaResult::Published); }
    deliver(root.path());
    { Device a(root.path(), "a"); CHECK(a.sync() == SignedReplicaResult::Pulled); a.verify("B"); a.edit("CONFLICT_A"); CHECK(a.sync() == SignedReplicaResult::Published); }
    { Device b(root.path(), "b"); b.edit("CONFLICT_B"); CHECK(b.sync() == SignedReplicaResult::Published); }
    deliver(root.path());
    { Device a(root.path(), "a"); CHECK(a.sync() == SignedReplicaResult::Conflict); a.verify("CONFLICT_A"); }
    resolve(root.path(), "a");
    deliver(root.path());
    { Device b(root.path(), "b"); CHECK(b.sync() == SignedReplicaResult::Pulled); b.verify("CONFLICT_B"); }
    { Device a(root.path(), "a"); a.verify("CONFLICT_B"); a.edit("GAP_1"); CHECK(a.sync() == SignedReplicaResult::Published); a.edit("GAP_2"); CHECK(a.sync() == SignedReplicaResult::Published); }
    deliver(root.path(), true);
    { Device b(root.path(), "b"); bool refused = false; try { b.sync(); } catch (const std::exception &) { refused = true; } CHECK(refused); b.verify("CONFLICT_B"); }
    deliver(root.path());
    { Device b(root.path(), "b"); CHECK(b.sync() == SignedReplicaResult::Pulled); b.verify("GAP_2"); }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    try {
        const auto args = app.arguments();
        if (args.size() == 1 || (args.size() == 2 && args[1] == "--self-test")) {
            selfTest(); std::cout << "Signed two-device self-test passed\n"; return 0;
        }
        CHECK(args.size() >= 3);
        const auto command = args[1], root = QFileInfo(args[2]).absoluteFilePath();
        if (command == "seed") { CHECK(args.size() == 5); seed(root, args[3], args[4]); }
        else if (command == "deliver") deliver(root);
        else if (command == "deliver-latest-only") deliver(root, true);
        else if (command == "resolve") { CHECK(args.size() == 4); resolve(root, args[3]); }
        else {
            CHECK(args.size() >= 4);
            Device device(root, args[3]);
            if (command == "sync") {
                const auto result = device.sync();
                switch (result) {
                case SignedReplicaResult::UpToDate: std::cout << "UpToDate\n"; break;
                case SignedReplicaResult::Pulled: std::cout << "Pulled\n"; break;
                case SignedReplicaResult::Published: std::cout << "Published\n"; break;
                case SignedReplicaResult::Conflict: std::cout << "Conflict\n"; break;
                }
                return 0;
            } else if (command == "verify") { CHECK(args.size() == 5); device.verify(args[4]); }
            else if (command == "tamper") {
                const auto mounted = device.checkpoint->mount(device.configuration->expected);
                const auto status = device.journal->inspect();
                const storage::SignedEventScope scope{status.state.group, status.state.root, status.state.keyGeneration};
                const auto filename = device.folder + "/transport/" + QString::fromStdString(storage::signedEventFolderName(scope)) + '/' +
                                      QString::fromStdString(storage::detail::signedEventFilename(mounted->replica().cursor.id));
                auto wire = read(filename); CHECK(!wire.isEmpty()); wire[wire.size() - 1] ^= 1; write(filename, wire);
            } else throw std::runtime_error("Unknown fixture action");
        }
        std::cout << "Verified\n";
        return 0;
    } catch (...) {
        std::cerr << "Signed fixture operation refused\n";
        return 2;
    }
}
