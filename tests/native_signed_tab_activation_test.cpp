// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_tab_activation.h"
#include "test_check.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QTemporaryDir>
#include <QVariant>
#include <QtEndian>

// Match the pinned host's public QObject surface without loading other plugins.
class ItemFactory final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QStringList copyqStats READ copyqStats CONSTANT)

public:
    using QObject::QObject;
    QStringList copyqStats() const { return inventory; }
    QStringList inventory;
};

namespace {
using namespace cqs::native;

const QString SecureSync = QStringLiteral("PLUGIN securesync: enabled");

void writeFile(const QString &path, const QByteArray &bytes) {
    QFile file(path);
    CHECK(file.open(QIODevice::WriteOnly));
    CHECK(file.write(bytes) == bytes.size());
}

cqs::trust::Token token(std::uint8_t first) {
    cqs::trust::Token result{};
    result.front() = first;
    return result;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("copyq-signed-test"));
    QTemporaryDir temp;
    CHECK(temp.isValid());
    const auto profile = temp.filePath("profile.ini");
    QSettings settings(profile, QSettings::IniFormat);
    settings.setValue("Options/encrypt_tabs", false);
    settings.sync();
    CHECK(settings.status() == QSettings::NoError);

    QObject server;
    ItemFactory factory(&server);
    factory.inventory = {SecureSync, QStringLiteral("PLUGIN itemtext: enabled")};
    CHECK(!signedTabHostReady(profile)); // No live CopyQ server.
    app.setProperty("CopyQ_server", QVariant::fromValue(static_cast<QObject *>(&server)));
    CHECK(!signedTabHostReady(profile)); // Encrypt Tabs is off.
    settings.setValue("Options/encrypt_tabs", true);
    settings.sync();
    CHECK(signedTabHostReady(profile));
    {
        QObject wrapper(&server);
        ItemFactory nested(&wrapper);
        nested.inventory = {QStringLiteral("PLUGIN itemgpg: enabled")};
        CHECK(signedTabHostReady(profile)); // Only the direct host ItemFactory counts.
    }
    {
        ItemFactory duplicate(&server);
        duplicate.inventory = factory.inventory;
        CHECK(!signedTabHostReady(profile));
    }
    factory.inventory = {QStringLiteral("PLUGIN itemtext: enabled"), SecureSync};
    CHECK(!signedTabHostReady(profile)); // Native re-save can select an earlier loader.
    factory.inventory = {QStringLiteral("PLUGIN securesync: disabled")};
    CHECK(!signedTabHostReady(profile));
    factory.inventory = {SecureSync, QStringLiteral("PLUGIN itemgpg: enabled")};
    CHECK(!signedTabHostReady(profile));
    factory.inventory = {SecureSync, QStringLiteral("PLUGIN itemgpg: disabled")};
    CHECK(signedTabHostReady(profile));
    factory.inventory = {SecureSync, SecureSync};
    CHECK(!signedTabHostReady(profile));
    factory.inventory = {SecureSync, QStringLiteral("PLUGIN itemtext: unknown")};
    CHECK(!signedTabHostReady(profile));
    factory.inventory = {SecureSync};
    CHECK(signedTabHostReady(profile));

    CHECK(signedTabCachePath().isEmpty());
    CHECK(!signedTabDestinationFree(profile));
    app.setProperty("CopyQ_item_data_path", temp.filePath("items"));
    const auto cache = temp.filePath("copyq-signed-test_tab_c2lnbmVkX3N5bmM=.dat");
    CHECK(signedTabCachePath() == cache);
    CHECK(signedTabDestinationFree(profile));
    settings.setValue("Options/tabs", QStringList{QStringLiteral("&signed_sync")});
    settings.sync();
    CHECK(!signedTabDestinationFree(profile));
    settings.remove("Options/tabs");
    settings.setValue("Options/clipboard_tab", QStringLiteral("signed_sync"));
    settings.sync();
    CHECK(!signedTabDestinationFree(profile));
    settings.remove("Options/clipboard_tab");
    settings.sync();
    CHECK(signedTabDestinationFree(profile));
    writeFile(cache, QByteArrayLiteral("keep existing tab"));
    CHECK(!signedTabDestinationFree(profile));
    CHECK(QFile::remove(cache));
    writeFile(cache + QStringLiteral(".tmp"), QByteArrayLiteral("keep pending tab"));
    CHECK(!signedTabDestinationFree(profile));
    CHECK(QFile::remove(cache + QStringLiteral(".tmp")));
    CHECK(signedTabDestinationFree(profile));

    CHECK(QDir(temp.path()).mkdir("checkpoint"));
    const auto key = temp.filePath("local-key");
    writeFile(key, QByteArray(32, 'K'));
    const std::string journal = "trust-" + std::string(64, 'a');
    SignedTabConfiguration configuration;
    configuration.checkpointDirectory = QFileInfo(temp.filePath("checkpoint")).canonicalFilePath();
    configuration.keyFile = QFileInfo(key).canonicalFilePath();
    const auto canonicalProfile = QFileInfo(profile).canonicalFilePath();
    configuration.expected = {signedTabBinding(canonicalProfile, configuration.checkpointDirectory, journal),
                              token(1), token(2), token(3), token(4), token(5), 0,
                              "d" + std::string(31, 'a') + "/000000000001"};
    const auto encoded = encodeSignedTab(configuration, journal);
    const auto decoded = decodeSignedTab(profile, encoded);
    CHECK(decoded && decoded->expected.generation == 0);
    CHECK(decoded->expected.profileBinding == configuration.expected.profileBinding);
    CHECK(encodeSignedTab(*decoded, journal) == encoded);
    auto guided = configuration;
    guided.keyFile.clear();
    guided.setupRoot = QFileInfo(temp.path()).canonicalFilePath();
    const auto guidedWire = encodeSignedTab(guided, journal);
    CHECK(decodeSignedTab(profile, guidedWire)->setupRoot == guided.setupRoot);
    guided.keyFile = key;
    CHECK(!decodeSignedTab(profile, encodeSignedTab(guided, journal)));
    guided.keyFile.clear();
    guided.predecessorMarker = QByteArray(32, 'P');
    guided.predecessorMaximumGeneration = 11;
    const auto transitioned = decodeSignedTab(profile, encodeSignedTab(guided, journal));
    CHECK(transitioned && transitioned->predecessorMaximumGeneration == 11);
    guided.predecessorMaximumGeneration = 0;
    CHECK(!decodeSignedTab(profile, encodeSignedTab(guided, journal)));

    const auto copiedProfile = temp.filePath("copied-profile.ini");
    CHECK(QFile::copy(profile, copiedProfile));
    CHECK(!decodeSignedTab(copiedProfile, encoded));
    CHECK(QDir(temp.path()).mkdir("transport") && QDir(temp.path()).mkdir("other-transport"));
    const auto transport = QFileInfo(temp.filePath("transport")).canonicalFilePath();
    const auto other = QFileInfo(temp.filePath("other-transport")).canonicalFilePath();
    const auto pin = signedReplicaSourcePin(configuration.expected.profileBinding, {transport, canonicalProfile + "/.."});
    const auto journalDirectory = QFileInfo(temp.path()).canonicalFilePath();
    CHECK(pin.isEmpty());
    const auto sourcePin = signedReplicaSourcePin(configuration.expected.profileBinding, {transport, journalDirectory});
    const auto otherPin = signedReplicaSourcePin(configuration.expected.profileBinding, {other, journalDirectory});
    const auto otherJournal = signedReplicaSourcePin(configuration.expected.profileBinding, {transport, other});
    CHECK(sourcePin.size() == 32 && otherPin.size() == 32 && sourcePin != otherPin && sourcePin != otherJournal);
    CHECK(signedReplicaSourcePin(configuration.expected.profileBinding, {"relative", journalDirectory}).isEmpty());
    CHECK(!confirmSignedReplicaSource(profile, encoded, sourcePin, true));
    settings.setValue("Plugins/securesync/active_signed_tab", encoded);
    settings.sync();
    CHECK(!confirmSignedReplicaSource(profile, encoded, sourcePin, false));
    CHECK(confirmSignedReplicaSource(profile, encoded, sourcePin, true));
    CHECK(confirmSignedReplicaSource(profile, encoded, sourcePin, false));
    CHECK(!confirmSignedReplicaSource(profile, encoded, otherPin, true));
    CHECK(!confirmSignedReplicaSource(profile, encoded, otherJournal, true));
    CHECK(!confirmSignedReplicaSource(profile, encoded + 'x', sourcePin, true));

    CHECK(signedTabReplicaLimit(profile) == 200);
    settings.setValue("Options/maxitems", 12);
    settings.beginWriteArray("Tabs", 1);
    settings.setArrayIndex(0);
    settings.setValue("name", "signed_sync");
    settings.setValue("max_item_count", 30);
    settings.endArray();
    settings.sync();
    CHECK(signedTabReplicaLimit(profile) == 30);
    settings.setValue("Tabs/1/store_items", false);
    settings.sync();
    CHECK(signedTabReplicaLimit(profile) == 0);

    const auto malformed = [&](const QString &name, const QJsonValue &value) {
        auto object = QJsonDocument::fromJson(encoded).object();
        object.insert(name, value);
        CHECK(!decodeSignedTab(profile, QJsonDocument(object).toJson(QJsonDocument::Compact)));
    };
    malformed(QStringLiteral("version"), 2);
    malformed(QStringLiteral("generation"), QStringLiteral("00"));
    malformed(QStringLiteral("tipId"), QStringLiteral("../other"));
    malformed(QStringLiteral("tipDigest"), QStringLiteral("not-a-digest"));
    malformed(QStringLiteral("journalBinding"), QStringLiteral("legacy-profile"));
    malformed(QStringLiteral("keyFile"), temp.filePath("missing-key"));
    malformed(QStringLiteral("unknown"), true);

    CHECK(QDir(temp.path()).mkdir("successor"));
    auto successor = configuration;
    successor.checkpointDirectory = QFileInfo(temp.filePath("successor")).canonicalFilePath();
    successor.expected.generation = 1;
    successor.expected.tipDigest = token(9);
    successor.expected.profileBinding = signedTabBinding(canonicalProfile, successor.checkpointDirectory, journal);
    QByteArray marker = SignedTabPreamble + QByteArrayLiteral("CQSSGN01") + signedTabMarkerIdentity(configuration.expected);
    const auto generation = qToBigEndian<quint64>(3);
    marker.append(reinterpret_cast<const char *>(&generation), sizeof(generation));
    writeFile(cache, marker);
    retainSignedPredecessorMarker(successor, configuration, 3);
    CHECK(successor.predecessorMaximumGeneration == 3 &&
          successor.predecessorMarker == signedTabMarkerIdentity(configuration.expected));
    const auto retentionRefuses = [&](const QByteArray &bytes, const SignedTabConfiguration &current,
                                     std::uint64_t maximum) {
        writeFile(cache, bytes);
        auto candidate = successor;
        bool refused = false;
        try {
            retainSignedPredecessorMarker(candidate, current, maximum);
        } catch (const cqs::trust::JournalError &error) {
            CHECK(error.code() == cqs::trust::JournalCode::HistoryChanged);
            refused = true;
        }
        CHECK(refused && candidate.predecessorMarker.isEmpty() && candidate.predecessorMaximumGeneration == 0);
    };
    auto futureMarker = marker;
    qToBigEndian<quint64>(4, futureMarker.data() + 48);
    retentionRefuses(futureMarker, configuration, 3);
    retentionRefuses(marker, configuration, 0);
    auto unrelatedMarker = marker;
    unrelatedMarker[16] = char(unrelatedMarker[16] ^ 1);
    retentionRefuses(unrelatedMarker, configuration, 3);
    retentionRefuses(marker.left(55), configuration, 3);
    writeFile(cache + QStringLiteral(".tmp"), marker);
    retentionRefuses(marker, configuration, 3);
    CHECK(QFile::remove(cache + QStringLiteral(".tmp")));
    auto earlier = configuration;
    earlier.predecessorMarker = QByteArray(32, 'P');
    earlier.predecessorMaximumGeneration = 2;
    auto inheritedMarker = marker;
    inheritedMarker.replace(16, 32, earlier.predecessorMarker);
    qToBigEndian<quint64>(2, inheritedMarker.data() + 48);
    writeFile(cache, inheritedMarker);
    auto inherited = successor;
    retainSignedPredecessorMarker(inherited, earlier, 99);
    CHECK(inherited.predecessorMarker == earlier.predecessorMarker && inherited.predecessorMaximumGeneration == 2);
    qToBigEndian<quint64>(3, inheritedMarker.data() + 48);
    retentionRefuses(inheritedMarker, earlier, 99);
    CHECK(QFile::remove(cache));
    auto uncached = successor;
    retainSignedPredecessorMarker(uncached, configuration, 3);
    CHECK(uncached.predecessorMarker.isEmpty() && uncached.predecessorMaximumGeneration == 0);
    writeFile(cache, marker);
    settings.setValue("Plugins/securesync/active_signed_tab", encoded + 'x');
    settings.sync();
    CHECK(!persistSignedSuccessor(profile, configuration, successor, journal, {transport, journalDirectory}));
    CHECK(settings.value("Plugins/securesync/active_signed_tab").toByteArray() == encoded + 'x');
    CHECK(settings.value("Plugins/securesync/signed_replica_source").toByteArray() == sourcePin);
    settings.setValue("Plugins/securesync/active_signed_tab", encoded);
    settings.sync();
    CHECK(!persistSignedSuccessor(profile, configuration, successor, journal, {other, journalDirectory}));
    CHECK(persistSignedSuccessor(profile, configuration, successor, journal, {transport, journalDirectory}));
    CHECK(persistSignedSuccessor(profile, configuration, successor, journal, {transport, journalDirectory}));
    CHECK(!confirmSignedReplicaSource(profile, encoded, sourcePin, false));
    const auto changed = settings.value("Plugins/securesync/active_signed_tab").toByteArray();
    CHECK(decodeSignedTab(profile, changed)->expected.generation == 1);
    settings.setValue("Plugins/securesync/signed_replica_source", sourcePin);
    settings.sync();
    CHECK(!persistSignedSuccessor(profile, configuration, successor, journal, {transport, journalDirectory}));
    CHECK(settings.value("Plugins/securesync/active_signed_tab").toByteArray() == changed);
    CHECK(settings.value("Plugins/securesync/signed_replica_source").toByteArray() == sourcePin);

    app.setProperty("CopyQ_server", QVariant{});
    CHECK(!signedTabHostReady(profile));
    std::cout << "Native signed tab activation checks passed\n";
}

#include "native_signed_tab_activation_test.moc"
