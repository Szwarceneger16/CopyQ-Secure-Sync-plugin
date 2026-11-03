// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_tab_activation.h"
#include "common/appconfig.h"
#include "plugin_inventory.h"
#include "storage.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <algorithm>

namespace cqs::native {
namespace {
bool canonicalPath(const QString &path, bool directory) {
    if (path.size() > 4096 || !QDir::isAbsolutePath(path) || path.startsWith("//") ||
        QDir::cleanPath(path) != path || QDir(path).isRoot()) return false;
    for (const auto c : path) if (c.unicode() < 32 || c.unicode() == 127) return false;
    const QFileInfo info(path);
    return info.canonicalFilePath() == path && (directory ? info.isDir() : info.isFile());
}

QString hex(const trust::Token &token) {
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(token.data()), token.size()).toHex());
}

bool token(const QJsonObject &object, const char *name, trust::Token &out) {
    const auto text = object.value(QLatin1String(name)).toString().toLatin1();
    const auto bytes = QByteArray::fromHex(text);
    if (bytes.size() != static_cast<qsizetype>(out.size()) || bytes.toHex() != text) return false;
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return true;
}
} // namespace

std::string signedTabBinding(const QString &settingsFile, const QString &directory, const std::string &journalBinding) {
    QByteArray bytes("CopyQ-Secure-Sync-native-signed-join-v1");
    bytes.append('\0').append(settingsFile.toUtf8()).append('\0').append(directory.toUtf8()).append('\0');
    bytes.append(QByteArray::fromStdString(journalBinding));
    return "signed-native-" + QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex().toStdString();
}

QByteArray signedReplicaSourcePin(const std::string &profileBinding, const SignedReplicaSource &source) {
    if (!canonicalPath(source.transport, true) || !canonicalPath(source.journal, true)) return {};
    QByteArray bytes("CopyQ-Secure-Sync-native-replica-source-v1");
    bytes.append('\0').append(QByteArray::fromStdString(profileBinding)).append('\0').append(source.transport.toUtf8())
        .append('\0').append(source.journal.toUtf8());
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
}

bool confirmSignedReplicaSource(const QString &settingsFile, const QByteArray &activation,
                                const QByteArray &pin, bool allowFirstPin) {
    if (activation.isEmpty() || pin.size() != 32) return false;
    QSettings settings(settingsFile, QSettings::IniFormat);
    settings.sync();
    settings.beginGroup("Plugins/securesync");
    if (settings.value(SignedTabSetting).toByteArray() != activation || settings.status() != QSettings::NoError)
        return false;
    if (settings.contains(SignedReplicaSourceSetting))
        return settings.value(SignedReplicaSourceSetting).toByteArray() == pin;
    if (!allowFirstPin) return false;
    settings.setValue(SignedReplicaSourceSetting, pin);
    settings.sync();
    if (settings.status() != QSettings::NoError) return false;
    QSettings confirmed(settingsFile, QSettings::IniFormat);
    confirmed.sync();
    confirmed.beginGroup("Plugins/securesync");
    return confirmed.value(SignedTabSetting).toByteArray() == activation &&
           confirmed.value(SignedReplicaSourceSetting).toByteArray() == pin &&
           confirmed.status() == QSettings::NoError;
}

QByteArray encodeSignedTab(const SignedTabConfiguration &configuration, const std::string &journalBinding) {
    const auto &a = configuration.expected;
    return QJsonDocument(QJsonObject{
        {"version", 1}, {"directory", configuration.checkpointDirectory}, {"keyFile", configuration.keyFile},
        {"journalBinding", QString::fromStdString(journalBinding)}, {"binding", QString::fromStdString(a.profileBinding)},
        {"group", hex(a.group)}, {"root", hex(a.root)}, {"head", hex(a.head)}, {"member", hex(a.member)},
        {"tipDigest", hex(a.tipDigest)}, {"generation", QString::number(a.generation)}, {"tipId", QString::fromStdString(a.tipId)}
    }).toJson(QJsonDocument::Compact);
}

std::optional<SignedTabConfiguration> decodeSignedTab(const QString &settingsFile, const QByteArray &encoded) {
    if (encoded.isEmpty() || encoded.size() > 64 * 1024) return {};
    const auto object = QJsonDocument::fromJson(encoded).object();
    SignedTabConfiguration configuration{};
    configuration.checkpointDirectory = object.value("directory").toString();
    configuration.keyFile = object.value("keyFile").toString();
    const auto canonicalSettings = QFileInfo(settingsFile).canonicalFilePath();
    if (!canonicalPath(canonicalSettings, false) || !canonicalPath(configuration.checkpointDirectory, true) ||
        !canonicalPath(configuration.keyFile, false)) return {};
    const auto journalBinding = object.value("journalBinding").toString().toStdString();
    const auto trustPin = QByteArray::fromStdString(journalBinding).mid(6);
    if (journalBinding.compare(0, 6, "trust-") != 0 || trustPin.size() != 64 ||
        QByteArray::fromHex(trustPin).toHex() != trustPin) return {};
    auto &a = configuration.expected;
    a.profileBinding = object.value("binding").toString().toStdString();
    a.tipId = object.value("tipId").toString().toStdString();
    bool ok = false;
    a.generation = object.value("generation").toString().toULongLong(&ok);
    if (!ok || !storage::validSignedEventId(a.tipId) ||
        a.profileBinding != signedTabBinding(canonicalSettings, configuration.checkpointDirectory, journalBinding) ||
        !token(object, "group", a.group) || !token(object, "root", a.root) ||
        !token(object, "head", a.head) || !token(object, "member", a.member) ||
        !token(object, "tipDigest", a.tipDigest) || encodeSignedTab(configuration, journalBinding) != encoded) return {};
    return configuration;
}

bool signedTabHostReady(const QString &settingsFile, QString *enabledInventory) {
    if (settingsFile.isEmpty() || !qApp) return false;
    QSettings settings(settingsFile, QSettings::IniFormat);
    if (!settings.value("Options/encrypt_tabs", false).toBool() || settings.status() != QSettings::NoError) return false;
    // CopyQ 17 exposes the running GUI server and its actual loader order
    // through these properties. Reading the preference alone can race a
    // settings reload and cannot detect another enabled storage plugin.
    const auto *server = qApp->property("CopyQ_server").value<QObject *>();
    if (!server) return false;
    QStringList inventory;
    for (const auto *child : server->children()) {
        if (qstrcmp(child->metaObject()->className(), "ItemFactory") != 0) continue;
        if (!inventory.isEmpty()) return false;
        const auto stats = child->property("copyqStats");
        if (stats.metaType() != QMetaType::fromType<QStringList>()) return false;
        inventory = stats.toStringList();
        if (inventory.isEmpty()) return false;
    }
    if (inventory.isEmpty() || inventory.front() != QStringLiteral("PLUGIN securesync: enabled")) return false;
    const auto report = inventory.join('\n');
    if (!incompatiblePlugin(report).isEmpty()) return false;
    if (enabledInventory) *enabledInventory = report;
    return true;
}

int signedTabReplicaLimit(const QString &settingsFile) {
    QSettings settings(settingsFile, QSettings::IniFormat);
    bool ok = false;
    auto limit = settings.value("Options/maxitems", Config::maxitems::defaultValue()).toInt(&ok);
    if (!ok) return 0;
    // Match CopyQ 17's per-tab override. A non-persistent signed tab cannot
    // safely receive a new local snapshot.
    const auto tabs = settings.beginReadArray("Tabs");
    if (tabs < 0 || tabs > 10000) return 0;
    for (int i = 0; i < tabs; ++i) {
        settings.setArrayIndex(i);
        if (settings.value("name").toString() != QLatin1String(SignedTabName)) continue;
        if (!settings.value("store_items", true).toBool()) return 0;
        const auto overrideLimit = settings.value("max_item_count").toInt();
        if (overrideLimit > 0) limit = overrideLimit;
    }
    return settings.status() == QSettings::NoError ? Config::maxitems::value(limit) : 0;
}

bool signedTabDestinationFree(const QString &settingsFile) {
    QSettings settings(settingsFile, QSettings::IniFormat);
    auto tabs = settings.value("Options/tabs").toStringList();
    tabs.append(settings.value("Options/clipboard_tab").toString());
    for (auto name : tabs) {
        if (name.remove('&') == QLatin1String(SignedTabName)) return false;
    }
    const auto cache = signedTabCachePath();
    if (cache.isEmpty() || settings.status() != QSettings::NoError) return false;
    const QFileInfo info(cache);
    const QFileInfo interrupted(cache + QStringLiteral(".tmp"));
    return !info.exists() && !info.isSymLink() && !interrupted.exists() && !interrupted.isSymLink();
}

QString signedTabCachePath() {
    const auto dataPath = qApp ? qApp->property("CopyQ_item_data_path").toString() : QString{};
    if (!QDir::isAbsolutePath(dataPath) || QCoreApplication::applicationName().isEmpty()) return {};
    const auto part = QByteArray(SignedTabName).toBase64().replace('/', '-');
    return QFileInfo(dataPath).dir().filePath(QCoreApplication::applicationName() +
        QStringLiteral("_tab_") + QString::fromLatin1(part) + QStringLiteral(".dat"));
}
} // namespace cqs::native
