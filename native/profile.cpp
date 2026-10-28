// SPDX-License-Identifier: GPL-3.0-or-later
#include "profile.h"
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <stdexcept>

namespace cqs::native {
namespace {
const auto format = QStringLiteral("profile_schema");
QString normalized(const QString &path) {
    return QDir::cleanPath(QDir::fromNativeSeparators(path));
}
bool contains(const QString &outer, const QString &inner) {
#ifdef Q_OS_WIN
    constexpr auto cs = Qt::CaseInsensitive;
#else
    constexpr auto cs = Qt::CaseSensitive;
#endif
    const auto a = normalized(outer), b = normalized(inner);
    return a.compare(b, cs) == 0 || b.startsWith(a + '/', cs);
}
QString pathError(const QString &value) {
    if (value.isEmpty() || value.size() > 4096 || !QDir::isAbsolutePath(value))
        return QStringLiteral("Use an absolute local path for every folder and for K-SYNC.");
    for (auto ch : value)
        if (ch.unicode() < 32 || ch.unicode() == 127)
            return QStringLiteral("Paths cannot contain control characters.");
    const auto path = QDir::fromNativeSeparators(value);
    if (path.startsWith(QStringLiteral("//")) || path.contains(QStringLiteral("://")))
        return QStringLiteral("Network and device paths are not supported; choose a local synchronized folder.");
    for (const auto &part : path.split('/'))
        if (part == QStringLiteral(".") || part == QStringLiteral(".."))
            return QStringLiteral("Remove dot and parent components from paths.");
    if (QDir(normalized(path)).isRoot())
        return QStringLiteral("A filesystem root cannot be used as a synchronization or private folder.");
    return {};
}
bool pathHasLink(QString path) {
    // The selected pathname is preserved, not silently canonicalized through
    // a symlink. The runtime's descriptor checks remain necessary against races.
    for (;;) {
        const QFileInfo info(path);
        if (info.isSymLink()) return true;
        const auto parent = info.absolutePath();
        if (parent == path || QDir(path).isRoot()) break;
        path = parent;
    }
    return false;
}
}
bool Profile::operator==(const Profile &o) const {
    return device == o.device && transport == o.transport && keyFile == o.keyFile &&
           stateDirectory == o.stateDirectory && schema == o.schema && standaloneStorage == o.standaloneStorage && vaultDirectory == o.vaultDirectory && publicationStaging == o.publicationStaging && predecessorBinding == o.predecessorBinding;
}
bool Profile::isEmpty() const {
    return schema == 3 && publicationStaging.isEmpty() && vaultDirectory.isEmpty() && !standaloneStorage && device.isEmpty() && transport.isEmpty() && keyFile.isEmpty() && stateDirectory.isEmpty();
}
Profile loadProfile(const QSettings &s) {
    if(s.contains("active_successor")) {
        try{return decodeProfile(s.value("active_successor").toByteArray());}
        catch(...){Profile invalid;invalid.schema=-1;invalid.standaloneStorage=true;return invalid;}
    }
    Profile result = {s.value(QStringLiteral("device")).toString(),
            s.value(QStringLiteral("transport")).toString(),
            s.value(QStringLiteral("key_file")).toString(),
            s.value(QStringLiteral("state_directory")).toString()};
    const auto schema = s.value(format, 1).toInt();
    if (schema != 1 && schema != 2 && schema != 3) result.schema = -1;
    if (schema == 2 && s.value(QStringLiteral("standalone_storage"), false).toBool()) result.schema = 2;
    result.vaultDirectory = s.value(QStringLiteral("vault_directory")).toString();
    result.publicationStaging = s.value(QStringLiteral("publication_staging")).toString();
    result.predecessorBinding = s.value("predecessor_binding").toString();
    if (schema != 1) result.standaloneStorage = s.value(QStringLiteral("standalone_storage"), false).toBool();
    return result;
}
void saveProfile(QSettings &s, const Profile &p) {
    if (p.schema != 3) return; // Preserve unknown future schemas.
    s.setValue(format, 3);
    s.setValue(QStringLiteral("vault_directory"), p.vaultDirectory);
    s.setValue(QStringLiteral("standalone_storage"), p.standaloneStorage);
    s.setValue(QStringLiteral("device"), p.device);
    s.setValue(QStringLiteral("transport"), p.transport);
    s.setValue(QStringLiteral("key_file"), p.keyFile);
    s.setValue(QStringLiteral("state_directory"), p.stateDirectory);
    s.setValue(QStringLiteral("publication_staging"), p.publicationStaging);
    if(!p.predecessorBinding.isEmpty())s.setValue("predecessor_binding",p.predecessorBinding);
    else s.remove("predecessor_binding");
    // Once present, keep the single-value activation boundary on every save.
    if(s.contains("active_successor"))s.setValue("active_successor",encodeProfile(p));
    // Do not call clear(), change another plugin's options or change the CopyQ
    // encryption/global clipboard configuration. CopyQ controls final sync().
}
QString validateProfile(const Profile &p, bool existing) {
    if (p.schema != 3) return QStringLiteral("Unsupported settings schema. Existing settings are preserved.");
    if(!p.predecessorBinding.isEmpty()&&!QRegularExpression("\\A[a-f0-9]{64}\\z").match(p.predecessorBinding).hasMatch())
        return QStringLiteral("Invalid predecessor identity; retain the existing profile.");
    static const QRegularExpression device(QStringLiteral("\\A[a-z][a-z0-9-]{2,31}\\z"));
    if (!device.match(p.device).hasMatch())
        return QStringLiteral("Device ID must contain 3–32 lowercase letters, digits or hyphens, starting with a letter.");
    for (const auto &path : {p.transport, p.stateDirectory}) {
        const auto error = pathError(path);
        if (!error.isEmpty()) return error;
    }
    const bool vault = !p.vaultDirectory.isEmpty();
    if (p.standaloneStorage && !vault) return QStringLiteral("Choose a separate private key vault directory.");
    if (!p.keyFile.isEmpty() || !vault) { const auto error = pathError(p.keyFile); if (!error.isEmpty()) return error; }
    if (vault) {
        const auto error = pathError(p.vaultDirectory); if (!error.isEmpty()) return error;
        for (const auto &other : {p.transport, p.stateDirectory})
            if (contains(other, p.vaultDirectory) || contains(p.vaultDirectory, other))
                return QStringLiteral("The key vault, state and synchronization folders must not overlap.");
    }
    if ((!p.keyFile.isEmpty() && (contains(p.transport, p.keyFile) || contains(p.keyFile, p.transport))) ||
        contains(p.transport, p.stateDirectory) || contains(p.stateDirectory, p.transport))
        return QStringLiteral("K-SYNC and private state must be outside the synchronized folder; private and transport folders must not contain each other.");
    if (p.keyFile == p.stateDirectory)
        return QStringLiteral("K-SYNC must be a file, not the private state directory.");
    if(!p.publicationStaging.isEmpty()){
        const auto error=pathError(p.publicationStaging);if(!error.isEmpty())return error;
        if(contains(p.transport,p.publicationStaging)||contains(p.publicationStaging,p.transport))
            return QStringLiteral("The private publication staging folder must be outside the synchronization folder and must not contain it.");
        if(vault&&(contains(p.vaultDirectory,p.publicationStaging)||contains(p.publicationStaging,p.vaultDirectory)))
            return QStringLiteral("The key vault and publication staging folders must not overlap.");
    }
    if (!existing) return {};
    for (const auto &path : {p.transport, p.keyFile, p.stateDirectory, p.vaultDirectory,p.publicationStaging})
        if (!path.isEmpty() && pathHasLink(normalized(path)))
            return QStringLiteral("A chosen path contains a symbolic link. Select its actual local target explicitly.");
    if (!QFileInfo(p.transport).isDir() || !QFileInfo(p.stateDirectory).isDir())
        return QStringLiteral("The transport and private state directories must already exist. No folder is created implicitly.");
    const QFileInfo events(QDir(p.transport).filePath(QStringLiteral("events")));
    if (!events.isDir() || events.isSymLink())
        return QStringLiteral("The selected transport must have an existing, non-symlink events directory.");
    if (vault && !QFileInfo(p.vaultDirectory).isDir()) return QStringLiteral("The private key vault folder must already exist.");
    if(!p.publicationStaging.isEmpty()&&!QFileInfo(p.publicationStaging).isDir())return QStringLiteral("The private publication staging folder must already exist.");
    const QFileInfo key(p.keyFile);
    if (!p.keyFile.isEmpty() && (!key.isFile() || key.size() != 32))
        return QStringLiteral("Select the existing 32-byte K-SYNC file, not a CopyQ DEK or a password.");
    // Check resolved relationships too. This catches aliases not evident from
    // textual spelling; it still does not replace handle checks during I/O.
    if ((!p.keyFile.isEmpty() && contains(QFileInfo(p.transport).canonicalFilePath(), key.canonicalFilePath())) ||
        contains(QFileInfo(p.transport).canonicalFilePath(), QFileInfo(p.stateDirectory).canonicalFilePath()) ||
        contains(QFileInfo(p.stateDirectory).canonicalFilePath(), QFileInfo(p.transport).canonicalFilePath()))
        return QStringLiteral("Resolved private paths overlap the synchronized folder.");
    return {};
}
QByteArray encodeProfile(const Profile &p){
    int nulls=0,bit=1;for(const auto &s:{p.device,p.transport,p.keyFile,p.stateDirectory,p.vaultDirectory,p.publicationStaging,p.predecessorBinding}){if(s.isNull())nulls|=bit;bit<<=1;}
    return QJsonDocument(QJsonObject{{"v",1},{"device",p.device},{"transport",p.transport},{"key",p.keyFile},
        {"state",p.stateDirectory},{"vault",p.vaultDirectory},{"staging",p.publicationStaging},
        {"predecessor",p.predecessorBinding},{"standalone",p.standaloneStorage},{"schema",p.schema},{"nulls",nulls}}).toJson(QJsonDocument::Compact);
}
Profile decodeProfile(const QByteArray &bytes){
    if(bytes.size()>32768)throw std::runtime_error("Invalid profile");
    const auto o=QJsonDocument::fromJson(bytes).object();
    if(o.size()!=11||o.value("v").toInt()!=1||!o.value("standalone").isBool()||!o.value("schema").isDouble()||
       o.value("nulls").toInt(-1)<0||o.value("nulls").toInt()>127)throw std::runtime_error("Invalid profile");
    for(const auto *key:{"device","transport","key","state","vault","staging","predecessor"})if(!o.value(key).isString())throw std::runtime_error("Invalid profile");
    Profile p{o.value("device").toString(),o.value("transport").toString(),o.value("key").toString(),o.value("state").toString(),
        o.value("schema").toInt(),o.value("standalone").toBool(),o.value("vault").toString(),o.value("staging").toString(),o.value("predecessor").toString()};
    // QDataStream includes QString's null marker in existing storage bindings.
    // JSON's empty string must not silently turn a null into a different identity.
    int bit=1;for(auto *s:{&p.device,&p.transport,&p.keyFile,&p.stateDirectory,&p.vaultDirectory,&p.publicationStaging,&p.predecessorBinding}){
        if(o.value("nulls").toInt()&bit){if(!s->isEmpty())throw std::runtime_error("Invalid profile");*s=QString{};}bit<<=1;
    }
    if(!validateProfile(p,false).isEmpty())throw std::runtime_error("Invalid profile");return p;
}
void activateProfile(QSettings &s,const Profile &p){
    if(!p.standaloneStorage||!validateProfile(p,true).isEmpty())throw std::runtime_error("Invalid successor");
    const auto bytes=encodeProfile(p);s.setValue("active_successor",bytes);s.sync();
    if(s.status()!=QSettings::NoError||s.value("active_successor").toByteArray()!=bytes)
        throw std::runtime_error("Unconfirmed profile activation; restart and resume");
}
} // namespace cqs::native
