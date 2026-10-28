// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_storage.h"
#include <QCryptographicHash>
#include "key_reader.h"
#include "packed_items.h"
#include "state_store.h"
#include <QDataStream>
#include <QIODevice>
#include <filesystem>
#include <future>

namespace cqs::native {
namespace {
struct Key { crypto::Bytes bytes; ~Key() { crypto::wipe(bytes); } };
std::filesystem::path path(const QString &value) {
#ifdef Q_OS_WIN
    return std::filesystem::path(value.toStdWString());
#else
    return std::filesystem::path(value.toUtf8().toStdString());
#endif
}
std::vector<std::string> pack(const transaction::Snapshot &snapshot) {
    packed::validateSnapshot(snapshot, storageLimits());
    std::vector<std::string> result;
    std::size_t total = 0;
    for (const auto &item : snapshot) {
        QByteArray bytes;
        QDataStream stream(&bytes, QIODevice::WriteOnly);
        stream.setVersion(QDataStream::Qt_4_7);
        stream << qint32(-2) << qint32(item.size());
        for (const auto &field : item) {
            stream << (QStringLiteral("0") + QString::fromLatin1(field.first.data(), qsizetype(field.first.size())))
                   << false << QByteArray(reinterpret_cast<const char *>(field.second.data()), qsizetype(field.second.size()));
        }
        if (stream.status() != QDataStream::Ok) throw packed::Error();
        auto encoded = bytes.toBase64().toStdString();
        if (encoded.size() > events::Limits{}.plaintextBytes - total) throw packed::Error();
        total += encoded.size(); result.push_back(std::move(encoded));
    }
    if (packed::decode(result, storageLimits()) != snapshot) throw packed::Error();
    return result;
}
void validate(const transaction::Record &record, const StorageConfiguration &c, const crypto::Bytes &syncKey) {
    if (record.binding != c.binding.toStdString()) throw packed::Error();
    if(record.schema >= 2) {
        if(record.publication){
            const auto &p=*record.publication;
            const auto event=events::decode(syncKey,{p.target.event.revision.id,p.wire});
            if(event.revision.device!=c.profile.device.toStdString() || event.revision.sequence!=record.allocatedSequence ||
               event.revision.id!=p.target.event.revision.id || event.revision.parents!=p.target.event.revision.parents ||
               event.items!=p.target.event.items || packed::decode(event.items,storageLimits())!=p.target.snapshot)throw packed::Error();
        }
        for(const auto &snapshot:record.archives)packed::validateSnapshot(snapshot,storageLimits());
        if(record.preserved)packed::validateSnapshot(*record.preserved,storageLimits());
        if(!record.local || record.keyIdentity != syncKeyIdentity(syncKey))throw packed::Error();
        packed::validateSnapshot(*record.local,storageLimits());
        for(const auto *head : {record.head?&*record.head:nullptr,record.pending?&record.pending->target:nullptr})
            if(head && packed::decode(head->event.items,storageLimits())!=head->snapshot)throw packed::Error();
        return;
    }
    if(record.schema!=1 || record.pending || (record.generation == 0 ? bool(record.head) : !record.head))throw packed::Error();
    if (record.head) {
        const auto &h = *record.head;
        if (h.event.revision.device != "cqs-storage" || h.event.revision.sequence != record.generation ||
            packed::decode(h.event.items, storageLimits()) != h.snapshot) throw packed::Error();
        packed::validateSnapshot(h.snapshot, storageLimits());
    }
}
transaction::Record operation(const StorageConfiguration &c, const transaction::Snapshot *snapshot, const crypto::Bytes &localKey, const crypto::Bytes &syncKey,
 const transaction::Store::Lease *ownedSession=nullptr,std::optional<std::uint64_t> generation={}) {
    if (!c.profile.standaloneStorage || !validateProfile(c.profile, false).isEmpty()) throw packed::Error();
    // The key and all descriptor-based disk work stay in this short-lived worker.
    // The public saver contract and boundary checkpoints are synchronous.
    // Import transactions instead use the worker/GUI bridge; neither path
    // treats CopyQ's delayed cache write or a timer as a durability barrier.
    return std::async(std::launch::async, [c, snapshot, &localKey, &syncKey,ownedSession,generation] {
        auto ownership=snapshot&&!ownedSession?acquireStorageSession(c):nullptr;
        const Key key{localKey};
        state::Limits bounds; bounds.snapshot = storageLimits(); bounds.recordBytes = 128 * 1024 * 1024;
        state::FileStore store(path(c.profile.stateDirectory), c.binding.toStdString(), key.bytes, bounds);
        const auto lease = store.lock();
        if (!lease) throw packed::Error();
        auto previous = store.load(); validate(previous, c,syncKey);
        if(previous.schema<2 || previous.schema>6)throw state::Error(state::ErrorCode::InvalidRecord,"Explicit unified-state migration required");
        if(generation&&previous.generation!=*generation)throw state::Error(state::ErrorCode::Stale,"Loaded model is stale; preserve changes and reload");
        if (!snapshot || *previous.local == *snapshot) return previous;
        auto next = previous;
        ++next.generation; // FileStore refuses wrapping; no synchronization sequence is invented.
        next.local = *snapshot; // Retain accepted head and any recovery intent/backup.
        store.commit(previous, next);
        const auto actual = store.load(); validate(actual, c,syncKey);
        const Key actualBytes{state::serialize(actual, bounds)}, wantedBytes{state::serialize(next, bounds)};
        if (actualBytes.bytes != wantedBytes.bytes) throw packed::Error();
        return actual;
    }).get();
}
} // namespace
transaction::Limits storageLimits() {
    transaction::Limits result;
    return result;
}
std::unique_ptr<transaction::Store::Lease> acquireStorageSession(const StorageConfiguration &c) {
    if(!c.profile.standaloneStorage||!validateProfile(c.profile,false).isEmpty())throw packed::Error();
    state::FileStore gate(path(c.profile.stateDirectory),c.binding.toStdString(),crypto::Bytes(32),{},state::Protection::Key,state::LeaseKind::Session);
    auto ownership=gate.lock();if(!ownership)throw state::Error(state::ErrorCode::Busy,"Profile is loaded or modified by another process");return ownership;
}
std::string syncKeyIdentity(const crypto::Bytes &key) {
    if(key.size()!=32)throw crypto::Error("Invalid synchronization key identity");
    QByteArray input("CopyQ-Secure-Sync-key-identity-v1");input.append('\0');
    input.append(reinterpret_cast<const char *>(key.data()),qsizetype(key.size()));
    const auto identity=QCryptographicHash::hash(input,QCryptographicHash::Sha256).toHex().toStdString();
    input.fill(0);return identity;
}
transaction::Record readStorage(const StorageConfiguration &c, const crypto::Bytes &key, const crypto::Bytes &syncKey) { return operation(c, nullptr, key,syncKey); }
transaction::Record saveStorage(const StorageConfiguration &c, const transaction::Snapshot &s, const crypto::Bytes &key, const crypto::Bytes &syncKey,
 const transaction::Store::Lease *ownedSession,std::optional<std::uint64_t> generation) {
    packed::validateSnapshot(s, storageLimits());
    return operation(c, &s, key,syncKey,ownedSession,generation);
}
StorageConfiguration storageConfiguration(const Profile &profile) {
    QByteArray identity;
    QDataStream stream(&identity, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_4_7);
    stream << QStringLiteral("CopyQ-Secure-Sync-local-storage-v1") << profile.device
           << QStringLiteral("synced_tray") << profile.transport << profile.keyFile << profile.stateDirectory;
    if (profile.schema == 3) stream << QStringLiteral("password-key-vault-v1") << profile.vaultDirectory;
    if(!profile.predecessorBinding.isEmpty())stream<<QStringLiteral("successor-cache-v1")<<profile.predecessorBinding;
    return {profile, (profile.schema == 3 ? QStringLiteral("CqsStandaloneStorageV2-") : QStringLiteral("CqsStandaloneStorageV1-")) +
        QString::fromLatin1(QCryptographicHash::hash(identity, QCryptographicHash::Sha256).toHex())};
}
void initializeStorage(const StorageConfiguration &c, const crypto::Bytes &localKey, const crypto::Bytes &syncKey,const transaction::Store::Lease *ownedSession) {
    if (!c.profile.standaloneStorage || !validateProfile(c.profile, false).isEmpty()) throw packed::Error();
    std::async(std::launch::async, [c, &localKey, &syncKey,ownedSession] {
        auto ownership=!ownedSession?acquireStorageSession(c):nullptr;
        const Key key{localKey};
        state::Limits bounds; bounds.snapshot = storageLimits();
        state::FileStore store(path(c.profile.stateDirectory), c.binding.toStdString(), key.bytes, bounds);
        const auto lease = store.lock();
        if (!lease) throw packed::Error();
        transaction::Record initial{2,c.binding.toStdString(),0,{},{}};
        initial.local=transaction::Snapshot{};initial.keyIdentity=syncKeyIdentity(syncKey);
        store.initialize(initial); // Explicit, create-only.
        validate(store.load(), c,syncKey);
    }).get();
}
transaction::Record checkpointRecord(const std::string &binding, const std::string &device,
    const transaction::Snapshot &snapshot, std::uint64_t generation, const std::vector<std::string> &parents) {
    events::Event event; event.revision = {history::makeId(device, generation), device, generation, parents};
    event.items = pack(snapshot); for (const auto &item : event.items) event.plaintextBytes += item.size();
    return {1, binding, generation, transaction::Head{std::move(event), snapshot}, {}};
}
void validateStorageRecord(const transaction::Record &r, const StorageConfiguration &c, const crypto::Bytes &syncKey) { validate(r, c,syncKey); }
void migrateStorageState(const StorageConfiguration &c,const crypto::Bytes &localKey,const crypto::Bytes &syncKey,const transaction::Store::Lease *ownedSession) {
    if(!c.profile.standaloneStorage||!validateProfile(c.profile,false).isEmpty())throw packed::Error();
    std::async(std::launch::async,[&]{auto ownership=!ownedSession?acquireStorageSession(c):nullptr;
        state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),localKey);
        const auto lease=store.lock();if(!lease)throw packed::Error();
        const auto before=store.load();validate(before,c,syncKey);
        if(before.schema>=2)return; // Idempotent retry after an unconfirmed migration.
        auto next=before;next.schema=2;++next.generation;next.local=before.head?before.head->snapshot:transaction::Snapshot{};
        next.head.reset();next.pending.reset();next.keyIdentity=syncKeyIdentity(syncKey);
        store.commit(before,next);const auto actual=store.load();validate(actual,c,syncKey);
        const Key actualBytes{state::serialize(actual)},wantedBytes{state::serialize(next)};
        if(actualBytes.bytes!=wantedBytes.bytes)throw packed::Error();
    }).get();
}
} // namespace cqs::native
