// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_lab.h"
#include "key_reader.h"
#include "packed_items.h"
#include "state_store.h"
#include <QDataStream>
#include <QIODevice>
#include <filesystem>
#include <future>

namespace cqs::lab {
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
    packed::validateSnapshot(snapshot, limits());
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
    if (packed::decode(result, limits()) != snapshot) throw packed::Error();
    return result;
}
void validate(const transaction::Record &record) {
    if (record.binding != Binding || record.pending ||
        (record.generation == 0 ? bool(record.head) : !record.head)) throw packed::Error();
    if (record.head) {
        const auto &h = *record.head;
        if (h.event.revision.device != "cqs-lab" || h.event.revision.sequence != record.generation ||
            packed::decode(h.event.items, limits()) != h.snapshot) throw packed::Error();
        packed::validateSnapshot(h.snapshot, limits());
    }
}
transaction::Record operation(const Configuration &c, const transaction::Snapshot *snapshot) {
    if (!c.enabled || c.directory.isEmpty() || c.keyFile.isEmpty()) throw packed::Error();
    // The key and all descriptor-based disk work stay in this short-lived worker.
    // Waiting here is deliberate for the synchronous saver contract; this is a
    // bounded prototype, not the production GUI scheduling implementation.
    return std::async(std::launch::async, [c, snapshot] {
        const Key key{native::readKeyStrict(path(c.keyFile))};
        state::Limits bounds; bounds.snapshot = limits(); bounds.recordBytes = 8 * 1024 * 1024;
        state::FileStore store(path(c.directory), Binding, key.bytes, bounds);
        const auto lease = store.lock();
        if (!lease) throw packed::Error();
        if (c.create) {
            try { store.initialize(); }
            catch (const state::Error &e) { if (e.code() != state::ErrorCode::AlreadyInitialized) throw; }
        }
        auto previous = store.load(); validate(previous);
        if (!snapshot || (previous.head && previous.head->snapshot == *snapshot)) return previous;
        auto next = previous;
        ++next.generation; // makeId refuses sequence exhaustion before commit.
        events::Event event;
        event.revision = {history::makeId("cqs-lab", next.generation), "cqs-lab", next.generation, {}};
        if (previous.head) event.revision.parents.push_back(previous.head->event.revision.id);
        event.items = pack(*snapshot);
        for (const auto &item : event.items) event.plaintextBytes += item.size();
        next.head = transaction::Head{std::move(event), *snapshot};
        store.commit(previous, next);
        const auto actual = store.load(); validate(actual);
        const Key actualBytes{state::serialize(actual, bounds)}, wantedBytes{state::serialize(next, bounds)};
        if (actualBytes.bytes != wantedBytes.bytes) throw packed::Error();
        return actual;
    }).get();
}
} // namespace
transaction::Limits limits() {
    transaction::Limits result;
    result.items = 200; result.snapshotBytes = 2 * 1024 * 1024;
    return result;
}
transaction::Record read(const Configuration &c) { return operation(c, nullptr); }
transaction::Record save(const Configuration &c, const transaction::Snapshot &s) {
    packed::validateSnapshot(s, limits());
    return operation(c, &s);
}
} // namespace cqs::lab
