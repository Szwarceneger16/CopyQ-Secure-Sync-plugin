// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_clipboard.h"
#include "tab_persistence.h"
#include "verified_save_file.h"
#include "state_store.h"
#include "packed_items.h"
#include "test_check.h"
#include "item/clipboardmodel.h"
#include "item/serialize.h"
#include "common/contenttype.h"
#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QProcess>
#include <QPluginLoader>
#include <QSaveFile>
#include <QTemporaryDir>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <thread>
#ifdef _WIN32
#include "windows_test_acl.h"
#else
#include <sys/stat.h>
#endif

// Only the configuration location is a test seam. Encryption, serialization,
// blob storage, OS flush, QSaveFile rename, readback and CQS FileStore are real.
namespace { QString testRoot; int passed = 0; }
QString itemDataPath() { return testRoot + "/blobs"; }
QString configurationFilePath(const char *suffix) { return testRoot + '/' + QString::fromLatin1(suffix); }
bool ensureSettingsDirectoryExists() { return QDir(testRoot).exists(); }
namespace {
using namespace copyq::sync;
using cqs::native::HostClipboard;
using cqs::native::ModelError;
using cqs::transaction::Snapshot;
using cqs::transaction::Importer;
using cqs::transaction::ImportMode;
using cqs::transaction::Recovery;
namespace fs = std::filesystem;
fs::path path(const QString &s) {
#ifdef _WIN32
    return fs::path(s.toStdWString());
#else
    return fs::path(s.toStdString());
#endif
}
void privateDirectory(const QString &name) {
#ifdef _WIN32
    cqs::testing::directory(path(name));
#else
    CHECK(QDir().mkpath(name)); CHECK(::chmod(QFile::encodeName(name).constData(), 0700) == 0);
#endif
}
QVariantMap text(const QByteArray &bytes) { return {{"text/plain", bytes}}; }
void put(ClipboardModel &model, const QVariantMap &map) {
    CHECK(model.insertRows(model.rowCount(), 1));
    CHECK(model.setData(model.index(model.rowCount() - 1, 0), map, contentType::data));
}
QByteArray contents(const QString &name) { QFile f(name); CHECK(f.open(QIODevice::ReadOnly)); return f.readAll(); }
void write(const QString &name, const QByteArray &bytes) {
    QFile f(name); CHECK(f.open(QIODevice::WriteOnly)); CHECK(f.write(bytes) == bytes.size());
}
void refused(const std::function<void()> &body) {
    bool caught = false; try { body(); } catch (const ModelError &) { caught = true; } CHECK(caught);
}
cqs::crypto::Bytes syncKey() { return cqs::crypto::Bytes(32, 0x42); } // public fixture key
struct Fixture {
    QString root, file;
    ClipboardBrowserSharedPtr shared = std::make_shared<ClipboardBrowserShared>();
    ClipboardModel model;
    ItemSaverPtr saver;
    bool loaded = true, editor = false, stored = true;
    std::unique_ptr<PersistentTab> bridge;
    std::unique_ptr<HostClipboard> clipboard;
    Fixture(QString directory, Items initial = {}, int threshold = -1, int maximumItems = 10000)
        : root(std::move(directory)), file(root + "/tab.dat") {
        testRoot = root;
        if (!QDir(root).exists()) privateDirectory(root);
        shared->tabsEncrypted = true;
        CHECK(shared->encryptionKey.importDEK(QByteArray(32, 'K'))); // public CopyQ fixture DEK
        saver = std::make_shared<NativeTabSaver>(threshold, shared);
        for (const auto &item : initial) put(model, item);
        if (QFile::exists(file)) {
            if (model.rowCount()) CHECK(model.removeRows(0, model.rowCount()));
            QFile f(file); CHECK(f.open(QIODevice::ReadOnly));
            CHECK(deserializeData(&model, &f, &shared->encryptionKey));
        } else {
            QSaveFile f(file); CHECK(f.open(QIODevice::WriteOnly));
            CHECK(saver->saveItems("synced_tray", model, &f)); CHECK(f.commit());
        }
        bridge = std::make_unique<PersistentTab>("synced_tray", &model, maximumItems, Access{
            [this] { return loaded && stored && shared->tabsEncrypted && shared->encryptionKey.isValid(); },
            [this] { return !editor; }, [this] { return saver; }, [this] { return file; }}, nullptr);
        clipboard = HostClipboard::bind(&model, "synced_tray"); CHECK(clipboard);
    }
    Snapshot snapshot() { return clipboard->capture({}).snapshot; }
    Snapshot replace(const Snapshot &desired) {
        const auto view = clipboard->replace(clipboard->capture({}), desired);
        return clipboard->persist(view, {});
    }
};
std::string envelope() {
    const auto item = serializeData(text("transaction target")).toBase64().toStdString();
    const std::string header = "{\"device\":\"host-test\",\"parents\":[],\"protocol\":\"copyq-secure-sync-v1\",\"seq\":1}";
    const std::string plain = "{\"items\":[\"" + item + "\"],\"tab\":\"synced_tray\",\"v\":1}";
    constexpr char domain[] = "CopyQ-Secure-Sync-event-v1";
    cqs::crypto::Bytes aad(domain, domain + sizeof(domain)); aad.insert(aad.end(), header.begin(), header.end());
    const auto nonce = cqs::crypto::random(12);
    const auto compressed = cqs::crypto::zlibCompress(cqs::crypto::Bytes(plain.begin(), plain.end()));
    const auto cipher = cqs::crypto::aes256GcmEncrypt(syncKey(), nonce, compressed, aad);
    const auto b64 = [](const cqs::crypto::Bytes &b) { return QByteArray(reinterpret_cast<const char *>(b.data()), qsizetype(b.size())).toBase64().toStdString(); };
    return "{\"header\":" + header + ",\"nonce\":\"" + b64(nonce) + "\",\"ciphertext\":\"" + b64(cipher) + "\"}";
}
void initializeStore(const QString &directory) {
    privateDirectory(directory);
    cqs::state::FileStore store(path(directory), "host-test-binding", syncKey());
    const auto lease = store.lock(); CHECK(lease); store.initialize();
}
void test(const char *name, const std::function<void()> &body) {
    testHook = {}; std::cout << "RUN " << name << std::endl;
    try {
        body();
    } catch (const ModelError &error) {
        std::cerr << "FAIL " << name << ": " << error.what()
                  << " (model error " << static_cast<int>(error.code()) << ")" << std::endl;
        std::exit(EXIT_FAILURE);
    } catch (const std::exception &error) {
        std::cerr << "FAIL " << name << ": " << error.what() << std::endl;
        std::exit(EXIT_FAILURE);
    }
    testHook = {}; ++passed; std::cout << "PASS " << name << std::endl;
}
} // namespace
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    CHECK(Encryption::initialize()); // Must fail, never SKIP, without a real provider.
    registerDataFileConverter();
    if (argc == 4 && QString::fromLocal8Bit(argv[1]) == "--interrupt") {
        Fixture f(QString::fromLocal8Bit(argv[2]));
        const auto state = f.root + "/state"; initializeStore(state);
        cqs::state::FileStore store(path(state), "host-test-binding", syncKey());
        const auto bytes = envelope();
        cqs::events::AuthenticatedHistory history(syncKey(), {{cqs::history::makeId("host-test", 1), bytes}});
        const bool after = QString::fromLocal8Bit(argv[3]) == "after";
        testHook = [after](Stage stage) { if (stage == (after ? Stage::AfterCommit : Stage::BeforeCommit)) std::_Exit(73); return true; };
        Importer importer("host-test-binding", store, *f.clipboard); importer.importTip(history, ImportMode::Join);
        return 99;
    }
    QTemporaryDir temp; CHECK(temp.isValid());
    int sequence = 0;
    const auto directory = [&] { return temp.path() + "/case-" + QString::number(++sequence); };
#ifdef Q_OS_WIN
    test("Qt temporary close retains a Windows handle that blocks native replacement", [&] {
        const auto root = directory(); privateDirectory(root);
        const auto target = root + "/replacement.dat";
        write(target, "old");
        QTemporaryFile temporary(target + ".cqs-XXXXXX"); CHECK(temporary.open());
        CHECK(temporary.write("new", 3) == 3); CHECK(flushFileToDisk(temporary));
        const auto temporaryName = temporary.fileName();
        temporary.close(); CHECK(!temporary.isOpen());
        const auto source = temporaryName.toStdWString(), destination = target.toStdWString();
        CHECK(!MoveFileExW(source.c_str(), destination.c_str(),
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
        CHECK(GetLastError() == ERROR_SHARING_VIOLATION);
        CHECK(contents(target) == "old"); CHECK(contents(temporaryName) == "new");
    });
#endif
    test("verified replacement releases the native temporary handle before rename", [&] {
        const auto root = directory(); privateDirectory(root);
        const auto target = root + "/replacement.dat";
        write(target, "old");
        VerifiedSaveFile save(target); CHECK(save.open());
        CHECK(save.device().write("new", 3) == 3);
        CHECK(flushFileToDisk(save.device()));
        CHECK(save.commit()); CHECK(contents(target) == "new");
        CHECK(QDir(root).entryList({"*.cqs-*"}, QDir::Files).isEmpty());
#ifdef Q_OS_WIN
        // A second attempt must fail safely after ownership has been consumed.
        CHECK(!save.commit());
#endif
    });
    test("actual encrypted save, ordered binary MIME, empty item and detached readback", [&] {
        Fixture f(directory(), {text("old")});
        const Snapshot desired{{{"text/plain", {'n',0,0xff,'\r','\n'}}, {"text/html", {'<','b','>'}}}, {}, {{"image/png", {137,80,0,255}}}};
        CHECK(f.replace(desired) == desired); CHECK(f.snapshot() == desired);
        CHECK(!contents(f.file).contains("<b>"));
        QFile disk(f.file); CHECK(disk.open(QIODevice::ReadOnly)); ClipboardModel detached;
        CHECK(deserializeData(&detached, &disk, &f.shared->encryptionKey)); CHECK(detached.rowCount() == 3);
        disk.seek(0); ClipboardModel withoutKey; CHECK(!deserializeData(&withoutKey, &disk));
    });
    test("empty tab is distinct from an empty item", [&] {
        Fixture f(directory(), {text("old")}); CHECK(f.replace({}).empty());
        CHECK(f.replace(Snapshot{{}}).size() == 1); CHECK(f.replace({}).empty());
    });
    test("large native encrypted DataFile survives readback and restart", [&] {
        const auto root = directory(); Snapshot wanted{{{"application/octet-stream", cqs::crypto::Bytes(300000, 0x7b)}}};
        { Fixture f(root, {}, 128); CHECK(f.replace(wanted) == wanted); }
        Fixture reopened(root, {}, 128); CHECK(reopened.snapshot() == wanted);
        CHECK(reopened.clipboard->persist(reopened.clipboard->capture({}), {}) == wanted);
    });
    test("corrupted external encrypted blob is refused without flattening to empty bytes", [&] {
        const auto root = directory();
        { Fixture f(root, {}, 128); CHECK(f.replace({{{"application/octet-stream", cqs::crypto::Bytes(4096,0x77)}}}).size() == 1); }
        Fixture reopened(root, {}, 128);
        QDirIterator it(itemDataPath(), {"*.dat"}, QDir::Files, QDirIterator::Subdirectories); CHECK(it.hasNext());
        write(it.next(), "corruption"); refused([&] { reopened.snapshot(); });
    });
    test("vanilla host and wrong tab or model cannot bind", [&] {
        ClipboardModel plain; CHECK(!HostClipboard::bind(&plain, "synced_tray"));
        Fixture f(directory()); CHECK(!HostClipboard::bind(&f.model, "other"));
        plain.setProperty(bridgeProperty, f.model.property(bridgeProperty)); CHECK(!HostClipboard::bind(&plain, "synced_tray"));
    });
    test("actual module ignores the historical host extension", [&] {
        CHECK(argc == 2); QPluginLoader loader(QString::fromLocal8Bit(argv[1]));
        auto *object = loader.instance(); CHECK(object);
        auto *plugin = qobject_cast<ItemLoaderInterface *>(object); CHECK(plugin);
        CHECK(!object->property("verifiedTabBindings").isValid());
        Fixture f(directory()); const auto observed=plugin->transformSaver(f.saver, &f.model);CHECK(observed);
        const QVariantMap sample{{"text/plain",QByteArray("public ordinary data")}};
        CHECK(observed->copyItem(f.model,sample)==f.saver->copyItem(f.model,sample));
        CHECK(!object->property("verifiedTabBindings").isValid());
        CHECK(f.model.rowCount() == 0); CHECK(!plugin->canSaveItems("synced_tray"));
        plugin->setEnabled(false); CHECK(!object->property("verifiedTabBindings").isValid());
        CHECK(plugin->transformSaver(f.saver, &f.model) == f.saver);
        CHECK(!object->property("verifiedTabBindings").isValid());
    });
    test("destroyed endpoint leaves a safe null capability", [&] {
        Fixture f(directory()); f.bridge.reset(); refused([&] { f.snapshot(); });
        CHECK(!HostClipboard::bind(&f.model, "synced_tray"));
    });
    test("invalidated or renamed host binding refuses before replacement", [&] {
        Fixture f(directory(), {text("old")}); const auto before = f.snapshot(); f.bridge->invalidate();
        refused([&] { f.clipboard->replace({before, 0}, {}); }); CHECK(f.model.rowCount() == 1);
    });
    for (int guard = 0; guard < 4; ++guard) test("locked, editor, disabled store and unencrypted host refuse writes", [&, guard] {
        Fixture f(directory(), {text("old")}); const auto view = f.clipboard->capture({}); const auto disk = contents(f.file);
        if (guard == 0) f.shared->encryptionKey.clear();
        if (guard == 1) f.editor = true;
        if (guard == 2) f.stored = false;
        if (guard == 3) f.shared->tabsEncrypted = false;
        refused([&] { f.clipboard->replace(view, {}); }); CHECK(f.model.rowCount() == 1); CHECK(contents(f.file) == disk);
    });
    test("capacity is checked before deleting the first row", [&] {
        Fixture f(directory(), {text("old")}, -1, 1); const auto view = f.clipboard->capture({});
        bool caught = false; try { f.clipboard->replace(view, Snapshot(2)); } catch (const cqs::packed::Error &) { caught = true; }
        CHECK(caught); CHECK(f.model.rowCount() == 1);
    });
    test("wrong thread is refused", [&] {
        Fixture f(directory()); bool caught = false;
        std::thread worker([&] { try { f.snapshot(); } catch (const ModelError &) { caught = true; } }); worker.join(); CHECK(caught);
    });
    for (const auto stage : {Stage::Write, Stage::Flush, Stage::Sync, Stage::BeforeCommit}) test("precommit failure preserves old authoritative file", [&, stage] {
        Fixture f(directory(), {text("old")}); const auto disk = contents(f.file);
        const auto view = f.clipboard->replace(f.clipboard->capture({}), {{{"text/plain", {'N'}}}});
        testHook = [stage](Stage current) { return current != stage; };
        refused([&] { f.clipboard->persist(view, {}); }); CHECK(contents(f.file) == disk);
    });
    for (const auto stage : {Stage::AfterCommit, Stage::Readback, Stage::DirectorySync}) test("postcommit failure never reports confirmation or rolls back", [&, stage] {
        Fixture f(directory(), {text("old")}); const auto disk = contents(f.file);
        const auto view = f.clipboard->replace(f.clipboard->capture({}), {{{"text/plain", {'N'}}}});
        testHook = [stage](Stage current) { return current != stage; };
        refused([&] { f.clipboard->persist(view, {}); }); CHECK(contents(f.file) != disk);
        CHECK(f.snapshot() == view.snapshot);
    });
    test("ABA during saver barrier cancels before commit", [&] {
        Fixture f(directory(), {text("old")}); const auto disk = contents(f.file); const auto view = f.clipboard->capture({});
        testHook = [&](Stage current) { if (current == Stage::BeforeCommit) {
            CHECK(f.model.setData(f.model.index(0,0), text("edit"), contentType::data));
            CHECK(f.model.setData(f.model.index(0,0), text("old"), contentType::data));
        } return true; };
        refused([&] { f.clipboard->persist(view, {}); }); CHECK(contents(f.file) == disk);
    });
    test("readback substitution is refused before parsing untrusted bytes", [&] {
        Fixture f(directory(), {text("old")}); const auto view = f.clipboard->capture({});
        testHook = [&](Stage current) { if (current == Stage::Readback) write(f.file, QByteArray(4096, '\xff')); return true; };
        refused([&] { f.clipboard->persist(view, {}); }); CHECK(f.snapshot() == view.snapshot);
    });
    test("missing file is not initialized", [&] {
        Fixture f(directory()); CHECK(QFile::remove(f.file)); refused([&] { f.clipboard->persist(f.clipboard->capture({}), {}); });
        CHECK(!QFile::exists(f.file));
    });
    test("actual rename failure is unconfirmed and does not discard local data", [&] {
        Fixture f(directory(), {text("old")}); const auto view = f.clipboard->capture({}); const auto disk = contents(f.file);
        testHook = [&](Stage current) { if (current == Stage::CommitAttempt) {
            CHECK(QFile::rename(f.file, f.file + ".saved")); CHECK(QDir().mkdir(f.file));
        } return true; };
        refused([&] { f.clipboard->persist(view, {}); });
        CHECK(contents(f.file + ".saved") == disk); CHECK(f.snapshot() == view.snapshot);
    });
    test("unsupported saver is refused before any row removal", [&] {
        struct OtherSaver final : ItemSaverInterface {};
        Fixture f(directory(), {text("old")}); const auto view = f.clipboard->capture({});
        f.saver = std::make_shared<OtherSaver>(); refused([&] { f.clipboard->replace(view, {}); }); CHECK(f.model.rowCount() == 1);
    });
    test("transaction clears durable journal only after real encrypted readback", [&] {
        Fixture f(directory()); const auto state = f.root + "/state"; initializeStore(state);
        cqs::state::FileStore store(path(state), "host-test-binding", syncKey());
        const auto bytes = envelope(); cqs::events::AuthenticatedHistory history(syncKey(), {{cqs::history::makeId("host-test", 1), bytes}});
        Importer importer("host-test-binding", store, *f.clipboard); CHECK(importer.importTip(history, ImportMode::Join) == cqs::transaction::Result::Applied);
        const auto lease = store.lock(); const auto record = store.load(); CHECK(record.head && !record.pending);
        CHECK(record.head->snapshot == f.snapshot()); CHECK(!contents(f.file).contains("transaction target"));
    });
    test("unconfirmed readback retains encrypted journal and preserves later manual edits", [&] {
        Fixture f(directory()); const auto state = f.root + "/state"; initializeStore(state);
        cqs::state::FileStore store(path(state), "host-test-binding", syncKey());
        const auto bytes = envelope(); cqs::events::AuthenticatedHistory history(syncKey(), {{cqs::history::makeId("host-test", 1), bytes}});
        Importer importer("host-test-binding", store, *f.clipboard);
        testHook = [](Stage stage) { return stage != Stage::Readback; };
        refused([&] { importer.importTip(history, ImportMode::Join); }); testHook = {};
        { const auto lease = store.lock(); const auto record = store.load(); CHECK(record.pending && !record.head); }
        CHECK(!contents(state + '/' + QString::fromLatin1(cqs::state::FileStore::RecordName)).contains("transaction target"));
        CHECK(f.model.setData(f.model.index(0,0), text("manual edit"), contentType::data));
        bool caught = false; try { importer.recover(Recovery::RestoreOriginal); }
        catch (const cqs::transaction::Error &e) { caught = e.code() == cqs::transaction::ErrorCode::LocalChanges; }
        CHECK(caught); CHECK(f.snapshot() == Snapshot({{{"text/plain", {'m','a','n','u','a','l',' ','e','d','i','t'}}}}));
        { const auto lease = store.lock(); CHECK(store.load().pending); }
    });
    for (const auto *when : {"before", "after"}) test("hard process interruption and explicit recovery use actual encrypted disk stores", [&, when] {
        const auto root = directory(); QProcess child;
        child.start(QCoreApplication::applicationFilePath(), {"--interrupt", root, QString::fromLatin1(when)});
        CHECK(child.waitForFinished(30000));
        if (child.exitCode() != 73) std::cerr << child.readAllStandardError().constData();
        CHECK(child.exitCode() == 73);
        Fixture reopened(root); cqs::state::FileStore store(path(root + "/state"), "host-test-binding", syncKey());
        { const auto lease = store.lock(); const auto record = store.load(); CHECK(record.pending && !record.head); }
        Importer importer("host-test-binding", store, *reopened.clipboard);
        CHECK(importer.recover(Recovery::RetryImport) == cqs::transaction::Result::Applied);
        { const auto lease = store.lock(); const auto record = store.load(); CHECK(record.head && !record.pending); CHECK(record.head->snapshot == reopened.snapshot()); }
    });
    std::cout << "PASS " << passed << " real encrypted host persistence scenarios\n";
}
