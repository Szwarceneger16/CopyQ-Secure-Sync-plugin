// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_lab.h"
#include "model_clipboard.h"
#include "state_store.h"
#include "item/clipboardmodel.h"
#include "common/contenttype.h"
#include "test_check.h"
#include <QBuffer>
#include <QCoreApplication>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QPluginLoader>
#include <QProcess>
#include <QSaveFile>
#include <QTemporaryDir>
#include <cstdlib>
#include <functional>
#include <iostream>
#ifdef Q_OS_WIN
#include "windows_test_acl.h"
#else
#include <sys/stat.h>
#endif

using cqs::transaction::Snapshot;
namespace {
QString module;
int passed = 0;
std::filesystem::path path(const QString &s) {
#ifdef Q_OS_WIN
    return std::filesystem::path(s.toStdWString());
#else
    return std::filesystem::path(s.toUtf8().toStdString());
#endif
}
void directory(const QString &name) {
#ifdef Q_OS_WIN
    cqs::testing::directory(path(name));
#else
    CHECK(QDir().mkdir(name)); CHECK(::chmod(QFile::encodeName(name).constData(), 0700) == 0);
#endif
}
void write(const QString &name, const QByteArray &bytes) {
#ifdef Q_OS_WIN
    cqs::testing::write(path(name), bytes.toStdString());
#else
    QFile f(name); CHECK(f.open(QIODevice::WriteOnly)); CHECK(f.write(bytes) == bytes.size()); f.close();
    CHECK(::chmod(QFile::encodeName(name).constData(), 0600) == 0);
#endif
}
QByteArray bytes(const QString &name) { QFile f(name); CHECK(f.open(QIODevice::ReadOnly)); return f.readAll(); }
QVariantMap text(const QByteArray &s) { return {{"text/plain", s}}; }
void put(ClipboardModel &model, const QVariantMap &map) {
    CHECK(model.insertRows(model.rowCount(), 1));
    CHECK(model.setData(model.index(model.rowCount()-1, 0), map, contentType::data));
}
Snapshot snapshot(ClipboardModel &model) {
    cqs::native::ModelAccess a; a.readable = [] { return true; };
    cqs::native::ModelClipboard adapter(&model, std::move(a)); return adapter.capture({}).snapshot;
}
class Fixture {
public:
    QString root;
    QPluginLoader loader;
    ItemLoaderInterface *plugin;
    ClipboardModel model;
    ItemSaverPtr saver;
    Fixture(const QString &r, bool create) : root(r), loader(module) {
        qputenv("CQS_STANDALONE_LAB", "1");
        qputenv("CQS_LAB_STATE_DIR", (root + "/state").toUtf8());
        qputenv("CQS_LAB_KEY_FILE", (root + "/key").toUtf8());
        qputenv("CQS_LAB_CREATE", create ? "1" : "0");
        if (create) { directory(root); directory(root + "/state"); write(root + "/key", QByteArray(32, 'q')); }
        auto *object = loader.instance(); if (!object) std::cerr << loader.errorString().toStdString() << std::endl;
        CHECK(object); plugin = qobject_cast<ItemLoaderInterface *>(object); CHECK(plugin);
    }
    ~Fixture() { saver.reset(); CHECK(loader.unload()); }
    bool initialize(int maximum = 200) {
        saver = plugin->initializeTab(cqs::lab::Tab, &model, maximum); return bool(saver);
    }
    QByteArray save() {
        QByteArray marker; QBuffer buffer(&marker); CHECK(buffer.open(QIODevice::WriteOnly));
        CHECK(saver->saveItems(cqs::lab::Tab, model, &buffer)); return marker;
    }
    bool load(const QByteArray &marker, int maximum = 200) {
        QBuffer buffer; buffer.setData(marker); CHECK(buffer.open(QIODevice::ReadOnly));
        saver = plugin->loadItems(cqs::lab::Tab, &model, &buffer, maximum); return bool(saver);
    }
    QString record() const { return root + "/state/" + QString::fromLatin1(cqs::state::FileStore::RecordName); }
};
void test(const char *name, const std::function<void()> &body) {
    std::cout << "RUN " << name << std::endl; body(); ++passed; std::cout << "PASS " << name << std::endl;
}
} // namespace
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv); CHECK(argc >= 2); module = QString::fromLocal8Bit(argv[1]);
    if (argc == 4 && QString::fromLocal8Bit(argv[2]) == "--interrupt") {
        Fixture f(QString::fromLocal8Bit(argv[3]), false); CHECK(f.initialize());
        CHECK(f.model.removeRows(0, f.model.rowCount())); put(f.model, text("after interruption"));
        class StopDevice final : public QIODevice {
        public:
            StopDevice() { open(WriteOnly); }
            qint64 readData(char *, qint64) override { return -1; }
            qint64 writeData(const char *, qint64) override { std::_Exit(73); }
        } device;
        f.saver->saveItems(cqs::lab::Tab, f.model, &device); return 99;
    }
    QTemporaryDir temp; CHECK(temp.isValid()); int count = 0;
    const auto root = [&] { return temp.path() + "/case-" + QString::number(++count); };
    test("separate module loads through unchanged CopyQ 17 ABI and claims only opt-in lab tab", [&] {
        Fixture f(root(), true); CHECK(f.plugin->id() == "securesynclab");
        CHECK(f.plugin->canSaveItems(cqs::lab::Tab)); CHECK(!f.plugin->canSaveItems("synced_tray"));
        CHECK(!f.plugin->supportsEncryption()); CHECK(f.initialize());
        CHECK(f.model.property("_copyq_verified_tab_bridge_v1").isNull());
        f.plugin->setEnabled(false); CHECK(!f.plugin->canSaveItems(cqs::lab::Tab));
        QBuffer b; b.open(QIODevice::WriteOnly); CHECK(!f.saver->saveItems(cqs::lab::Tab, f.model, &b));
    });
    test("binary ordered MIME and empty items survive module unload and encrypted disk reload", [&] {
        const auto r = root(); QByteArray marker; Snapshot wanted;
        { Fixture f(r, true); CHECK(f.initialize());
          put(f.model, text(QByteArray("a\0\xff\r\n", 5))); put(f.model, {});
          put(f.model, {{"image/png", QByteArray("\x89\0\xff", 3)}, {"text/html", QByteArray("<b>lab</b>")}});
          wanted = snapshot(f.model); marker = f.save(); CHECK(marker.size() == 16);
          CHECK(!marker.contains("lab</b>")); CHECK(!bytes(f.record()).contains("lab</b>")); }
        Fixture f(r, false); QBuffer recognized; recognized.setData(marker); recognized.open(QIODevice::ReadOnly);
        CHECK(f.plugin->canLoadItems(&recognized));
        CHECK(f.load(marker)); CHECK(snapshot(f.model) == wanted);
    });
    test("stale CopyQ cache loads newest authoritative checkpoint after hard interruption", [&] {
        const auto r = root(); QByteArray old;
        { Fixture f(r, true); CHECK(f.initialize()); put(f.model, text("before")); old = f.save(); }
        QProcess child; child.start(QCoreApplication::applicationFilePath(), {module, "--interrupt", r});
        CHECK(child.waitForFinished(30000)); CHECK(child.exitCode() == 73);
        Fixture f(r, false); CHECK(f.load(old)); CHECK(snapshot(f.model)[0].at("text/plain") == cqs::crypto::Bytes({'a','f','t','e','r',' ','i','n','t','e','r','r','u','p','t','i','o','n'}));
    });
    test("missing CopyQ cache does not reset existing authoritative snapshot", [&] {
        const auto r = root();
        { Fixture f(r, true); CHECK(f.initialize()); put(f.model, text("recover without cache")); f.save(); }
        Fixture f(r, false); CHECK(f.initialize()); CHECK(f.model.rowCount() == 1);
    });
    test("empty tab differs from one empty item across restart", [&] {
        const auto r = root(); QByteArray marker;
        { Fixture f(r, true); CHECK(f.initialize()); put(f.model, {}); marker = f.save(); }
        { Fixture f(r, false); CHECK(f.load(marker)); CHECK(f.model.rowCount() == 1);
          CHECK(f.model.removeRows(0,1)); marker = f.save(); }
        Fixture f(r, false); CHECK(f.load(marker)); CHECK(f.model.rowCount() == 0);
    });
    test("wrong key refuses load without replacing record or creating an empty tab", [&] {
        const auto r = root(); QByteArray marker, record;
        { Fixture f(r, true); CHECK(f.initialize()); put(f.model, text("keep")); marker = f.save(); record = bytes(f.record()); }
        write(r + "/key", QByteArray(32, 'x'));
        Fixture f(r, false); CHECK(!f.load(marker)); CHECK(f.model.rowCount() == 0); CHECK(bytes(f.record()) == record);
    });
    test("corrupted checkpoint refuses load without reset", [&] {
        const auto r = root(); QByteArray marker, corrupt;
        { Fixture f(r, true); CHECK(f.initialize()); marker = f.save(); corrupt = bytes(f.record());
          corrupt[corrupt.size()-1] = char(corrupt.at(corrupt.size()-1) ^ 1); write(f.record(), corrupt); }
        Fixture f(r, false); CHECK(!f.load(marker)); CHECK(bytes(f.record()) == corrupt);
    });
    test("missing private record is not silently initialized on restart", [&] {
        const auto r = root(); QByteArray marker;
        { Fixture f(r, true); CHECK(f.initialize()); marker = f.save(); CHECK(QFile::remove(f.record())); }
        Fixture f(r, false); CHECK(!f.load(marker)); CHECK(!f.initialize()); CHECK(!QFile::exists(f.record()));
    });
    test("newer cache detects a rolled-back authoritative checkpoint", [&] {
        const auto r = root(); QByteArray marker;
        { Fixture f(r, true); CHECK(f.initialize()); marker = f.save(); }
        QDataStream stream(&marker, QIODevice::ReadWrite); stream.setVersion(QDataStream::Qt_4_7); stream.device()->seek(8); stream << quint64(99);
        CHECK(marker.left(8) == "CQSLAB01");
        Fixture f(r, false); CHECK(!f.load(marker)); CHECK(f.model.rowCount() == 0);
    });
    test("capacity refusal preserves durable data rather than cropping it", [&] {
        const auto r = root(); QByteArray marker;
        { Fixture f(r, true); CHECK(f.initialize()); put(f.model, text("one")); put(f.model, text("two")); marker = f.save(); }
        Fixture f(r, false); const auto original = bytes(f.record()); CHECK(!f.load(marker, 1)); CHECK(bytes(f.record()) == original);
    });
    test("wrong model and unsupported MIME never write a checkpoint", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); const auto original = bytes(f.record());
        ClipboardModel other; QBuffer buffer; buffer.open(QIODevice::WriteOnly);
        CHECK(!f.saver->saveItems(cqs::lab::Tab, other, &buffer)); CHECK(bytes(f.record()) == original);
        put(f.model, {{"text/plain", QStringLiteral("unsupported")}});
        CHECK(!f.saver->saveItems(cqs::lab::Tab, f.model, &buffer)); CHECK(bytes(f.record()) == original);
    });
    test("precommit key read failure preserves previous disk checkpoint", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); put(f.model, text("old")); f.save(); const auto original = bytes(f.record());
        CHECK(QFile::remove(f.root + "/key")); put(f.model, text("new")); QBuffer buffer; buffer.open(QIODevice::WriteOnly);
        CHECK(!f.saver->saveItems(cqs::lab::Tab, f.model, &buffer)); CHECK(bytes(f.record()) == original);
    });
    std::cout << "PASS " << passed << " standalone module storage scenarios\n";
}
