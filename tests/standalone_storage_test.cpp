// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_storage.h"
#include "sync_schedule.h"
#include "transport_watch.h"
#include "profile.h"
#include <QSettings>
#include "model_clipboard.h"
#include "state_store.h"
#include "storage.h"
#include "item/clipboardmodel.h"
#include "item/serialize.h"
#include "common/contenttype.h"
#include "test_check.h"
#include <QElapsedTimer>
#include <QThread>
#include "item/serialize.h"
#include <QBuffer>
#include <QCoreApplication>
#include <QApplication>
#include <QListView>
#include <QTextEdit>
#include <QInputDialog>
#include <QMessageBox>
#include <QAbstractButton>
#include "unified_state.h"
#include <QDataStream>
#include <QDir>
#include <QDirIterator>
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
// Only the upstream fixture serializer can access this disposable blob folder.
// The actual module never links serialize.cpp or a DataFile converter.
namespace { QString fixtureBlobDirectory; }
QString itemDataPath() {
    if (fixtureBlobDirectory.isEmpty()) throw std::runtime_error("Unexpected blob access");
    return fixtureBlobDirectory;
}
struct ConvertibleStorageValue {};
Q_DECLARE_METATYPE(ConvertibleStorageValue)
class PublicExternalEditor final : public QObject {
    Q_OBJECT
public:
    using QObject::QObject;
public slots:
    void start() {}
signals:
    void fileModified(QByteArray,QString,QModelIndex);
    void closed(QObject *,QModelIndex);
};
namespace {
QString module;
int passed = 0, convertedStorageValues = 0;
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
    QByteArray password = "public-fixture-password";
    QPluginLoader loader;
    ItemLoaderInterface *plugin;
    ClipboardModel model;
    ItemSaverPtr saver;
    Fixture(const QString &r, bool create) : root(r), loader(module) {
        if (create) {
            directory(root); directory(root + "/state"); directory(root + "/vault"); directory(root + "/transport");
            directory(root + "/transport/events"); write(root + "/key", QByteArray(32, 'q'));
        }
        auto *object = loader.instance(); if (!object) std::cerr << loader.errorString().toStdString() << std::endl;
        CHECK(object); plugin = qobject_cast<ItemLoaderInterface *>(object); CHECK(plugin);
        configure();
        if (create) CHECK(plugin->scriptCallback({"initializeStorage",password}).toString() == "Initialized");
        else plugin->scriptCallback({"unlockStorage",password});
    }
    cqs::native::Profile profile() const {
        cqs::native::Profile p{"test-pc", root + "/transport", root + "/key", root + "/state"};
        p.standaloneStorage = true; p.vaultDirectory=root+"/vault"; return p;
    }
    void configure() { configure(profile()); }
    void configure(const cqs::native::Profile &p) {
        QSettings settings(root + "/settings.ini", QSettings::IniFormat);
        settings.beginGroup("Plugins/securesync"); cqs::native::saveProfile(settings, p); plugin->loadSettings(settings);
    }
    QVariant call(const QVariantList &arguments) {
        auto result=plugin->scriptCallback(arguments).toString();
        if(result.startsWith("Working:")){
            const auto token=result.mid(8);QElapsedTimer timeout;timeout.start();
            do {QCoreApplication::processEvents();QThread::msleep(1);
                result=plugin->scriptCallback({"operationStatus",token}).toString();
                CHECK(timeout.elapsed()<15000);
            }while(result=="Working");
        }
        return result;
    }
    ~Fixture() { saver.reset(); CHECK(loader.unload()); }
    bool initialize(int maximum = 10000) {
        saver = plugin->initializeTab("synced_tray", &model, maximum); return bool(saver);
    }
    QByteArray save() {
        QByteArray marker; QBuffer buffer(&marker); CHECK(buffer.open(QIODevice::WriteOnly));
        CHECK(saver->saveItems("synced_tray", model, &buffer)); return marker;
    }
    bool load(const QByteArray &marker, int maximum = 10000) {
        QBuffer buffer; buffer.setData(marker); CHECK(buffer.open(QIODevice::ReadOnly));
        saver = plugin->loadItems("synced_tray", &model, &buffer, maximum); return bool(saver);
    }
    QString record() const { return root + "/state/" + QString::fromLatin1(cqs::state::FileStore::RecordName); }
};
class ScriptContext final : public QObject {
    Q_OBJECT
public:
    explicit ScriptContext(Fixture &fixture):f(fixture){}
    ~ScriptContext(){saver.reset();delete model;}
    Fixture &f;ClipboardModel *model=nullptr;ItemSaverPtr saver;bool editor=false,visible=false,currentSynced=false;int stateCalls=0;
    QVariantList scriptArguments;
public slots:
    QVariantList currentArguments(){return scriptArguments;}
    QVariant call(QString method,QVariantList arguments){
        // Independently model CopyQ's public API: tab() only selects script
        // context, show() actually loads; unload refuses a visible tab/editor.
        if(method=="tab")return arguments.isEmpty()?QVariant(QStringList{"Clipboard","synced_tray"}):QVariant();
        if(method=="show"){
            visible=true;currentSynced=true;
            if(!model){model=new ClipboardModel;saver=f.plugin->initializeTab("synced_tray",model,10000);CHECK(saver);}
            return {};
        }
        if(method=="setCurrentTab"){currentSynced=arguments[0].toString()=="synced_tray";return {};}
        if(method=="hide"){visible=false;return {};}
        if(method=="unload"){
            if(editor||(visible&&currentSynced))return QStringList{};
            saver.reset();delete model;model=nullptr;return QStringList{"synced_tray"};
        }
        if(method=="sleep"){QCoreApplication::processEvents();QThread::msleep(1);return {};}
        if(method=="stats")return QStringLiteral("PLUGIN securesync: enabled");
        if(method=="callPlugin"){
            CHECK(arguments[0].toString()=="securesync");
            if(arguments[1].toString()=="joinHistory"||arguments[1].toString()=="seedHistory")++stateCalls;
            if(arguments.size()>2&&arguments[2].isNull())arguments[2]=f.password;
            return f.plugin->scriptCallback(arguments.mid(1));
        }
        CHECK(false);return {};
    }
};
void test(const char *name, const std::function<void()> &body) {
    std::cout << "RUN " << name << std::endl; body(); ++passed; std::cout << "PASS " << name << std::endl;
}
void waitFor(const std::function<bool()> &ready,int limit=4000) {
    QElapsedTimer timer;timer.start();
    while(!ready()) {CHECK(timer.elapsed()<limit);QCoreApplication::processEvents();QThread::msleep(1);}
}
} // namespace
int main(int argc, char **argv) {
    QApplication app(argc, argv); CHECK(argc >= 2); module = QString::fromLocal8Bit(argv[1]);
    if(argc==4&&QString::fromLocal8Bit(argv[2])=="--try-open"){
        Fixture f(QString::fromLocal8Bit(argv[3]),false);return f.initialize()?99:0;
    }
    if (argc == 4 && QString::fromLocal8Bit(argv[2]) == "--interrupt") {
        Fixture f(QString::fromLocal8Bit(argv[3]), false); CHECK(f.initialize());
        CHECK(f.model.removeRows(0, f.model.rowCount())); put(f.model, text("after interruption"));
        class StopDevice final : public QIODevice {
        public:
            StopDevice() { open(WriteOnly); }
            qint64 readData(char *, qint64) override { return -1; }
            qint64 writeData(const char *, qint64) override { std::_Exit(73); }
        } device;
        f.saver->saveItems("synced_tray", f.model, &device); return 99;
    }
    QTemporaryDir temp; CHECK(temp.isValid()); int count = 0;
    const auto root = [&] { return temp.path() + "/case-" + QString::number(++count); };
    test("UI distinguishes verified local saves, pending edits and redacted failures",[&]{
        Fixture f(root(),true);CHECK(f.initialize());
        CHECK(f.plugin->scriptCallback({"userStatus"}).toString().contains("committed tab contents were verified"));
        put(f.model,text("PRIVATE-CLIPBOARD-CONTENT"));
        CHECK(f.plugin->scriptCallback({"diagnostics"}).toString().contains("pending"));
        CHECK(f.plugin->scriptCallback({"userStatus"}).toString().contains("recent edits"));
        CHECK(!f.save().isEmpty());
        CHECK(f.plugin->scriptCallback({"diagnostics"}).toString().contains("verified"));
        const auto secret=f.root+" SECRET-KEY-PASSWORD PRIVATE-CLIPBOARD-CONTENT";
        CHECK(f.plugin->scriptCallback({"userActionResult","syncNow","Unconfirmed: "+secret}).toString()=="Reported");
        const auto status=f.plugin->scriptCallback({"userStatus"}).toString();
        CHECK(status.contains("Recovery required")&&status.contains("Next:")&&!status.contains(secret));
        const auto diagnostic=f.plugin->scriptCallback({"diagnostics"}).toString();
        CHECK(!diagnostic.contains(f.root)&&!diagnostic.contains("SECRET")&&!diagnostic.contains("PRIVATE-CLIPBOARD"));
        CHECK(f.plugin->scriptCallback({"userActionResult","not-an-action",secret}).toString()=="Refused");
    });
    test("reloaded UI retains pending publication guidance after a verified local load and save",[&]{
        Fixture f(root(),true);const QString stats="PLUGIN securesync: enabled";
        CHECK(f.call({"seedHistory",f.password,stats}).toString()=="Applied");
        const auto c=cqs::native::storageConfiguration(f.profile());
        const auto k=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
        const Snapshot local{{{"text/plain",{'N','E','W'}}}};
        cqs::native::saveStorage(c,local,k->local,k->sync);
        const auto before=cqs::native::readStorage(c,k->local,k->sync);
        const auto history=cqs::storage::Directory(path(f.profile().transport)).scan(k->sync);
        cqs::native::reservePublication(c,k,before,*cqs::native::preparePublication(c,k,before,history),nullptr);
        CHECK(f.loader.unload());auto *object=f.loader.instance();CHECK(object);
        f.plugin=qobject_cast<ItemLoaderInterface *>(object);CHECK(f.plugin);f.configure();
        CHECK(f.call({"unlockStorage",f.password}).toString()=="Unlocked");CHECK(f.initialize());
        const auto guidance=f.call({"userStatus"}).toString();
        CHECK(guidance.startsWith("Pending publication")&&guidance.contains("retry reserved publication"));
        CHECK(!f.save().isEmpty());
        CHECK(f.call({"userStatus"}).toString().startsWith("Pending publication"));
        const auto after=cqs::native::readStorage(c,k->local,k->sync);
        CHECK(after.publication&&after.local==local&&after.head->event.revision.sequence==1);
    });
    test("schedule coalesces bursts, bounds continuous edits and polls when idle",[]{
        using cqs::native::SyncSchedule;SyncSchedule s;s.reset(0);CHECK(s.begin(0));s.finish(1,SyncSchedule::Result::Success);
        CHECK(s.delay(30000)==1);CHECK(s.begin(30001));s.changed(30002);s.finish(30003,SyncSchedule::Result::Success);
        CHECK(!s.begin(30501)&&s.begin(30502));s.finish(30503,SyncSchedule::Result::Success);
        for(int now=31000;now<=32900;now+=100)s.changed(now);
        CHECK(s.delay(32999)==1&&s.begin(33000));
    });
    test("schedule backs off a bounded burst, ignores notification noise during cooldown and pauses for review",[]{
        using cqs::native::SyncSchedule;using R=SyncSchedule::Result;SyncSchedule s;s.reset(0);std::int64_t now=0;
        for(auto delay:{1000,2000,4000,8000,16000,30000,60000,60000}){
            CHECK(s.begin(now));s.finish(now,R::Transient);s.changed(now+1);
            CHECK(!s.begin(now+delay-1));now+=delay;
        }
        CHECK(s.begin(now));s.finish(now,R::Success);s.reset(now);CHECK(s.begin(now));
        s.finish(now,R::Review);s.changed(now+100000);CHECK(!s.begin(now+100001)&&s.paused());
        s.reset(now);CHECK(s.begin(now));s.finish(now,R::Locked);s.changed(now+100000);CHECK(!s.begin(now+100001));
        s.reset(now+100002);CHECK(s.begin(now+100002));
        s.finish(now+100002,R::Conflict);s.changed(now+100003);
        CHECK(!s.paused()&&!s.begin(now+100502)&&s.begin(now+100503));
    });
    test("transport notifications rearm new device directories and a recreated events folder",[&]{
        const auto folder=root();directory(folder);directory(folder+"/events");
        cqs::native::TransportWatch watcher;int changes=0;
        QObject::connect(&watcher,&cqs::native::TransportWatch::changed,[&]{++changes;});watcher.setFolder(folder);
        directory(folder+"/events/device");waitFor([&]{return changes>0;});watcher.refresh();
        const int before=changes;write(folder+"/events/device/new.cqs","notification is only a hint");waitFor([&]{return changes>before;});
        watcher.setFolder({});CHECK(QDir(folder+"/events").removeRecursively());watcher.setFolder(folder);
        const int missing=changes;directory(folder+"/events");waitFor([&]{return changes>missing;});watcher.refresh();
        const int restored=changes;directory(folder+"/events/another-device");waitFor([&]{return changes>restored;});
    });
    test("own timer durably coalesces committed edits while automatic synchronization is off",[&]{
        const auto folder=root();Snapshot expected;std::uint64_t initial=0;
        {
            Fixture f(folder,true);CHECK(f.initialize());const auto c=cqs::native::storageConfiguration(f.profile());
            const auto k=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
            initial=cqs::native::readStorage(c,k->local,k->sync).generation;const auto original=bytes(f.record());
            for(int i=0;i<20;++i)put(f.model,text(QByteArray::number(i)));expected=snapshot(f.model);
            CHECK(bytes(f.record())==original);waitFor([&]{return bytes(f.record())!=original;});
            const auto r=cqs::native::readStorage(c,k->local,k->sync);CHECK(r.local==expected&&r.generation==initial+1&&!r.head);
            QElapsedTimer quiet;quiet.start();while(quiet.elapsed()<350){QCoreApplication::processEvents();QThread::msleep(1);}
            CHECK(cqs::native::readStorage(c,k->local,k->sync).generation==r.generation);
        }
        Fixture reopened(folder,false);CHECK(reopened.initialize());CHECK(snapshot(reopened.model)==expected);
    });
    test("scheduled checkpoint retains dirty edits across missing private record and retries after restoration",[&]{
        Fixture f(root(),true);CHECK(f.initialize());const auto original=bytes(f.record());
        CHECK(QFile::rename(f.record(),f.record()+".offline"));put(f.model,text("retained while storage is unavailable"));
        QElapsedTimer wait;wait.start();while(wait.elapsed()<450){QCoreApplication::processEvents();QThread::msleep(1);}
        CHECK(!QFile::exists(f.record())&&bytes(f.record()+".offline")==original);
        CHECK(QFile::rename(f.record()+".offline",f.record()));waitFor([&]{return bytes(f.record())!=original;});
        const auto c=cqs::native::storageConfiguration(f.profile());const auto k=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
        CHECK(cqs::native::readStorage(c,k->local,k->sync).local==snapshot(f.model));
    });
    test("scoped ordinary-tab capture delegates copying and detects edits, wrong model and missing reads",[&]{
        Fixture f(root(),true);ClipboardModel source,foreign;const auto item=text("public source");put(source,item);put(foreign,item);
        auto saver=f.plugin->transformSaver(std::make_shared<ItemSaverInterface>(),&source);
        const QString token(36,'c');const auto original=bytes(f.record());
        CHECK(f.call({"beginNativeCapture",token,0}).toString()=="Refused");
        CHECK(saver->copyItem(source,item)==item);
        CHECK(f.call({"beginNativeCapture",token,1}).toString()=="Started");
        CHECK(f.call({"beginNativeCapture",token,1}).toString()=="Refused");
        CHECK(saver->copyItem(source,item)==item);
        CHECK(f.call({"finishNativeCapture",token}).toString()=="Captured");
        CHECK(f.call({"beginNativeCapture",token,1}).toString()=="Started");
        CHECK(saver->copyItem(source,item)==item);CHECK(source.setData(source.index(0,0),text("edited"),contentType::data));
        CHECK(f.call({"finishNativeCapture",token}).toString().startsWith("Refused"));
        CHECK(source.setData(source.index(0,0),item,contentType::data));
        CHECK(f.call({"beginNativeCapture",token,2}).toString()=="Started");
        CHECK(saver->copyItem(source,item).isEmpty());
        CHECK(f.call({"finishNativeCapture",token}).toString().startsWith("Refused"));
        CHECK(f.call({"beginNativeCapture",token,1}).toString()=="Started");
        CHECK(f.call({"finishNativeCapture",token}).toString().startsWith("Refused"));
        CHECK(f.call({"beginNativeCapture",token,1}).toString()=="Started");
        CHECK(saver->copyItem(source,item)==item);CHECK(saver->copyItem(foreign,item).isEmpty());
        CHECK(f.call({"finishNativeCapture",token}).toString().startsWith("Refused"));
        CHECK(saver->copyItem(source,item)==item);CHECK(bytes(f.record())==original);
    });
    test("visible bound view receives remote data after an active public Qt editor closes",[&]{
        Fixture f(root(),true);const QString stats="PLUGIN securesync: enabled",token(36,'b');
        CHECK(f.call({"seedHistory",f.password,stats}).toString()=="Applied");
        const auto c=cqs::native::storageConfiguration(f.profile());const auto originalKeys=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
        auto peer=f.profile();peer.device="peer-pc";peer.stateDirectory=f.root+"/peer-state";directory(peer.stateDirectory);
        const auto pc=cqs::native::storageConfiguration(peer);auto k=std::make_shared<cqs::native::StorageKeys>();k->sync=originalKeys->sync;k->local=cqs::crypto::Bytes(32,0x45);
        cqs::native::initializeStorage(pc,k->local,k->sync);cqs::native::runStateAction(pc,k,cqs::native::StateAction::Join);
        const cqs::transaction::Snapshot received{{{"text/plain",{'R','E','M','O','T','E',0,255}}}};
        cqs::native::saveStorage(pc,received,k->local,k->sync);cqs::native::runStateAction(pc,k,cqs::native::StateAction::Publish);
        ScriptContext context(f);context.call("show",{"synced_tray"});QListView view;view.setModel(context.model);view.show();
        auto *editor=new QTextEdit(&view);editor->setPlainText("public unsaved editor fixture");
        CHECK(f.call({"startAutomaticSync",token,stats}).toString()=="Started");
        auto cycle=[&]{waitFor([&]{return f.call({"automaticCycleDelay",token}).toInt()==0;});
            CHECK(f.call({"automaticCycle",token,stats}).toString()=="Working");QElapsedTimer time;time.start();
            while(f.call({"automaticSyncStatus",token}).toString()=="Working"&&time.elapsed()<10000){QCoreApplication::processEvents();QThread::msleep(1);}};
        cycle();CHECK(f.call({"automaticSyncStatus",token}).toString()=="Waiting: active editor or unverified view");
        CHECK(context.model->rowCount()==0&&editor->toPlainText()=="public unsaved editor fixture");
        delete editor;auto *external=new PublicExternalEditor(&view);cycle();
        CHECK(f.call({"automaticSyncStatus",token}).toString()=="Waiting: active editor or unverified view");
        CHECK(context.model->rowCount()==0);delete external;
        cycle();CHECK(f.call({"automaticSyncStatus",token}).toString()=="Applied");
        CHECK(snapshot(*context.model)==received);CHECK(view.isVisible());
        put(*context.model,text("later local edit"));
        const Snapshot newer{{{"text/plain",{'N','E','W'}}}};
        cqs::native::saveStorage(pc,newer,k->local,k->sync);cqs::native::runStateAction(pc,k,cqs::native::StateAction::Publish);
        cycle();CHECK(f.call({"automaticSyncStatus",token}).toString().startsWith("Conflict"));
        const auto before=cqs::native::readStorage(c,originalKeys->local,originalKeys->sync);
        QTimer decisions;decisions.setInterval(10);bool disabled=false;
        QObject::connect(&decisions,&QTimer::timeout,&app,[&]{for(auto *w:QApplication::allWidgets()){
            if(auto *dialog=qobject_cast<QInputDialog *>(w);dialog&&dialog->isVisible()&&dialog->windowTitle()=="Secure Sync — conflict"){
                if(!disabled){disabled=true;f.plugin->setEnabled(false);}dialog->setTextValue("Keep both versions");QTimer::singleShot(0,dialog,&QDialog::accept);
            }
            if(auto *dialog=qobject_cast<QMessageBox *>(w);dialog&&dialog->isVisible()&&dialog->windowTitle()=="Secure Sync — confirm resolution"){
                auto *yes=dialog->button(QMessageBox::Yes);QTimer::singleShot(0,yes,&QAbstractButton::click);
            }
        }});decisions.start();
        CHECK(f.call({"resolveConflict",QVariant(),stats}).toString().startsWith("Cancelled"));decisions.stop();CHECK(disabled);
        const auto after=cqs::native::readStorage(c,originalKeys->local,originalKeys->sync);
        CHECK(after.generation==before.generation&&after.local==before.local&&after.archives.empty()&&!after.resolution&&!after.publication);
        CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
    });
    test("actual module automatic worker pins unlocked keys, excludes another loop and stops without resetting state",[&]{
        Fixture f(root(),true);const QString stats="PLUGIN securesync: enabled",token(36,'a');
        CHECK(f.call({"startAutomaticSync",token,stats}).toString()=="Started");
        CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
        CHECK(f.call({"seedHistory",f.password,stats}).toString()=="Applied");
        CHECK(f.call({"startAutomaticSync",token,stats+"\nPLUGIN other: enabled"}).toString().startsWith("Refused"));
        ScriptContext context(f);context.call("show",{"synced_tray"});context.call("hide",{});
        CHECK(f.call({"startAutomaticSync",token,stats}).toString()=="Started");
        CHECK(f.call({"startAutomaticSync",token,stats}).toString().startsWith("Refused"));
        CHECK(f.call({"automaticCycle",token,stats,QStringList{"Clipboard"}}).toString()=="Waiting: configured tab was removed");
        context.call("unload",{"synced_tray"});
        CHECK(f.call({"status"}).toString()=="Locked");
        CHECK(f.call({"checkpointStorage"}).toString()=="Checkpointed");
        const auto original=bytes(f.record());
        CHECK(f.call({"automaticCycle",token,stats}).toString()=="Working");
        CHECK(f.call({"rotateLocalKey",f.password}).toString()=="Working");
        QElapsedTimer timeout;timeout.start();
        while(f.call({"automaticSyncStatus",token}).toString()=="Working"&&timeout.elapsed()<10000){
            QCoreApplication::processEvents();QThread::msleep(1);
        }
        CHECK(f.call({"automaticSyncStatus",token}).toString()=="UpToDate");
        CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
        CHECK(f.call({"status"}).toString()=="Locked");CHECK(bytes(f.record())==original);
    });
    test("actual module throttles failed transport cycles and resumes the same accepted history",[&]{
        Fixture f(root(),true);const QString stats="PLUGIN securesync: enabled",token(36,'c');
        CHECK(f.call({"seedHistory",f.password,stats}).toString()=="Applied");
        CHECK(f.call({"startAutomaticSync",token,stats}).toString()=="Started");
        const auto event=f.root+"/transport/events/test-pc/000000000001.cqs";
        CHECK(QFile::rename(event,f.root+"/held-event"));const auto original=bytes(f.record());
        CHECK(f.call({"automaticCycle",token,stats,QStringList{"synced_tray"}}).toString()=="Working");
        waitFor([&]{return f.call({"automaticSyncStatus",token}).toString()!="Working";});
        CHECK(f.call({"automaticSyncStatus",token}).toString().startsWith("Waiting"));
        for(int i=0;i<50;++i)CHECK(f.call({"automaticCycle",token,stats}).toString()!="Working");
        CHECK(bytes(f.record())==original);CHECK(QFile::rename(f.root+"/held-event",event));
        waitFor([&]{return f.call({"automaticCycleDelay",token}).toInt()==0;});
        CHECK(f.call({"automaticCycle",token,stats}).toString()=="Working");
        waitFor([&]{return f.call({"automaticSyncStatus",token}).toString()!="Working";});
        CHECK(f.call({"automaticSyncStatus",token}).toString()=="UpToDate"&&bytes(f.record())==original);
        CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
        CHECK(f.call({"unlockStorage",f.password}).toString()=="Unlocked");
        const auto c=cqs::native::storageConfiguration(f.profile());
        const auto k=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
        const Snapshot outbound{{{"text/plain",{'P','E','N','D','I','N','G'}}}};
        cqs::native::saveStorage(c,outbound,k->local,k->sync);const auto before=cqs::native::readStorage(c,k->local,k->sync);
        const auto history=cqs::storage::Directory(path(f.profile().transport)).scan(k->sync);
        const auto reserved=cqs::native::reservePublication(c,k,before,*cqs::native::preparePublication(c,k,before,history),nullptr);
        CHECK(QFile::rename(event,f.root+"/held-event"));const auto intent=bytes(f.record());
        CHECK(f.call({"startAutomaticSync",token,stats}).toString()=="Started");
        CHECK(f.call({"automaticCycle",token,stats}).toString()=="Working");
        waitFor([&]{return f.call({"automaticSyncStatus",token}).toString()!="Working";});
        CHECK(f.call({"automaticSyncStatus",token}).toString()=="Waiting: reserved publication retained; previously observed history not yet delivered");
        CHECK(bytes(f.record())==intent);CHECK(QFile::rename(f.root+"/held-event",event));
        waitFor([&]{return f.call({"automaticCycleDelay",token}).toInt()==0;});
        CHECK(f.call({"automaticCycle",token,stats}).toString()=="Working");
        waitFor([&]{return f.call({"automaticSyncStatus",token}).toString()!="Working";});
        const auto accepted=cqs::native::readStorage(c,k->local,k->sync);
        CHECK(!accepted.publication&&accepted.allocatedSequence==2&&accepted.local==outbound);
        CHECK(bytes(f.profile().transport+"/events/test-pc/000000000002.cqs").toStdString()==reserved.publication->wire);
        CHECK(cqs::storage::Directory(path(f.profile().transport)).scan(k->sync).events().size()==2);
        CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
    });
    test("reserved delivery durably witnesses an unaccepted remote branch before review",[&]{
        Fixture f(root(),true);const QString stats="PLUGIN securesync: enabled",token(36,'e');
        CHECK(f.call({"seedHistory",f.password,stats}).toString()=="Applied");
        const auto c=cqs::native::storageConfiguration(f.profile());
        const auto k=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
        auto peer=f.profile();peer.device="peer-pc";peer.stateDirectory=f.root+"/peer-state";directory(peer.stateDirectory);
        peer.transport=f.root+"/peer-transport";directory(peer.transport);directory(peer.transport+"/events");directory(peer.transport+"/events/test-pc");
        write(peer.transport+"/events/test-pc/000000000001.cqs",bytes(f.profile().transport+"/events/test-pc/000000000001.cqs"));
        const auto pc=cqs::native::storageConfiguration(peer);auto pk=std::make_shared<cqs::native::StorageKeys>();pk->sync=k->sync;pk->local=cqs::crypto::Bytes(32,0x45);
        cqs::native::initializeStorage(pc,pk->local,pk->sync);cqs::native::runStateAction(pc,pk,cqs::native::StateAction::Join);
        const Snapshot local{{{"text/plain",{'L'}}}},remote{{{"text/plain",{'R'}}}},changed{{{"text/plain",{'X'}}}};
        cqs::native::saveStorage(c,local,k->local,k->sync);auto before=cqs::native::readStorage(c,k->local,k->sync);
        const auto base=cqs::storage::Directory(path(f.profile().transport)).scan(k->sync);
        auto changedOwn=before;changedOwn.local=changed;const auto changedOwnPublication=*cqs::native::preparePublication(c,k,changedOwn,base);
        const auto reserved=cqs::native::reservePublication(c,k,before,*cqs::native::preparePublication(c,k,before,base),nullptr);
        cqs::native::saveStorage(pc,remote,pk->local,pk->sync);auto alternative=cqs::native::readStorage(pc,pk->local,pk->sync);alternative.local=changed;
        const auto replaced=*cqs::native::preparePublication(pc,pk,alternative,base);
        cqs::native::runStateAction(pc,pk,cqs::native::StateAction::Publish);
        const auto folder=f.profile().transport+"/events/peer-pc";directory(folder);
        const auto event=folder+"/000000000001.cqs";write(event,bytes(peer.transport+"/events/peer-pc/000000000001.cqs"));
        auto cycle=[&]{CHECK(f.call({"unlockStorage",f.password}).toString()=="Unlocked");
            CHECK(f.call({"startAutomaticSync",token,stats}).toString()=="Started");
            CHECK(f.call({"automaticCycle",token,stats}).toString()=="Working");
            waitFor([&]{return f.call({"automaticSyncStatus",token}).toString()!="Working";});};
        cycle();CHECK(f.call({"automaticSyncStatus",token}).toString().startsWith("Conflict"));
        auto observed=cqs::native::readStorage(c,k->local,k->sync);
        CHECK(observed.witnessed.count("peer-pc/000000000001")==1&&observed.local==local);
        CHECK(observed.publication->wire==reserved.publication->wire&&observed.head->event.revision.sequence==1);
        CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");const auto durable=bytes(f.record());
        CHECK(QFile::rename(event,f.root+"/held-peer"));cycle();
        CHECK(f.call({"automaticSyncStatus",token}).toString().startsWith("Waiting")&&bytes(f.record())==durable);
        CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
        write(event,QByteArray::fromStdString(replaced.wire));cycle();
        CHECK(f.call({"automaticSyncStatus",token}).toString().startsWith("Recovery: previously observed history was replaced"));
        CHECK(bytes(f.record())==durable);CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
        // Reconcile the exact reservation, then replace an authenticated tip
        // while the actual conflict chooser is open. Same tips are insufficient.
        write(event,bytes(peer.transport+"/events/peer-pc/000000000001.cqs"));
        observed=cqs::native::readStorage(c,k->local,k->sync);
        cqs::native::deliverPublication(c,k,observed,true);
        const auto ownEvent=f.profile().transport+"/events/test-pc/000000000002.cqs";
        write(ownEvent,QByteArray::fromStdString(changedOwnPublication.wire));cycle();
        CHECK(f.call({"automaticSyncStatus",token}).toString().startsWith("Recovery: previously observed history was replaced"));
        CHECK(bytes(f.record())==durable);CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
        write(ownEvent,QByteArray::fromStdString(reserved.publication->wire));
        cqs::native::acceptPublication(c,k,observed,nullptr);
        // A manual scan must also prepare the guarded comparison UI, even
        // without an automatic scheduling client.
        CHECK(f.call({"syncNow",f.password,stats}).toString().contains("multiple authenticated tips"));
        CHECK(f.call({"userStatus"}).toString().startsWith("Conflict"));
        CHECK(f.call({"unlockStorage",f.password}).toString()=="Unlocked");
        const auto decisionState=bytes(f.record());QTimer decision;decision.setInterval(10);bool changedDuringDecision=false;
        QObject::connect(&decision,&QTimer::timeout,&app,[&]{for(auto *w:QApplication::allWidgets()){
            if(auto *dialog=qobject_cast<QInputDialog *>(w);dialog&&dialog->isVisible()&&dialog->windowTitle()=="Secure Sync — conflict"){
                if(!changedDuringDecision){write(event,QByteArray::fromStdString(replaced.wire));changedDuringDecision=true;}
                dialog->setTextValue("Keep local version");QTimer::singleShot(0,dialog,&QDialog::accept);
            }
            if(auto *dialog=qobject_cast<QMessageBox *>(w);dialog&&dialog->isVisible()&&dialog->windowTitle()=="Secure Sync — confirm resolution"){
                auto *yes=dialog->button(QMessageBox::Yes);QTimer::singleShot(0,yes,&QAbstractButton::click);
            }
        }});decision.start();
        CHECK(f.call({"resolveConflict",QVariant(),stats}).toString()=="Working");decision.stop();CHECK(changedDuringDecision);
        waitFor([&]{return f.call({"automaticSyncStatus"}).toString()!="Working";});
        CHECK(f.call({"automaticSyncStatus"}).toString()=="Conflict: history changed during the decision");
        CHECK(bytes(f.record())==decisionState);
    });
    test("a clean device observes conflict then imports another device's authenticated merge without another Start",[&]{
        Fixture f(root(),true);const QString stats="PLUGIN securesync: enabled",token(36,'d');
        CHECK(f.call({"seedHistory",f.password,stats}).toString()=="Applied");
        const auto c=cqs::native::storageConfiguration(f.profile());
        const auto k=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
        auto peer=f.profile();peer.device="peer-pc";peer.stateDirectory=f.root+"/peer-state";directory(peer.stateDirectory);
        peer.transport=f.root+"/peer-transport";directory(peer.transport);directory(peer.transport+"/events");directory(peer.transport+"/events/test-pc");
        write(peer.transport+"/events/test-pc/000000000001.cqs",bytes(f.profile().transport+"/events/test-pc/000000000001.cqs"));
        const auto pc=cqs::native::storageConfiguration(peer);auto pk=std::make_shared<cqs::native::StorageKeys>();
        pk->sync=k->sync;pk->local=cqs::crypto::Bytes(32,0x45);
        cqs::native::initializeStorage(pc,pk->local,pk->sync);cqs::native::runStateAction(pc,pk,cqs::native::StateAction::Join);
        const Snapshot local{{{"text/plain",{'L'}}}},remote{{{"text/plain",{'R'}}}};
        cqs::native::saveStorage(c,local,k->local,k->sync);cqs::native::runStateAction(c,k,cqs::native::StateAction::Publish);
        cqs::native::saveStorage(pc,remote,pk->local,pk->sync);cqs::native::runStateAction(pc,pk,cqs::native::StateAction::Publish);
        // Two offline roots converge by delivering their immutable ciphertexts.
        directory(f.profile().transport+"/events/peer-pc");
        write(f.profile().transport+"/events/peer-pc/000000000001.cqs",bytes(peer.transport+"/events/peer-pc/000000000001.cqs"));
        write(peer.transport+"/events/test-pc/000000000002.cqs",bytes(f.profile().transport+"/events/test-pc/000000000002.cqs"));
        CHECK(f.call({"startAutomaticSync",token,stats}).toString()=="Started");
        CHECK(f.call({"automaticCycle",token,stats}).toString()=="Working");
        waitFor([&]{return f.call({"automaticSyncStatus",token}).toString()!="Working";});
        CHECK(f.call({"automaticSyncStatus",token}).toString()=="Conflict: compare versions before continuing");
        CHECK(cqs::native::readStorage(c,k->local,k->sync).local==local);
        const auto h=cqs::storage::Directory(path(peer.transport)).scan(pk->sync);
        const auto before=cqs::native::readStorage(pc,pk->local,pk->sync);
        const auto p=cqs::native::prepareResolution(pc,pk,before,h,remote);
        const auto reserved=cqs::native::reserveResolution(pc,pk,before,h,p,true,nullptr);
        cqs::native::deliverPublication(pc,pk,reserved);cqs::native::acceptPublication(pc,pk,reserved,nullptr);
        write(f.profile().transport+"/events/peer-pc/000000000002.cqs",bytes(peer.transport+"/events/peer-pc/000000000002.cqs"));
        waitFor([&]{return f.call({"automaticCycleDelay",token}).toInt()==0;});
        CHECK(f.call({"automaticCycle",token,stats}).toString()=="Working");
        waitFor([&]{return f.call({"automaticSyncStatus",token}).toString()!="Working";});
        CHECK(f.call({"automaticSyncStatus",token}).toString()=="Applied");
        const auto accepted=cqs::native::readStorage(c,k->local,k->sync);
        CHECK(accepted.local==remote&&accepted.head->event.revision.id==p.target.event.revision.id);
        CHECK(cqs::storage::Directory(path(peer.transport)).scan(pk->sync).events().size()==4);
        CHECK(f.call({"stopAutomaticSync"}).toString()=="Stopped");
    });
    test("authorization dialog reserves admission and Stop invalidates its result",[&]{
        Fixture f(root(),true);const auto original=bytes(f.record());bool visited=false;
        QTimer responder;responder.setInterval(1);QObject::connect(&responder,&QTimer::timeout,&app,[&]{
            for(auto *widget:QApplication::allWidgets())if(auto *dialog=qobject_cast<QInputDialog *>(widget);dialog&&dialog->isVisible()&&dialog->windowTitle()=="Secure Sync password"){
                CHECK(f.plugin->scriptCallback({"seedHistory",f.password,QStringLiteral("PLUGIN securesync: enabled")}).toString()=="Working");
                CHECK(f.plugin->scriptCallback({"stopAutomaticSync"}).toString().startsWith("Stopping"));
                dialog->setTextValue(QString::fromUtf8(f.password));visited=true;dialog->accept();
            }
        });responder.start();
        CHECK(f.plugin->scriptCallback({"seedHistory",QVariant(),QStringLiteral("PLUGIN securesync: enabled")}).toString().startsWith("Refused"));
        responder.stop();CHECK(visited);CHECK(bytes(f.record())==original);
    });
    test("manual operation returns immediately, blocks reload and cancels without resetting state",[&]{
        Fixture f(root(),true);const auto original=bytes(f.record());
        const auto started=f.plugin->scriptCallback({"seedHistory",f.password,QStringLiteral("PLUGIN securesync: enabled")}).toString();
        CHECK(started.startsWith("Working:"));const auto token=started.mid(8);
        CHECK(!f.initialize());
        CHECK(f.plugin->scriptCallback({"stopAutomaticSync"}).toString().startsWith("Stopping"));
        QElapsedTimer timeout;timeout.start();QString result;
        do{QCoreApplication::processEvents();QThread::msleep(1);result=f.plugin->scriptCallback({"operationStatus",token}).toString();CHECK(timeout.elapsed()<10000);}while(result=="Working");
        CHECK(result.startsWith("Cancelled"));CHECK(bytes(f.record())==original);
        CHECK(f.plugin->scriptCallback({"operationStatus",QStringLiteral("stale")}).toString().startsWith("Refused"));
        CHECK(f.call({"unlockStorage",f.password}).toString()=="Unlocked");CHECK(f.initialize());
    });
    test("settings invalidation cancels a worker before applying its old profile result",[&]{
        Fixture f(root(),true);const auto original=bytes(f.record());
        const auto started=f.plugin->scriptCallback({"seedHistory",f.password,QStringLiteral("PLUGIN securesync: enabled")}).toString();CHECK(started.startsWith("Working:"));
        f.configure();QElapsedTimer timeout;timeout.start();QString status;
        do{QCoreApplication::processEvents();QThread::msleep(1);status=f.plugin->scriptCallback({"operationStatus",started.mid(8)}).toString();CHECK(timeout.elapsed()<10000);}while(status=="Working");
        CHECK(status.startsWith("Cancelled"));CHECK(bytes(f.record())==original);
    });
    test("aboutToQuit joins cancelled worker without GUI pumping or losing encrypted state",[&]{
        Fixture f(root(),true);const auto original=bytes(f.record());
        CHECK(f.plugin->scriptCallback({"seedHistory",f.password,QStringLiteral("PLUGIN securesync: enabled")}).toString().startsWith("Working:"));
        QElapsedTimer timeout;timeout.start();CHECK(QMetaObject::invokeMethod(&app,"aboutToQuit",Qt::DirectConnection));
        CHECK(timeout.elapsed()<5000);CHECK(bytes(f.record())==original);
        CHECK(f.plugin->scriptCallback({"status"}).toString()=="Refused");
    });
    test("actual module adopts packed data and Seeds through guarded public callbacks",[&]{
        Fixture f(root(),true);const QString stats="PLUGIN securesync: enabled";
        const auto item=text(QByteArray("old\0binary",10));QVariantList packed{serializeData(item),serializeData(QVariantMap{})};
        CHECK(f.call({"adoptSnapshot",f.password,stats,QVariant(packed)}).toString()=="AdoptedPreservedTab");
        CHECK(f.call({"adoptSnapshot",f.password,stats,QVariant(packed)}).toString()=="UpToDate");
        CHECK(f.call({"seedHistory",f.password,stats}).toString()=="Applied");
        CHECK(f.call({"retrySeed",f.password,stats}).toString()=="UpToDate");
        CHECK(f.call({"syncState"}).toString()=="Joined");
        CHECK(f.initialize());CHECK(f.model.rowCount()==2&&f.model.data(f.model.index(0,0),contentType::data).toMap()==item);
        const auto record=bytes(f.record());CHECK(f.call({"seedHistory",f.password,stats}).toString().startsWith("Refused: checkpoint"));
        CHECK(bytes(f.record())==record);
    });
    test("actual scriptable Seed loads checkpoints unloads and reloads using public API",[&]{
        Fixture f(root(),true);ScriptContext context(f);std::unique_ptr<ItemScriptable> script(f.plugin->scriptableObject());script->setScriptable(&context);QString result;
        context.scriptArguments={QStringLiteral("seedHistory")};
        CHECK(QMetaObject::invokeMethod(script.get(),"userAction",Qt::DirectConnection,Q_RETURN_ARG(QString,result)));
        CHECK(result=="Applied"&&context.model&&context.stateCalls==1);
        CHECK(f.call({"syncState"}).toString()=="Joined");
    });
    test("ordinary-tab preservation requires native encryption and current exclusive plugin inventory",[&]{
        Fixture f(root(),true);auto p=f.profile();p.standaloneStorage=false;f.configure(p);
        CHECK(f.call({"nativeMigrationStatus",QVariant(),"PLUGIN securesync: enabled"}).toString()=="Refused");
        QSettings settings(f.root+"/settings.ini",QSettings::IniFormat);settings.setValue("Options/encrypt_tabs",true);settings.sync();
        CHECK(f.call({"nativeMigrationStatus",QVariant(),"PLUGIN securesync: enabled\nPLUGIN other: enabled"}).toString().startsWith("Refused"));
        CHECK(f.call({"nativeMigrationStatus",QVariant(),"PLUGIN securesync: enabled"}).toString()=="NativeStorage");
    });
    test("separate module loads through unchanged CopyQ 17 ABI and claims only explicitly configured synced_tray", [&] {
        Fixture f(root(), true); CHECK(f.plugin->id() == "securesync");
        CHECK(f.plugin->canSaveItems("synced_tray")); CHECK(!f.plugin->canSaveItems("other-tab"));
        CHECK(f.plugin->supportsEncryption()); CHECK(f.initialize());
        CHECK(f.model.property("_copyq_verified_tab_bridge_v1").isNull());
        f.plugin->setEnabled(false); CHECK(f.plugin->isEnabled()); // Unsafe direct disable is deferred.
        QBuffer b; b.open(QIODevice::WriteOnly); CHECK(f.saver->saveItems("synced_tray", f.model, &b));
    });
    test("binary ordered MIME and empty items survive module unload and encrypted disk reload", [&] {
        const auto r = root(); QByteArray marker; Snapshot wanted;
        { Fixture f(r, true); CHECK(f.initialize());
          put(f.model, text(QByteArray("a\0\xff\r\n", 5))); put(f.model, {});
          put(f.model, {{"image/png", QByteArray("\x89\0\xff", 3)}, {"text/html", QByteArray("<b>lab</b>")}});
          wanted = snapshot(f.model); marker = f.save(); CHECK(marker.size() == 80);
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
    test("raw K-SYNC import changes do not retarget the independent local key", [&] {
        const auto r = root(); QByteArray marker, record;
        { Fixture f(r, true); CHECK(f.initialize()); put(f.model, text("keep")); marker = f.save(); record = bytes(f.record()); }
        write(r + "/key", QByteArray(32, 'x'));
        Fixture f(r, false); CHECK(f.load(marker)); CHECK(f.model.rowCount() == 1); CHECK(bytes(f.record()) == record);
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
        CHECK(f.call({"resumeStorageSetup",f.password}).toString().startsWith("Refused"));
        CHECK(!QFile::exists(f.record()));
    });
    test("newer cache detects a rolled-back authoritative checkpoint", [&] {
        const auto r = root(); QByteArray marker;
        { Fixture f(r, true); CHECK(f.initialize()); marker = f.save(); }
        QDataStream stream(&marker, QIODevice::ReadWrite); stream.setVersion(QDataStream::Qt_4_7); stream.device()->seek(72); stream << quint64(99);
        CHECK(marker.left(8) == "CQSLOC01");
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
        CHECK(!f.saver->saveItems("synced_tray", other, &buffer)); CHECK(bytes(f.record()) == original);
        put(f.model, {{"text/plain", QStringLiteral("unsupported")}});
        CHECK(!f.saver->saveItems("synced_tray", f.model, &buffer)); CHECK(bytes(f.record()) == original);
    });
    test("removing the optional raw import file does not remove vault-protected local keys", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); put(f.model, text("old")); f.save(); const auto original = bytes(f.record());
        CHECK(QFile::remove(f.root + "/key")); put(f.model, text("new")); QBuffer buffer; buffer.open(QIODevice::WriteOnly);
        CHECK(f.saver->saveItems("synced_tray", f.model, &buffer)); CHECK(bytes(f.record()) != original);
    });
    test("explicit initialization is create-only and repeated calls preserve the record", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); put(f.model, text("keep initialization")); f.save();
        const auto original = bytes(f.record());
        CHECK(f.call({"initializeStorage",f.password}).toString() != "Initialized");
        CHECK(bytes(f.record()) == original);
    });
    test("lost vault refuses initialization over existing data and can be repaired from live keys", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); put(f.model,text("keep after lost vault"));f.save();
        const auto original=bytes(f.record()); CHECK(QFile::remove(f.root+"/vault/record-v1.cqr"));
        CHECK(f.call({"initializeStorage",f.password}).toString().startsWith("Refused"));
        CHECK(!QFile::exists(f.root+"/vault/record-v1.cqr"));CHECK(bytes(f.record())==original);
        CHECK(f.call({"repairMissingVault",f.password}).toString()=="VaultRepaired");
        CHECK(bytes(f.record())==original);
    });
    test("last owned model destruction clears keys and a wrong password cannot unlock", [&] {
        Fixture f(root(),true);auto *model=new ClipboardModel;
        auto saver=f.plugin->initializeTab("synced_tray",model,10000);CHECK(saver);
        CHECK(f.call({"status"}).toString()=="Unlocked");
        CHECK(f.call({"lockStorage"}).toString().startsWith("Refused"));
        saver.reset();delete model;
        CHECK(f.call({"status"}).toString()=="Locked");
        CHECK(f.call({"unlockStorage",QByteArray("wrong-public-password")}).toString().startsWith("Refused"));
        CHECK(f.call({"status"}).toString()=="Locked");
        CHECK(f.call({"unlockStorage",f.password}).toString()=="Unlocked");
    });
    test("state operations refuse a loaded model or another enabled plugin without changing data", [&] {
        Fixture f(root(),true);CHECK(f.initialize());const auto before=bytes(f.record());
        for(const auto &action:{"joinHistory","fastForward","migrateUnifiedState","restorePendingOriginal"})
            CHECK(f.call({action,f.password,QStringLiteral("PLUGIN securesync: enabled")}).toString().startsWith("Refused"));
        CHECK(bytes(f.record())==before);
    });
    test("explicit module migration preserves local contents and does not accept the laboratory revision", [&] {
        Fixture f(root(),true);const auto c=cqs::native::storageConfiguration(f.profile());
        const auto k=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
        const Snapshot original{{{"text/plain",{'L','E','G','A','C','Y'}}}};CHECK(QFile::remove(f.record()));
        {cqs::state::FileStore old(path(f.root+"/state"),c.binding.toStdString(),k->local);const auto lease=old.lock();
         old.initialize(cqs::native::checkpointRecord(c.binding.toStdString(),"cqs-storage",original,41));}
        CHECK(f.call({"migrateUnifiedState",f.password,QStringLiteral("PLUGIN securesync: enabled\nPLUGIN other: enabled")}).toString().startsWith("Refused"));
        CHECK(f.call({"migrateUnifiedState",f.password,QStringLiteral("PLUGIN securesync: enabled")}).toString()=="MigratedUnifiedState");
        const auto r=cqs::native::readStorage(c,k->local,k->sync);CHECK(r.local==original&&!r.head&&!r.pending&&r.generation==42);
        CHECK(f.initialize());CHECK(snapshot(f.model)==original);CHECK(f.call({"syncState"}).toString()=="Unjoined");
    });
    test("a loaded profile excludes another CopyQ process and refuses stale model saves", [&] {
        Fixture f(root(),true);CHECK(f.initialize());const auto before=bytes(f.record());
        QProcess child;child.start(QCoreApplication::applicationFilePath(),{module,"--try-open",f.root});CHECK(child.waitForFinished(30000));CHECK(child.exitCode()==0);
        const auto c=cqs::native::storageConfiguration(f.profile());const auto k=cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()));
        bool refused=false;try{cqs::native::saveStorage(c,{{{"text/plain",{'O','T','H','E','R'}}}},k->local,k->sync);}catch(const std::exception &){refused=true;}CHECK(refused);CHECK(bytes(f.record())==before);
        // Model a noncooperating low-level writer: generation CAS still refuses
        // to silently replace its newer durable contents with our stale model.
        {cqs::state::FileStore store(path(f.root+"/state"),c.binding.toStdString(),k->local);auto lease=store.lock();const auto r=store.load();auto next=r;++next.generation;
         next.local=Snapshot{{{"text/plain",{'N','E','W'}}}};store.commit(r,next);}
        const auto newer=bytes(f.record());QBuffer output;output.open(QIODevice::WriteOnly);CHECK(!f.saver->saveItems("synced_tray",f.model,&output));
        CHECK(bytes(f.record())==newer&&output.size()==0);
    });
    test("actual scriptable import command loads a cold tab and reloads after safe refusal", [&] {
        Fixture f(root(),true);const auto wire=bytes(f.record());ScriptContext context(f);
        std::unique_ptr<ItemScriptable> script(f.plugin->scriptableObject());script->setScriptable(&context);QString result;
        CHECK(QMetaObject::invokeMethod(script.get(),"joinHistory",Qt::DirectConnection,Q_RETURN_ARG(QString,result)));
        CHECK(result.startsWith("Refused: no authenticated history")&&context.model&&context.stateCalls==1&&bytes(f.record())==wire);
    });
    test("actual scriptable command retains an open editor and never dispatches import", [&] {
        Fixture f(root(),true);const auto wire=bytes(f.record());ScriptContext context(f);context.editor=true;
        std::unique_ptr<ItemScriptable> script(f.plugin->scriptableObject());script->setScriptable(&context);QString result;
        context.scriptArguments={QStringLiteral("joinHistory")};
        CHECK(QMetaObject::invokeMethod(script.get(),"userAction",Qt::DirectConnection,Q_RETURN_ARG(QString,result)));
        CHECK(result.startsWith("Refused: close editors")&&context.model&&context.stateCalls==0&&bytes(f.record())==wire);
    });
    test("active profile changes are deferred and a fresh wrong profile cannot authenticate the cache", [&] {
        const auto r=root(); QByteArray marker;
        { Fixture f(r,true);CHECK(f.initialize());put(f.model,text("profile-bound"));marker=f.save();
          const auto original=bytes(f.record());auto p=f.profile();p.device="other-pc";f.configure(p);
          QBuffer output;output.open(QIODevice::WriteOnly);CHECK(f.saver->saveItems("synced_tray",f.model,&output));
          CHECK(bytes(f.record())==original); }
        Fixture f(r,false);auto p=f.profile();p.device="other-pc";f.configure(p);
        CHECK(!f.load(marker)); CHECK(f.model.rowCount()==0);
    });
    test("opt-out profile still recognizes owned cache and refuses to load or save plaintext", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); const auto marker = f.save();
        f.saver.reset(); CHECK(f.loader.unload());
        auto p = f.profile(); p.standaloneStorage = false;
        auto *object=f.loader.instance();CHECK(object);f.plugin=qobject_cast<ItemLoaderInterface *>(object);CHECK(f.plugin);f.configure(p);
        CHECK(!f.plugin->canSaveItems("synced_tray")); CHECK(f.plugin->supportsEncryption());
        QBuffer cache; cache.setData(marker); cache.open(QIODevice::ReadOnly);
        CHECK(f.plugin->canLoadItems(&cache)); ClipboardModel empty;
        CHECK(!f.plugin->loadItems("synced_tray", &empty, &cache, 10000));
        QBuffer output; output.open(QIODevice::WriteOnly); CHECK(output.size()==0);
    });
    test("ordinary tabs and borrowed nonempty models cannot be claimed or modified", [&] {
        Fixture f(root(), true); put(f.model, text("existing user data")); const auto original = snapshot(f.model);
        CHECK(!f.plugin->initializeTab("synced_tray", &f.model, 10000)); CHECK(snapshot(f.model) == original);
        CHECK(!f.plugin->setData(text("remote data"), f.model.index(0, 0), &f.model));
        CHECK(snapshot(f.model) == original); CHECK(!f.plugin->canSaveItems("cqs-standalone-lab"));
    });
    test("three MiB binary data exceed old laboratory bounds and survive restart", [&] {
        const auto r = root(); QByteArray marker;
        { Fixture f(r, true); CHECK(f.initialize());
          put(f.model, {{"application/octet-stream", QByteArray(3 * 1024 * 1024, char(0xff))}}); marker = f.save(); }
        Fixture f(r, false); CHECK(f.load(marker)); CHECK(snapshot(f.model)[0].at("application/octet-stream").size() == 3 * 1024 * 1024);
    });
    test("item and MIME byte ceilings refuse rather than crop or overwrite durable data", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); const auto original = bytes(f.record());
        CHECK(f.model.insertRows(0, 10001)); QBuffer output; output.open(QIODevice::WriteOnly);
        CHECK(!f.saver->saveItems("synced_tray", f.model, &output)); CHECK(bytes(f.record()) == original);
        CHECK(f.model.removeRows(0, f.model.rowCount()));
        put(f.model, {{"application/octet-stream", QByteArray(32 * 1024 * 1024, 'x')}});
        CHECK(!f.saver->saveItems("synced_tray", f.model, &output)); CHECK(output.size() == 0);
        CHECK(bytes(f.record()) == original);
    });
    test("actual stock CopyQ DataFile is refused without reading or dropping its MIME value", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); const auto original = bytes(f.record());
        fixtureBlobDirectory = f.root + "/blobs"; directory(fixtureBlobDirectory);
        registerDataFileConverter();
        QByteArray raw; QDataStream stream(&raw, QIODevice::WriteOnly); stream.setVersion(QDataStream::Qt_4_7);
        serializeData(&stream, {{"application/octet-stream", QByteArray("legacy blob bytes")}}, 1);
        CHECK(stream.status() == QDataStream::Ok);
        QVariantMap data; CHECK(deserializeData(&data, raw));
        CHECK(data.value("application/octet-stream").metaType().id() != QMetaType::QByteArray);
        put(f.model, data); QBuffer output; output.open(QIODevice::WriteOnly);
        CHECK(!f.saver->saveItems("synced_tray", f.model, &output));
        CHECK(output.size() == 0); CHECK(bytes(f.record()) == original);
        // Delete the blob to ensure refusal does not rely on successful conversion.
        QDirIterator files(fixtureBlobDirectory, QDir::Files, QDirIterator::Subdirectories);
        int removed = 0; while (files.hasNext()) { CHECK(QFile::remove(files.next())); ++removed; }
        CHECK(removed > 0); CHECK(!f.saver->saveItems("synced_tray", f.model, &output));
        int copied=0;
        class ConvertingCopy final:public ItemSaverInterface {
        public:
            explicit ConvertingCopy(int &calls):calls_(calls){}
            QVariantMap copyItem(const QAbstractItemModel &,const QVariantMap &data) override {
                ++calls_;QVariantMap result;for(auto it=data.cbegin();it!=data.cend();++it)result.insert(it.key(),it.value().toByteArray());return result;
            }
        private:int &calls_;
        };
        auto converting=f.plugin->transformSaver(std::make_shared<ConvertingCopy>(copied),&f.model);
        auto ordinary=f.plugin->transformSaver(std::make_shared<ItemSaverInterface>(),&f.model);const QString token(36,'d');
        CHECK(f.call({"beginNativeCapture",token,1}).toString()=="Started");
        CHECK(converting->copyItem(f.model,data).isEmpty());CHECK(copied==0);
        CHECK(f.call({"finishNativeCapture",token}).toString().startsWith("Refused"));
        CHECK(ordinary->copyItem(f.model,data)==data); // Ordinary host semantics survive capture cleanup.
        CHECK(bytes(f.record()) == original); CHECK(f.model.data(f.model.index(0, 0), contentType::data).toMap() == data);
        fixtureBlobDirectory.clear();
    });
    test("custom MIME converters are never executed by the main saver", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); const auto original = bytes(f.record());
        convertedStorageValues = 0;
        QMetaType::registerConverter<ConvertibleStorageValue, QByteArray>([](const ConvertibleStorageValue &) {
            ++convertedStorageValues; return QByteArray("must not read arbitrary files");
        });
        put(f.model, {{"text/plain", QVariant::fromValue(ConvertibleStorageValue{})}});
        QBuffer output; output.open(QIODevice::WriteOnly);
        CHECK(!f.saver->saveItems("synced_tray", f.model, &output)); CHECK(convertedStorageValues == 0);
        CHECK(bytes(f.record()) == original);
    });
    test("busy private state lease refuses save without blocking or changing data", [&] {
        Fixture f(root(), true); CHECK(f.initialize()); put(f.model, text("local edit"));
        const auto original = bytes(f.record()); const auto c = cqs::native::storageConfiguration(f.profile());
        cqs::state::FileStore store(path(f.root + "/state"), c.binding.toStdString(), cqs::native::unlockVault(c,cqs::crypto::Bytes(f.password.begin(),f.password.end()))->local);
        const auto lease = store.lock(); CHECK(lease);
        QBuffer output; output.open(QIODevice::WriteOnly);
        CHECK(!f.saver->saveItems("synced_tray", f.model, &output)); CHECK(output.size() == 0);
        CHECK(bytes(f.record()) == original);
    });
    test("invalid and unknown opt-in profiles refuse initialization without default-storage fallback", [&] {
        Fixture f(root(), true); const auto original = bytes(f.record());
        QSettings settings(f.root + "/invalid.ini", QSettings::IniFormat);
        auto p = f.profile(); p.device = "INVALID"; cqs::native::saveProfile(settings, p);
        f.plugin->loadSettings(settings); CHECK(f.plugin->canSaveItems("synced_tray"));
        CHECK(!f.plugin->initializeTab("synced_tray", &f.model, 10000)); CHECK(bytes(f.record()) == original);
        settings.setValue("profile_schema", 99); f.plugin->loadSettings(settings);
        CHECK(f.plugin->canSaveItems("synced_tray"));
        CHECK(!f.plugin->initializeTab("synced_tray", &f.model, 10000)); CHECK(bytes(f.record()) == original);
    });
    std::cout << "PASS " << passed << " standalone module storage scenarios\n";
}
#include "standalone_storage_test.moc"
