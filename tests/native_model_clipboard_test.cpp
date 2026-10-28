// SPDX-License-Identifier: GPL-3.0-or-later
#include "model_clipboard.h"
#include "packed_items.h"
#include "native_blob.h"
#include "gui_clipboard.h"
#include <QElapsedTimer>
#include <QTimer>
#include <atomic>
#include <chrono>
#include <QTemporaryDir>
#include <QDir>
#include <QFile>
#include <QPersistentModelIndex>
#include "test_check.h"
#include "item/clipboardmodel.h"
#include "item/serialize.h"
#include "common/contenttype.h"
#include <QCoreApplication>
#include <QDataStream>
#include <QIODevice>
#include <QVariantMap>
#include <functional>
#include <cstdlib>
#include <iostream>
#include <thread>
#ifdef Q_OS_WIN
#include "windows_test_acl.h"
#endif

// Test-only link seam for upstream serialize.cpp. Normal pack() with in-memory
// QByteArrays must not request any user data path or write a DataFile.
QString blobRoot;
QString itemDataPath() { if(blobRoot.isEmpty())throw std::runtime_error("Unexpected CopyQ filesystem access in test");return blobRoot; }
struct Convertible { int marker = 1; };
Q_DECLARE_METATYPE(Convertible)
using cqs::native::ModelClipboard;
using cqs::native::ModelAccess;
using cqs::native::ModelError;
using cqs::native::ModelErrorCode;
using cqs::transaction::Snapshot;
using cqs::transaction::View;
namespace {
int passed = 0, conversions = 0;
QVariantMap text(const QByteArray &bytes) { return {{QStringLiteral("text/plain"), bytes}}; }
void put(ClipboardModel &model, const QVariantMap &map) { CHECK(model.insertRows(model.rowCount(), 1)); CHECK(model.setData(model.index(model.rowCount()-1,0),map,contentType::data)); }
Snapshot wanted(unsigned char c) { return {{{"text/plain", {c}}}}; }
ModelAccess allowed() {
    // A synthetic test port, explicitly not a CopyQ disk persistence adapter.
    return {[] { return true; }, [] { return true; }, [](const View &view, cqs::transaction::Limits) { return view.snapshot; }};
}
void rejects(ModelErrorCode code, const std::function<void()> &body) {
    bool caught = false; try { body(); } catch (const ModelError &e) { CHECK(e.code() == code); caught = true; } CHECK(caught);
}
void invalid(const std::function<void()> &body) { bool caught = false; try { body(); } catch(const cqs::packed::Error&) { caught=true; } CHECK(caught); }
void test(const char *name, const std::function<void()> &body) { std::cout << "RUN " << name << std::endl; try{body();}catch(const std::exception &e){std::cerr<<"FAIL "<<name<<": "<<e.what()<<std::endl;std::exit(1);} ++passed; std::cout << "PASS " << name << std::endl; }
class FaultModel final : public QAbstractListModel {
public:
    QList<QVariantMap> rows;
    bool failRemove=false, failSet=false;
    int rowCount(const QModelIndex & = {}) const override { return static_cast<int>(rows.size()); }
    QVariant data(const QModelIndex &i,int role) const override { return i.isValid() && role==contentType::data ? QVariant(rows[i.row()]) : QVariant(); }
    bool insertRows(int at,int count,const QModelIndex & = {}) override { beginInsertRows({},at,at+count-1); for(int i=0;i<count;++i)rows.insert(at,{}); endInsertRows(); return true; }
    bool removeRows(int at,int count,const QModelIndex & = {}) override { if(failRemove)return false; beginRemoveRows({},at,at+count-1); rows.remove(at,count); endRemoveRows(); return true; }
    bool setData(const QModelIndex &i,const QVariant &v,int role) override { if(failSet||role!=contentType::data)return false; rows[i.row()]=v.toMap(); emit dataChanged(i,i); return true; }
};
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    test("decode matches the actual pinned CopyQ pack serializer", [] {
        ClipboardModel model; ModelClipboard adapter(&model,allowed());
        const QVariantMap original{{"text/plain",QByteArray("\0\xff\r\n",4)}, {"text/html",QByteArray("<b>\xc5\xbc</b>")},
            {"application/x-copyq-private-example",QByteArray("\0",1)}};
        const auto raw=serializeData(original);
        const auto decoded=adapter.decode({raw.toBase64().toStdString()},{});
        put(model,original); CHECK(adapter.capture({}).snapshot==decoded);
        const auto empty=serializeData(QVariantMap{}); CHECK(adapter.decode({empty.toBase64().toStdString()},{}).size()==1);
    });
    test("real Qt QDataStream accepts all equivalent text prefixes", [] {
        ClipboardModel model; ModelClipboard adapter(&model,allowed()); Snapshot first;
        for(const auto *name:{"4","8plain","0text/plain"}) {
            QByteArray raw; QDataStream s(&raw,QIODevice::WriteOnly); s.setVersion(QDataStream::Qt_4_7);
            s << qint32(-2) << qint32(1) << QString::fromLatin1(name) << false << QByteArray("a\0b",3);
            auto actual=adapter.decode({raw.toBase64().toStdString()},{});
            if(first.empty())first=actual; CHECK(actual==first);
        }
    });
    test("capture and replacement preserve ordered empty and binary items", [] {
        ClipboardModel model; put(model,text("old")); ModelClipboard adapter(&model,allowed());
        const Snapshot desired{{},{{"application/octet-stream",{0,1,127,255,13,10}}},{{"text/plain",{}}}};
        const auto view=adapter.replace(adapter.capture({}),desired); CHECK(view.snapshot==desired);
        CHECK(adapter.capture({}).snapshot==desired); CHECK(model.rowCount()==3);
    });
    test("empty target and no-op replacement", [] {
        ClipboardModel model; put(model,text("old")); ModelClipboard adapter(&model,allowed());
        const auto empty=adapter.replace(adapter.capture({}),{}); CHECK(empty.snapshot.empty());
        CHECK(adapter.replace(empty,{}).epoch==empty.epoch);
    });
    test("missing access guard denies capture", [] {
        ClipboardModel model; ModelClipboard adapter(&model,{}); rejects(ModelErrorCode::AccessDenied,[&]{adapter.capture({});});
    });
    test("locked tab or editor denies writes before removal", [] {
        ClipboardModel model; put(model,text("a")); auto access=allowed(); access.writable=[] { return false; };
        ModelClipboard adapter(&model,access); const auto old=adapter.capture({});
        rejects(ModelErrorCode::AccessDenied,[&]{adapter.replace(old,wanted('b'));}); CHECK(adapter.capture({}).snapshot==old.snapshot);
    });
    test("missing durability port blocks the first destructive write", [] {
        ClipboardModel model; put(model,text("a")); auto access=allowed(); access.persistAndReadback={};
        ModelClipboard adapter(&model,access); const auto old=adapter.capture({}); int removed=0;
        QObject::connect(&model,&QAbstractItemModel::rowsAboutToBeRemoved,[&]{++removed;});
        rejects(ModelErrorCode::PersistenceUnavailable,[&]{adapter.replace(old,wanted('b'));});
        rejects(ModelErrorCode::PersistenceUnavailable,[&]{adapter.persist(old,{});});
        CHECK(removed==0 && adapter.capture({}).snapshot==old.snapshot);
    });
    test("ABA edit cannot reuse a captured view", [] {
        ClipboardModel model; put(model,text("a")); ModelClipboard adapter(&model,allowed()); const auto old=adapter.capture({});
        CHECK(model.setData(model.index(0,0),text("b"),contentType::data)); CHECK(model.setData(model.index(0,0),text("a"),contentType::data));
        CHECK(adapter.capture({}).snapshot==old.snapshot && adapter.capture({}).epoch!=old.epoch);
        rejects(ModelErrorCode::Changed,[&]{adapter.replace(old,wanted('c'));});
    });
    test("adapter reconstruction never reuses an epoch", [] {
        ClipboardModel model; put(model,text("a")); View old;
        { ModelClipboard adapter(&model,allowed()); old=adapter.capture({}); }
        ModelClipboard replacement(&model,allowed()); rejects(ModelErrorCode::Changed,[&]{replacement.replace(old,wanted('b'));});
    });
    test("row reorder invalidates a captured view", [] {
        ClipboardModel model; put(model,text("a")); put(model,text("b")); ModelClipboard adapter(&model,allowed()); const auto old=adapter.capture({});
        CHECK(model.moveRows({},0,1,{},2)); rejects(ModelErrorCode::Changed,[&]{adapter.replace(old,{});});
    });
    test("wrong thread is rejected", [] {
        ClipboardModel model; ModelClipboard adapter(&model,allowed()); bool rejected=false;
        std::thread worker([&]{try{adapter.capture({});}catch(const ModelError&e){rejected=e.code()==ModelErrorCode::WrongThread;}});
        worker.join(); CHECK(rejected);
    });
    test("destroyed model is rejected", [] {
        auto *model=new ClipboardModel; ModelClipboard adapter(model,allowed()); delete model;
        rejects(ModelErrorCode::Unavailable,[&]{adapter.capture({});});
    });
    test("unsupported QVariant is rejected without invoking its converter", [] {
        conversions=0; QMetaType::registerConverter<Convertible,QByteArray>([](const Convertible&){++conversions;return QByteArray("unsafe");});
        ClipboardModel model; put(model,{{"text/plain",QVariant::fromValue(Convertible{})}}); ModelClipboard adapter(&model,allowed());
        invalid([&]{adapter.capture({});}); invalid([&]{cqs::native::materializeNativeModel(&model,QString(),{});}); CHECK(conversions==0);
    });
    test("capture and desired data respect byte budgets", [] {
        ClipboardModel model; put(model,text("a")); ModelClipboard adapter(&model,allowed()); cqs::transaction::Limits limit; limit.snapshotBytes=10;
        invalid([&]{adapter.capture(limit);}); const auto old=adapter.capture({});
        invalid([&]{adapter.replace(old,{{{"FILE:text/plain",{}}}});}); CHECK(adapter.capture({}).snapshot==old.snapshot);
    });
    test("synthetic persistence port returns only verified readback", [] {
        ClipboardModel model; put(model,text("a")); auto access=allowed(); unsigned calls=0;
        access.persistAndReadback=[&](const View&view,cqs::transaction::Limits){++calls;return view.snapshot;};
        ModelClipboard adapter(&model,access); const auto old=adapter.capture({}); CHECK(adapter.persist(old,{})==old.snapshot && calls==1);
    });
    test("wrong durable readback is rejected", [] {
        ClipboardModel model; put(model,text("a")); auto access=allowed(); access.persistAndReadback=[](const View&,cqs::transaction::Limits){return wanted('b');};
        ModelClipboard adapter(&model,access); const auto old=adapter.capture({}); rejects(ModelErrorCode::Changed,[&]{adapter.persist(old,{});});
    });
    test("edit during persistence is retained and rejected", [] {
        ClipboardModel model; put(model,text("a")); auto access=allowed();
        access.persistAndReadback=[&](const View&view,cqs::transaction::Limits){CHECK(model.setData(model.index(0,0),text("b"),contentType::data));return view.snapshot;};
        ModelClipboard adapter(&model,access); const auto old=adapter.capture({}); rejects(ModelErrorCode::Changed,[&]{adapter.persist(old,{});});
        CHECK(adapter.capture({}).snapshot==wanted('b'));
    });
    test("access callback mutation is rejected", [] {
        ClipboardModel model; put(model,text("a")); auto access=allowed(); bool edit=true;
        access.readable=[&]{if(edit){edit=false;CHECK(model.setData(model.index(0,0),text("b"),contentType::data));}return true;};
        ModelClipboard adapter(&model,access); rejects(ModelErrorCode::Changed,[&]{adapter.capture({});});
    });
    test("reentrant adapter calls from signals are refused", [] {
        ClipboardModel model; ModelClipboard adapter(&model,allowed()); bool refused=false;
        QObject::connect(&model,&QAbstractItemModel::dataChanged,[&]{try{adapter.capture({});}catch(const ModelError&e){refused=e.code()==ModelErrorCode::Reentrant;}});
        adapter.replace(adapter.capture({}),wanted('a')); CHECK(refused);
    });
    test("failed removal preserves data and failed fill reports partial state", [] {
        FaultModel model; model.rows={text("a")}; ModelClipboard adapter(&model,allowed()); const auto old=adapter.capture({});
        model.failRemove=true; rejects(ModelErrorCode::WriteFailed,[&]{adapter.replace(old,wanted('b'));}); CHECK(adapter.capture({}).snapshot==old.snapshot);
        model.failRemove=false; model.failSet=true; rejects(ModelErrorCode::WriteFailed,[&]{adapter.replace(old,wanted('b'));});
        CHECK(adapter.capture({}).snapshot==Snapshot(1));
    });
    test("external insertion callback edit is retained without overwrite", [] {
        ClipboardModel model; ModelClipboard adapter(&model,allowed());
        QObject::connect(&model,&QAbstractItemModel::rowsInserted,[&]{CHECK(model.setData(model.index(0,0),text("u"),contentType::data));});
        const auto old=adapter.capture({}); rejects(ModelErrorCode::Changed,[&]{adapter.replace(old,wanted('a'));});
        CHECK(adapter.capture({}).snapshot==wanted('u'));
    });
    test("protected rows retain identity while surrounding gaps change", [] {
        ClipboardModel model;put(model,{{"text/plain",QByteArray("pin")},{"application/x-copyq-item-pinned",QByteArray()}});
        put(model,text("old"));put(model,{{"text/plain",QByteArray("tag")},{"application/x-copyq-tags",QByteArray("private")}});put(model,text("end"));
        auto access=allowed();access.protection={true,true,{"private;;;;;;;;;;L"}};ModelClipboard adapter(&model,access);auto before=adapter.capture({});
        QPersistentModelIndex pin(model.index(0,0)),tag(model.index(2,0));
        auto desired=before.snapshot;desired[1]={{"text/plain",{'n'}}};desired.insert(desired.begin()+3,{{"text/plain",{'x'}}});desired.pop_back();
        adapter.preflight(before,desired);adapter.replace(before,desired);
        CHECK(pin.isValid()&&pin.row()==0&&tag.isValid()&&tag.row()==2&&adapter.capture({}).snapshot==desired);
        before=adapter.capture({});auto bad=desired;bad.erase(bad.begin()+2);
        rejects(ModelErrorCode::ProtectedItems,[&]{adapter.preflight(before,bad);});CHECK(adapter.capture({}).snapshot==desired);
        bad=desired;bad[0]["text/plain"]={'c'};rejects(ModelErrorCode::ProtectedItems,[&]{adapter.replace(before,bad);});
        bad=desired;std::swap(bad[0],bad[1]);rejects(ModelErrorCode::ProtectedItems,[&]{adapter.replace(before,bad);});
    });
    test("middle pins stay at fixed positions while unprotected prefix changes", [] {
        ClipboardModel model;put(model,text("unprotected"));put(model,{{"text/plain",QByteArray("middle-pin")},{"application/x-copyq-item-pinned",QByteArray()}});put(model,text("after"));
        auto access=allowed();access.protection.pinned=true;ModelClipboard adapter(&model,access);auto before=adapter.capture({});QPersistentModelIndex pin(model.index(1,0));
        auto desired=before.snapshot;desired[0]={{"text/plain",{'c'}}};desired[2]["application/x-copyq-item-pinned"]={};desired.push_back({{"text/plain",{'n'}}});
        adapter.preflight(before,desired);adapter.replace(before,desired);CHECK(pin.isValid()&&pin.row()==1&&adapter.capture({}).snapshot==desired);
    });
    test("tag matching uses ordered exact or anchored regex rules", [] {
        cqs::native::RowProtection p{false,true,{"unlocked;;;;;;;;a.*;;","locked;;;;;;;;a.*;;L","private;;;;;;;;;;L"}};
        CHECK(!p.protects({{"application/x-copyq-tags",{'a','b'}}}));
        CHECK(p.protects({{"application/x-copyq-tags",{'p','r','i','v','a','t','e'}}}));
        CHECK(!p.protects({{"application/x-copyq-tags",{' ','p','r','i','v','a','t','e'}}}));
        p.definitions={"regex;;;;;;;;secret-[0-9]+;;L"};CHECK(p.protects({{"application/x-copyq-tags",{'s','e','c','r','e','t','-','2'}}}));
    });
    test("frozen ciphertext denies mutation and is cleaned up after conversion", [] {
        QString frozen;const auto result=cqs::native::withFrozenCiphertext(QByteArray("cipher"),[&](const QString &file){
            frozen=file;QFile read(file);if(!read.open(QIODevice::ReadOnly))throw std::runtime_error("Frozen ciphertext Qt read failed: "+read.errorString().toStdString());CHECK(read.readAll()=="cipher");read.close();
            QFile write(file);const bool opened=write.open(QIODevice::WriteOnly);if(opened){CHECK(write.write("changed")==-1);CHECK(!write.resize(0));}return QByteArray("converted");
        });CHECK(result=="converted"&&!QFile::exists(frozen));
    });
    test("native DataFile is bounded and content addressed; missing or changed blobs refuse", [] {
        QTemporaryDir temp;CHECK(temp.isValid());blobRoot=temp.path();
#ifdef Q_OS_WIN
        cqs::testing::WindowsAcl acl;acl.apply(std::filesystem::path(blobRoot.toStdWString()));
#endif
        registerDataFileConverter();
        QByteArray serialized;QDataStream stream(&serialized,QIODevice::WriteOnly);stream.setVersion(QDataStream::Qt_4_7);
        const auto original=text(QByteArray("large-native-blob\0binary",24));serializeData(&stream,original,1);CHECK(stream.status()==QDataStream::Ok);
        QVariantMap data;CHECK(deserializeData(&data,serialized));CHECK(data["text/plain"].metaType().id()!=QMetaType::QByteArray);
        ClipboardModel model;put(model,data);const auto actual=cqs::native::materializeNativeModel(&model,blobRoot,{});
        CHECK(cqs::native::materializeNativeModel(&model,blobRoot+"/",{})==actual);
#ifdef Q_OS_WIN
        CHECK(cqs::native::materializeNativeModel(&model,QDir::toNativeSeparators(blobRoot),{})==actual);
#endif
        CHECK(actual==Snapshot({{{"text/plain",cqs::crypto::Bytes({'l','a','r','g','e','-','n','a','t','i','v','e','-','b','l','o','b',0,'b','i','n','a','r','y'})}}}));
        auto tiny=cqs::transaction::Limits{};tiny.snapshotBytes=12;bool caught=false;try{cqs::native::materializeNativeModel(&model,blobRoot,tiny);}catch(...){caught=true;}CHECK(caught);
        const auto file=data["text/plain"].toString();QFile changed(file);CHECK(changed.open(QIODevice::WriteOnly));CHECK(changed.write("different")==9);changed.close();
        caught=false;try{cqs::native::materializeNativeModel(&model,blobRoot,{});}catch(...){caught=true;}CHECK(caught);
        CHECK(QFile::remove(file));caught=false;try{cqs::native::materializeNativeModel(&model,blobRoot,{});}catch(...){caught=true;}CHECK(caught);blobRoot.clear();
    });
    test("worker persistence leaves GUI responsive and only marshals model work",[&] {
        QObject context;ClipboardModel model;put(model,text("a"));
        auto control=std::make_shared<cqs::native::OperationControl>();
        auto access=allowed();access.readable=access.writable=[&]{CHECK(QThread::currentThread()==app.thread());return true;};
        cqs::native::GuiClipboard clipboard(&context,control,&model,access);
        std::atomic<bool> done=false;std::exception_ptr error;int ticks=0;
        QTimer timer;timer.setInterval(1);QObject::connect(&timer,&QTimer::timeout,[&]{++ticks;});timer.start();
        std::thread worker([&]{try{
            const auto before=clipboard.capture({});const auto desired=wanted('b');
            clipboard.preflight(before,desired);const auto after=clipboard.replace(before,desired);
            clipboard.readDurable=[&]{CHECK(QThread::currentThread()!=app.thread());std::this_thread::sleep_for(std::chrono::milliseconds(40));return desired;};
            CHECK(clipboard.persist(after,{})==desired);
        }catch(...){error=std::current_exception();}done=true;});
        QElapsedTimer timeout;timeout.start();while(!done&&timeout.elapsed()<3000){QCoreApplication::processEvents();QThread::msleep(1);}
        CHECK(done);worker.join();if(error)std::rethrow_exception(error);
        CHECK(ticks>0);ModelClipboard actual(&model,allowed());CHECK(actual.capture({}).snapshot==wanted('b'));
    });
    test("worker cannot overwrite edits or a newly opened editor between GUI calls",[&] {
        for(bool edit:{false,true}){
            QObject context;ClipboardModel model;put(model,text("a"));bool editor=false;
            auto control=std::make_shared<cqs::native::OperationControl>();auto access=allowed();access.writable=[&]{return !editor;};
            cqs::native::GuiClipboard clipboard(&context,control,&model,access);
            std::atomic<bool> captured=false,resume=false,done=false;bool rejected=false;
            std::thread worker([&]{try{
                const auto before=clipboard.capture({});captured=true;
                while(!resume)std::this_thread::sleep_for(std::chrono::milliseconds(1));
                clipboard.replace(before,wanted('b'));
            }catch(const ModelError &){rejected=true;}done=true;});
            QElapsedTimer timeout;timeout.start();while(!captured&&timeout.elapsed()<3000){QCoreApplication::processEvents();QThread::msleep(1);}CHECK(captured);
            if(edit)CHECK(model.setData(model.index(0,0),text("u"),contentType::data));else editor=true;
            resume=true;while(!done&&timeout.elapsed()<3000){QCoreApplication::processEvents();QThread::msleep(1);}CHECK(done);worker.join();
            CHECK(rejected);ModelClipboard actual(&model,allowed());CHECK(actual.capture({}).snapshot==wanted(edit?'u':'a'));
        }
    });
    test("cancelling a queued GUI request permits join without pumping GUI events",[&] {
        QObject context;auto control=std::make_shared<cqs::native::OperationControl>();cqs::native::GuiDispatch dispatch(&context,control);
        std::atomic<bool> entered=false,done=false;bool called=false,cancelled=false;
        std::thread worker([&]{entered=true;try{dispatch.call([&]{called=true;});}catch(const cqs::native::Cancelled &){cancelled=true;}done=true;});
        while(!entered)std::this_thread::yield();control->cancel();
        QElapsedTimer timeout;timeout.start();while(!done&&timeout.elapsed()<3000)std::this_thread::sleep_for(std::chrono::milliseconds(1));
        CHECK(done);worker.join();CHECK(cancelled);QCoreApplication::processEvents();CHECK(!called);
    });
    test("deleted model is refused by a later worker replacement",[&] {
        QObject context;auto model=std::make_unique<ClipboardModel>();put(*model,text("a"));
        auto control=std::make_shared<cqs::native::OperationControl>();cqs::native::GuiClipboard clipboard(&context,control,model.get(),allowed());
        std::atomic<bool> captured=false,resume=false,done=false;bool rejected=false;
        std::thread worker([&]{try{const auto before=clipboard.capture({});captured=true;
            while(!resume)std::this_thread::sleep_for(std::chrono::milliseconds(1));clipboard.replace(before,wanted('b'));
        }catch(const ModelError &e){rejected=e.code()==ModelErrorCode::Unavailable;}done=true;});
        QElapsedTimer timeout;timeout.start();while(!captured&&timeout.elapsed()<3000){QCoreApplication::processEvents();QThread::msleep(1);}CHECK(captured);
        model.reset();resume=true;while(!done&&timeout.elapsed()<3000){QCoreApplication::processEvents();QThread::msleep(1);}CHECK(done);worker.join();CHECK(rejected);
    });
    std::cout << passed << " native model/pack scenarios passed\n";
}
