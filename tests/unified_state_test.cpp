// SPDX-License-Identifier: GPL-3.0-or-later
#include "unified_state.h"
#include "gui_clipboard.h"
#include "common/contenttype.h"
#include <QElapsedTimer>
#include <QThread>
#include <atomic>
#include <thread>
#include <chrono>
#include "state_store.h"
#include "state_hooks.h"
#include "storage_hooks.h"
#include "storage.h"
#include "test_check.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <numeric>
#include <cstdlib>
#include <iostream>
#ifdef Q_OS_WIN
#include "windows_test_acl.h"
#else
#include <sys/stat.h>
#endif
namespace cqs::state::testing { std::function<void(Point)> hook; }
namespace cqs::storage::testing { std::function<void(Point)> hook; }
using namespace cqs::native;
using namespace cqs::transaction;
using cqs::crypto::Bytes;
namespace {
int cases=0;
const Snapshot First{{{"text/plain",{'A',0,255,13,10}},{"application/octet-stream",{0,1,255}}},{}};
const Snapshot Second{{{"text/plain",{'B'}}},{},{ {"text/html",{}} }};
const Snapshot Manual{{{"text/plain",{'U','S','E','R'}}}};
std::filesystem::path path(const QString &s) {
#ifdef Q_OS_WIN
 return std::filesystem::path(s.toStdWString());
#else
 return std::filesystem::u8path(s.toUtf8().toStdString());
#endif
}
void directory(const QString &s) {
#ifdef Q_OS_WIN
 cqs::testing::directory(path(s));
#else
 CHECK(QDir().mkdir(s));CHECK(::chmod(QFile::encodeName(s).constData(),0700)==0);
#endif
}
void write(const QString &s,const QByteArray &bytes) {
#ifdef Q_OS_WIN
 cqs::testing::write(path(s),bytes.toStdString());
#else
 QFile f(s);CHECK(f.open(QIODevice::WriteOnly));CHECK(f.write(bytes)==bytes.size());f.close();CHECK(::chmod(QFile::encodeName(s).constData(),0600)==0);
#endif
}
QByteArray read(const QString &s){QFile f(s);CHECK(f.open(QIODevice::ReadOnly));return f.readAll();}
StorageKeysPtr keys(){auto k=std::make_shared<StorageKeys>();k->local=Bytes(32,0x71);k->sync=Bytes(32);std::iota(k->sync.begin(),k->sync.end(),0);return k;}
Profile profile(const QString &root){Profile p{"test-pc",root+"/transport",{},root+"/data"};p.vaultDirectory=root+"/vault";p.standaloneStorage=true;return p;}
QByteArray event(std::uint64_t sequence,const Snapshot &snapshot,const Bytes &key,const std::string &device="remote-pc",std::optional<std::vector<std::string>> parentsOverride={}) {
 const auto h=checkpointRecord("public-fixture",device,snapshot,sequence,parentsOverride?*parentsOverride:sequence==1?std::vector<std::string>{}:std::vector<std::string>{device+"/000000000001"}).head;
 QJsonArray items,parents;for(const auto &s:h->event.items)items.append(QString::fromStdString(s));
 for(const auto &s:h->event.revision.parents)parents.append(QString::fromStdString(s));
 const QJsonObject header{{"device",QString::fromStdString(device)},{"parents",parents},{"protocol","copyq-secure-sync-v1"},{"seq",qint64(sequence)}};
 const auto canonical=QJsonDocument(header).toJson(QJsonDocument::Compact);
 constexpr char domain[]="CopyQ-Secure-Sync-event-v1";Bytes aad(domain,domain+sizeof(domain));aad.insert(aad.end(),canonical.begin(),canonical.end());
 const auto plain=QJsonDocument(QJsonObject{{"items",items},{"tab","synced_tray"},{"v",1}}).toJson(QJsonDocument::Compact);
 const auto nonce=cqs::crypto::random(12),compressed=cqs::crypto::zlibCompress(Bytes(plain.begin(),plain.end()));
 const auto cipher=cqs::crypto::aes256GcmEncrypt(key,nonce,compressed,aad);
 auto b64=[](const Bytes &b){return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(b.data()),qsizetype(b.size())).toBase64());};
 return QJsonDocument(QJsonObject{{"header",header},{"nonce",b64(nonce)},{"ciphertext",b64(cipher)}}).toJson(QJsonDocument::Compact);
}
class GuiFixtureModel final : public QAbstractListModel {
public:
 QList<QVariantMap> rows;
 int rowCount(const QModelIndex & = {}) const override{return int(rows.size());}
 QVariant data(const QModelIndex &i,int role) const override{return i.isValid()&&role==contentType::data?QVariant(rows[i.row()]):QVariant();}
 bool insertRows(int at,int count,const QModelIndex & = {}) override{beginInsertRows({},at,at+count-1);for(int i=0;i<count;++i)rows.insert(at,{});endInsertRows();return true;}
 bool removeRows(int at,int count,const QModelIndex & = {}) override{beginRemoveRows({},at,at+count-1);rows.remove(at,count);endRemoveRows();return true;}
 bool setData(const QModelIndex &i,const QVariant &v,int role) override{if(role!=contentType::data)return false;rows[i.row()]=v.toMap();emit dataChanged(i,i);return true;}
};
struct Fixture {
 QString root;StorageConfiguration c;StorageKeysPtr k=keys();
 explicit Fixture(QString r,bool create=true,bool remoteHistory=true,const QString &transport={}):root(std::move(r)),c([&]{auto p=profile(root);if(!transport.isEmpty())p.transport=transport;return storageConfiguration(p);}()){
  if(create){directory(root);for(auto n:{"transport","data","vault"})directory(root+'/'+n);directory(root+"/transport/events");
   directory(root+"/transport/events/remote-pc");initializeStorage(c,k->local,k->sync);if(remoteHistory)remote(1,First);}
 }
 void remote(unsigned sequence,const Snapshot &snapshot){write(root+"/transport/events/remote-pc/"+QString::number(sequence).rightJustified(12,'0')+".cqs",event(sequence,snapshot,k->sync));}
 Record record(){return readStorage(c,k->local,k->sync);}
 Result action(StateAction a){return runStateAction(c,k,a);}
 QString filename(){return root+"/data/record-v1.cqr";}
};
void refused(const std::function<void()> &f){bool no=false;try{f();}catch(const std::exception &){no=true;}CHECK(no);}
void test(const char *name,const std::function<void()> &f){cqs::state::testing::hook={};cqs::storage::testing::hook={};std::cout<<"RUN "<<name<<std::endl;f();cqs::state::testing::hook={};cqs::storage::testing::hook={};std::cout<<"PASS "<<++cases<<" "<<name<<std::endl;}
void crash(const QString &root,int commit,cqs::state::testing::Point point,StateAction action=StateAction::Join){
 QProcess child;child.start(QCoreApplication::applicationFilePath(),{"--crash",root,QString::number(commit),QString::number(int(point)),QString::number(int(action))});
 CHECK(child.waitForFinished(30000));CHECK(child.exitCode()==86);
}
}
int main(int argc,char **argv){QCoreApplication app(argc,argv);
 if(argc==5&&QString::fromLocal8Bit(argv[1])=="--resolution-crash"){
  Fixture f(QString::fromLocal8Bit(argv[2]),false);const int commit=std::atoi(argv[3]);const auto point=cqs::state::testing::Point(std::atoi(argv[4]));int count=0;
  cqs::state::testing::hook=[&](auto p){if(p==point&&++count==commit)std::_Exit(86);};
  auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);auto r=f.record();
  auto p=prepareResolution(f.c,f.k,r,h,Second);r=reserveResolution(f.c,f.k,r,h,p,true,nullptr);
  deliverPublication(f.c,f.k,r);acceptPublication(f.c,f.k,r,nullptr);prepareResolutionProjection(f.c,f.k,nullptr);
  h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);importDetachedHistory(f.c,f.k,h,true);return 99;
 }
 if(argc==3&&QString::fromLocal8Bit(argv[1])=="--protect-public-copyq-root"){
  const auto root=QFileInfo(QString::fromLocal8Bit(argv[2]));CHECK(root.isDir()&&!root.isSymLink()&&root.fileName().startsWith("cqs-standalone-"));
#ifdef Q_OS_WIN
  cqs::testing::WindowsAcl acl;
  auto protect=[&](const std::filesystem::path &item){CHECK((GetFileAttributesW(item.c_str())&FILE_ATTRIBUTE_REPARSE_POINT)==0);
   BOOL defaulted=FALSE,present=FALSE;PSID owner=nullptr;PACL dacl=nullptr;CHECK(GetSecurityDescriptorOwner(acl.descriptor,&owner,&defaulted));
   CHECK(GetSecurityDescriptorDacl(acl.descriptor,&present,&dacl,&defaulted)&&present);
   CHECK(SetNamedSecurityInfoW(const_cast<wchar_t *>(item.c_str()),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,owner,nullptr,dacl,nullptr)==ERROR_SUCCESS);};
  protect(path(root.absoluteFilePath()));for(const auto &entry:std::filesystem::recursive_directory_iterator(path(root.absoluteFilePath())))protect(entry.path());
#else
  CHECK(::chmod(QFile::encodeName(root.absoluteFilePath()).constData(),0700)==0);
#endif
  std::cout<<"PUBLIC_COPYQ_ROOT_PROTECTED\n";return 0;
 }
 if(argc==4&&QString::fromLocal8Bit(argv[1])=="--update-publish-crash"){
  Fixture f(QString::fromLocal8Bit(argv[2]),false);const auto point=cqs::storage::testing::Point(std::atoi(argv[3]));
  cqs::storage::testing::hook=[point](auto p){if(p==point)std::_Exit(86);};f.action(StateAction::Publish);return 99;
 }
 if(argc==4&&QString::fromLocal8Bit(argv[1])=="--seed-publish-crash"){
  Fixture f(QString::fromLocal8Bit(argv[2]),false);const auto point=cqs::storage::testing::Point(std::atoi(argv[3]));
  cqs::storage::testing::hook=[point](auto p){if(p==point)std::_Exit(86);};f.action(StateAction::Seed);return 99;
 }
 if(argc==6&&QString::fromLocal8Bit(argv[1])=="--crash"){
  Fixture f(QString::fromLocal8Bit(argv[2]),false);const int commit=std::atoi(argv[3]);const auto point=cqs::state::testing::Point(std::atoi(argv[4]));int count=0;
  cqs::state::testing::hook=[&](auto p){if(p==point&&++count==commit)std::_Exit(86);};f.action(StateAction(std::atoi(argv[5])));return 99;
 }
 if(argc==3&&QString::fromLocal8Bit(argv[1])=="--busy"){
  Fixture f(QString::fromLocal8Bit(argv[2]),false);try{f.action(StateAction::Join);}catch(const std::exception &){return 0;}return 99;
 }
 if(argc==4&&QString::fromLocal8Bit(argv[1])=="--migrate-crash"){
  Fixture f(QString::fromLocal8Bit(argv[2]),false);const auto point=cqs::state::testing::Point(std::atoi(argv[3]));
  cqs::state::testing::hook=[point](auto p){if(p==point)std::_Exit(86);};migrateStorageState(f.c,f.k->local,f.k->sync);return 99;
 }
 if(argc==3&&QString::fromLocal8Bit(argv[1])=="--replace-public-event"){
  const auto root=QFileInfo(qEnvironmentVariable("CQS_TEST_PRIVATE_ROOT")).canonicalFilePath();
  const auto filename=QFileInfo(QString::fromLocal8Bit(argv[2])).canonicalFilePath();
  CHECK(QFileInfo(root).fileName().startsWith("cqs-standalone-")&&qEnvironmentVariable("COPYQ_SESSION_NAME").startsWith("cqslab-"));
  CHECK(filename.startsWith(root+'/')&&filename.contains("/transport/events/")&&filename.endsWith(".cqs"));
  const auto info=QFileInfo(filename);const auto device=info.dir().dirName().toStdString();
  const auto sequence=info.baseName().toULongLong();const auto id=cqs::history::makeId(device,sequence);
  const auto wire=read(filename).toStdString();const auto old=cqs::events::decode(keys()->sync,{id,wire});
  write(filename,event(sequence,Manual,keys()->sync,device,old.revision.parents));
  std::cout<<"PUBLIC_AUTHENTICATED_EVENT_REPLACED\n";return 0;
 }
 if(argc==4&&QString::fromLocal8Bit(argv[1])=="--write-public-history"){
  const auto root=QFileInfo(qEnvironmentVariable("COPYQ_SETTINGS_PATH")).dir().absolutePath();
  const auto destination=QString::fromLocal8Bit(argv[2]);const int sequence=std::atoi(argv[3]);
  CHECK(QFileInfo(root).fileName().startsWith("cqs-standalone-")&&qEnvironmentVariable("COPYQ_SESSION_NAME").startsWith("cqslab-"));
  CHECK(destination==root+"/transport"&&(sequence==1||sequence==2));
  const auto folder=destination+"/events/remote-pc";if(sequence==1)directory(folder);
  write(folder+'/'+QString::number(sequence).rightJustified(12,'0')+".cqs",event(unsigned(sequence),sequence==1?First:Second,keys()->sync));
  std::cout<<"PUBLIC_HISTORY_FIXTURE_CREATED\n";return 0;
 }
 CHECK(argc==1);QTemporaryDir temporary;CHECK(temporary.isValid());int count=0;auto root=[&]{return temporary.path()+"/case-"+QString::number(++count);};
 test("persisted witnesses reject altered ancestors and missing previously observed branches",[&]{
  Fixture f(root());CHECK(f.action(StateAction::Join)==Result::Applied);f.remote(2,Second);
  CHECK(f.action(StateAction::FastForward)==Result::Applied);
  const auto trusted=read(f.root+"/transport/events/remote-pc/000000000001.cqs"),before=read(f.filename());
  f.remote(1,Manual);refused([&]{f.action(StateAction::FastForward);});CHECK(read(f.filename())==before);
  write(f.root+"/transport/events/remote-pc/000000000001.cqs",trusted);
  CHECK(f.action(StateAction::FastForward)==Result::UpToDate);
  // This branch was observed but never accepted as a head.
  const auto branch=f.root+"/transport/events/test-pc";directory(branch);
  // Seed a second, independently authenticated root using the real publisher.
  Fixture peer(root(),true,false);
  // A different local device name is unnecessary for this independent root;
  // the default test-pc ID is distinct from the remote-pc accepted lineage.
  saveStorage(peer.c,Manual,peer.k->local,peer.k->sync);CHECK(peer.action(StateAction::Seed)==Result::Applied);
  const auto wire=read(peer.root+"/transport/events/test-pc/000000000001.cqs");write(branch+"/000000000001.cqs",wire);
  auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);CHECK(h.graph().hasConflict());
  const auto observed=observeHistory(f.c,f.k,h,nullptr);CHECK(observed.schema==6&&observed.witnessed.size()==3);
  const auto durable=read(f.filename());CHECK(QFile::remove(branch+"/000000000001.cqs"));
  refused([&]{f.action(StateAction::FastForward);});CHECK(read(f.filename())==durable);
  // A fresh instance still retains the rejected branch's witness.
  Fixture restarted(f.root,false);write(branch+"/000000000001.cqs",wire);
  h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);CHECK(observeHistory(restarted.c,restarted.k,h,nullptr).witnessed==observed.witnessed);
 });
 test("explicit divergent recovery preserves edits before retry or restore without transport",[&]{
  for(auto action:{StateAction::PreserveAndRetry,StateAction::PreserveAndRestore}){
   Fixture f(root());CHECK(f.action(StateAction::Join)==Result::Applied);f.remote(2,Second);
   crash(f.root,1,cqs::state::testing::Point::Published,StateAction::FastForward);
   CHECK(f.record().pending);saveStorage(f.c,Manual,f.k->local,f.k->sync);
   const auto before=read(f.filename());refused([&]{f.action(StateAction::RetryImport);});CHECK(read(f.filename())==before);
   CHECK(QDir().rename(f.root+"/transport",f.root+"/offline"));
   CHECK(f.action(action)==(action==StateAction::PreserveAndRetry?Result::Applied:Result::Restored));
   const auto r=f.record();CHECK(!r.pending&&r.archives.front()==Manual);
   CHECK(r.local==(action==StateAction::PreserveAndRetry?Second:First));
   CHECK(r.head->snapshot==*r.local);
  }
 });
 test("history publication capacity refuses count and aggregate byte overflow before reservation",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);
  const auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);const auto before=f.record();
  const auto p=*preparePublication(f.c,f.k,before,h);cqs::events::Limits limits;
  limits.events=1;refused([&]{checkHistoryCapacity(h,p,1,limits);});
  limits={};limits.historyBytes=h.wireBytes()+p.wire.size();checkHistoryCapacity(h,p,1,limits);
  --limits.historyBytes;refused([&]{checkHistoryCapacity(h,p,1,limits);});
  limits={};limits.historyPlaintextBytes=h.events().front().plaintextBytes+p.target.event.plaintextBytes;
  checkHistoryCapacity(h,p,1,limits);--limits.historyPlaintextBytes;
  refused([&]{checkHistoryCapacity(h,p,1,limits);});
  CHECK(f.record().generation==before.generation&&!f.record().publication);
 });
 test("empty device directories cannot make a new publication exceed the scan device ceiling",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);
  for(unsigned n=1;n<128;++n)directory(f.root+"/transport/events/empty-"+QString::number(n));
  const auto before=read(f.filename());refused([&]{f.action(StateAction::Publish);});
  CHECK(read(f.filename())==before&&!f.record().publication);
 });
 test("full production history remains readable but refuses another publication without allocating an ID",[&]{
  Fixture f(root());f.action(StateAction::Join);
  for(unsigned n=2;n<=cqs::history::MaxEvents;++n)
   write(f.root+"/transport/events/remote-pc/"+QString::number(n).rightJustified(12,'0')+".cqs",
    event(n,First,f.k->sync,"remote-pc",std::vector<std::string>{cqs::history::makeId("remote-pc",n-1)}));
  CHECK(f.action(StateAction::FastForward)==Result::Applied);CHECK(f.record().witnessed.size()==cqs::history::MaxEvents);
  saveStorage(f.c,Manual,f.k->local,f.k->sync);const auto before=read(f.filename());
  try{f.action(StateAction::Publish);CHECK(false);}catch(const Error &e){CHECK(e.code()==ErrorCode::HistoryLimit);}
  CHECK(read(f.filename())==before&&!f.record().publication&&f.record().allocatedSequence==0);
 });
 test("divergent recovery capacity and interrupted backup retain edits across retry",[&]{
  Fixture f(root());f.action(StateAction::Join);f.remote(2,Second);
  crash(f.root,1,cqs::state::testing::Point::Published,StateAction::FastForward);
  saveStorage(f.c,Manual,f.k->local,f.k->sync);
  cqs::state::FileStore store(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),f.k->local);
  {auto lease=store.lock();const auto before=store.load();auto next=before;++next.generation;
   next.archives={First,Second,First,Second};store.commit(before,next);}
  const auto full=read(f.filename());refused([&]{f.action(StateAction::PreserveAndRetry);});CHECK(read(f.filename())==full&&f.record().local==Manual);
  auto r=f.record();discardArchive(f.c,f.k,r,0,nullptr);CHECK(f.record().pending&&f.record().archives.size()==3);
  bool interrupted=false;cqs::state::testing::hook=[&](auto point){if(!interrupted&&point==cqs::state::testing::Point::Published){interrupted=true;throw std::runtime_error("public interruption");}};
  refused([&]{f.action(StateAction::PreserveAndRetry);});cqs::state::testing::hook={};CHECK(interrupted);
  r=f.record();CHECK(r.pending&&r.local==Manual&&r.archives.front()==Manual&&r.archives.size()==4);
  CHECK(f.action(StateAction::PreserveAndRetry)==Result::Applied);r=f.record();CHECK(!r.pending&&r.archives.size()==4&&r.local==Second);
 });
 test("preserve-and-recover retains the active resolution original while archiving post-crash edits",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);f.action(StateAction::Publish);f.remote(2,Second);
  const auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);auto r=f.record();
  const auto p=prepareResolution(f.c,f.k,r,h,Second);r=reserveResolution(f.c,f.k,r,h,p,true,nullptr);
  deliverPublication(f.c,f.k,r);acceptPublication(f.c,f.k,r,nullptr);prepareResolutionProjection(f.c,f.k,nullptr);
  CHECK(f.record().pending&&f.record().resolution);saveStorage(f.c,First,f.k->local,f.k->sync);
  CHECK(QDir().rename(f.root+"/transport",f.root+"/offline"));
  CHECK(f.action(StateAction::PreserveAndRetry)==Result::Applied);r=f.record();
  CHECK(!r.pending&&!r.resolution&&r.local==Second&&r.archives.front()==First&&r.archives.back()==Manual);
 });
 test("staged publication preserves saves during inspection and delivery",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);const auto captured=f.record();
  auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  const auto p=preparePublication(f.c,f.k,captured,h);CHECK(p);
  saveStorage(f.c,Second,f.k->local,f.k->sync);const auto reserved=reservePublication(f.c,f.k,captured,*p,nullptr);
  CHECK(reserved.local==Second&&reserved.publication->target.snapshot==Manual);
  deliverPublication(f.c,f.k,reserved);saveStorage(f.c,First,f.k->local,f.k->sync);
  const auto accepted=acceptPublication(f.c,f.k,reserved,nullptr);
  CHECK(accepted.local==First&&accepted.head->snapshot==Manual&&!accepted.publication);
 });
 test("protected detached import refuses before any record or head commit",[&]{
  Fixture f(root(),true,false);Snapshot protectedData={{{"text/plain",{'p'}},{"application/x-copyq-item-pinned",{}}},{{"text/plain",{'t'}},{"application/x-copyq-tags",{'p','r','i','v','a','t','e'}}}};
  f.remote(1,protectedData);CHECK(f.action(StateAction::Join)==Result::Applied);const auto before=read(f.filename());
  f.remote(2,Second);RowProtection policy{true,true,{"private;;;;;;;;;;L"}};
  refused([&]{runStateAction(f.c,f.k,StateAction::FastForward,nullptr,policy);});CHECK(read(f.filename())==before&&!f.record().pending);
  const auto history=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  refused([&]{importDetachedHistory(f.c,f.k,history,false,Recovery::RetryImport,policy);});CHECK(read(f.filename())==before);
  auto desired=protectedData;desired.push_back({{"text/plain",{'n'}}});f.remote(2,desired);
  CHECK(importDetachedHistory(f.c,f.k,cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync),false,Recovery::RetryImport,policy)==Result::Applied);
  CHECK(f.record().local==desired&&f.record().head->snapshot==desired);
 });
 test("explicit conflict resolution joins all branches and preserves original local data",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);f.action(StateAction::Publish);f.remote(2,Second);
  auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);CHECK(h.graph().hasConflict());
  const auto before=f.record();auto p=prepareResolution(f.c,f.k,before,h,Second);
  auto r=reserveResolution(f.c,f.k,before,h,p,true,nullptr);CHECK(r.schema==6&&r.archives.back()==Manual);
  deliverPublication(f.c,f.k,r);acceptPublication(f.c,f.k,r,nullptr);r=f.record();CHECK(r.local==Manual&&r.head->snapshot==Second);
  prepareResolutionProjection(f.c,f.k,nullptr);h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  CHECK(importDetachedHistory(f.c,f.k,h,true)==Result::Applied);r=f.record();
  CHECK(r.local==Second&&!r.resolution&&!r.pending&&r.archives.back()==Manual);
  saveStorage(f.c,First,f.k->local,f.k->sync);CHECK(f.action(StateAction::Publish)==Result::Applied);
  CHECK(f.record().schema==6&&f.record().archives.back()==Manual);
 });
 test("restoring a full protected archive preserves current data and retains the selected snapshot",[&]{
  Fixture f(root());f.action(StateAction::Join);auto before=f.record();
  cqs::state::FileStore store(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),f.k->local);
  {auto lease=store.lock();auto next=before;next.schema=std::max(5u,next.schema);++next.generation;next.archives={Manual,Second,First,Manual};store.commit(before,next);}
  auto r=f.record();auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  auto publication=prepareResolution(f.c,f.k,r,h,Manual);r=reserveResolution(f.c,f.k,r,h,publication,true,nullptr,0);
  CHECK(r.archives.size()==4&&r.archives.back()==First&&r.publication->target.snapshot==Manual);
  deliverPublication(f.c,f.k,r);acceptPublication(f.c,f.k,r,nullptr);prepareResolutionProjection(f.c,f.k,nullptr);
  h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);CHECK(importDetachedHistory(f.c,f.k,h,true)==Result::Applied);
  CHECK(f.record().local==Manual&&f.record().archives.back()==First);
  const auto stale=f.record();saveStorage(f.c,Second,f.k->local,f.k->sync);
  refused([&]{discardArchive(f.c,f.k,stale,0,nullptr);});CHECK(f.record().archives.size()==4&&f.record().local==Second);
  const auto beforeRemoval=f.record();discardArchive(f.c,f.k,beforeRemoval,0,nullptr);
  CHECK(f.record().archives.size()==3&&f.record().head->event.revision.id==beforeRemoval.head->event.revision.id&&f.record().local==Second);
 });
 test("reserved resolution refuses new branches until explicit exact-event reconciliation",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);f.action(StateAction::Publish);f.remote(2,Second);
  auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);auto r=f.record();
  const auto p=prepareResolution(f.c,f.k,r,h,Second);r=reserveResolution(f.c,f.k,r,h,p,true,nullptr);f.remote(3,First);
  refused([&]{deliverPublication(f.c,f.k,r);});CHECK(f.record().publication->wire==p.wire&&f.record().local==Manual);
  deliverPublication(f.c,f.k,r,true);acceptPublication(f.c,f.k,r,nullptr);
  h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  CHECK(h.graph().hasConflict()&&h.graph().contains(p.target.event.revision.id)&&f.record().allocatedSequence==p.target.event.revision.sequence);
 });
 test("projection capacity is checked before reserving any irreversible merge event",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);f.remote(2,Second);
  const Snapshot largeArchive{{{"application/octet-stream",Bytes(20*1024*1024,'A')}}};
  {cqs::state::FileStore store(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),f.k->local);auto lease=store.lock();
   const auto before=store.load();auto next=before;next.schema=std::max(5u,next.schema);++next.generation;next.archives={largeArchive,largeArchive,largeArchive};store.commit(before,next);}
  const Snapshot chosen{{{"application/octet-stream",Bytes(23*1024*1024,'B')}}};
  auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);auto r=f.record();const auto p=prepareResolution(f.c,f.k,r,h,chosen);
  refused([&]{reserveResolution(f.c,f.k,r,h,p,true,nullptr);});
  const auto after=f.record();CHECK(after.generation==r.generation&&after.local==Manual&&after.archives.size()==3&&!after.publication&&!after.resolution);
  CHECK(cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync).events().size()==2);
 });
 test("all twenty-five resolution state crash boundaries retain recoverable choices and local backup",[&]{
  for(int commit=1;commit<=5;++commit)for(auto point:{cqs::state::testing::Point::StageSynced,cqs::state::testing::Point::StageLinked,cqs::state::testing::Point::BeforePublish,cqs::state::testing::Point::Published,cqs::state::testing::Point::DirectorySynced}){
   Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);f.action(StateAction::Publish);f.remote(2,Second);
   QProcess child;child.start(QCoreApplication::applicationFilePath(),{"--resolution-crash",f.root,QString::number(commit),QString::number(int(point))});
   CHECK(child.waitForFinished(30000)&&child.exitCode()==86);auto r=f.record();
   CHECK(r.local==Manual||r.local==Second);
   if(r.archives.empty()){CHECK(!r.publication&&!r.resolution&&r.local==Manual);continue;}
   CHECK(r.archives.back()==Manual);
   if(r.publication){deliverPublication(f.c,f.k,r);acceptPublication(f.c,f.k,r,nullptr);r=f.record();}
   if(r.resolution&&!r.pending){prepareResolutionProjection(f.c,f.k,nullptr);r=f.record();}
   if(r.pending){const cqs::events::AuthenticatedHistory offline(f.k->sync,{});CHECK(importDetachedHistory(f.c,f.k,offline,true)==Result::Applied);}
   CHECK(f.record().local==Second&&!f.record().pending&&!f.record().resolution&&f.record().archives.back()==Manual);
  }
 });
 test("three-tip decisions recover intermediate merges and never absorb unreviewed local changes",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);f.action(StateAction::Publish);f.remote(2,Second);
  directory(f.root+"/transport/events/third-pc");
  auto third=f.c;third.profile.device="third-pc";third.profile.stateDirectory=f.root+"/third-data";directory(third.profile.stateDirectory);third=storageConfiguration(third.profile);
  initializeStorage(third,f.k->local,f.k->sync);saveStorage(third,First,f.k->local,f.k->sync);

  // Use the actual publisher to create a separate root before combining transport.
  auto isolated=third;isolated.profile.transport=f.root+"/third-transport";directory(isolated.profile.transport);directory(isolated.profile.transport+"/events");
  isolated=storageConfiguration(isolated.profile);CHECK(QFile::remove(f.root+"/third-data/record-v1.cqr"));initializeStorage(isolated,f.k->local,f.k->sync);
  saveStorage(isolated,First,f.k->local,f.k->sync);runStateAction(isolated,f.k,StateAction::Seed);
  write(f.root+"/transport/events/third-pc/000000000001.cqs",read(f.root+"/third-transport/events/third-pc/000000000001.cqs"));
  auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);CHECK(h.graph().tips().size()==3);
  auto r=f.record();auto p=prepareResolution(f.c,f.k,r,h,Manual);r=reserveResolution(f.c,f.k,r,h,p,true,nullptr);
  deliverPublication(f.c,f.k,r);acceptPublication(f.c,f.k,r,nullptr);
  h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);r=f.record();CHECK(r.resolution->tips.size()==2);
  p=prepareResolution(f.c,f.k,r,h,r.head->snapshot);r=reserveResolution(f.c,f.k,r,h,p,false,nullptr);
  deliverPublication(f.c,f.k,r);acceptPublication(f.c,f.k,r,nullptr);
  saveStorage(f.c,Second,f.k->local,f.k->sync);refused([&]{prepareResolutionProjection(f.c,f.k,nullptr);});
  CHECK(f.record().local==Second&&f.record().archives.back()==Manual&&f.record().resolution);
  {cqs::state::FileStore store(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),f.k->local);auto lease=store.lock();const auto before=store.load();
   auto next=before;++next.generation;next.archives.insert(next.archives.begin(),{First,First,First});store.commit(before,next);}
  r=f.record();refused([&]{discardArchive(f.c,f.k,r,3,nullptr);});discardArchive(f.c,f.k,r,0,nullptr);
  CHECK(f.record().resolution&&f.record().archives.size()==3&&f.record().archives.back()==Manual);
  h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  r=f.record();p=prepareResolution(f.c,f.k,r,h,Second);r=reserveResolution(f.c,f.k,r,h,p,true,nullptr);
  deliverPublication(f.c,f.k,r);acceptPublication(f.c,f.k,r,nullptr);prepareResolutionProjection(f.c,f.k,nullptr);
  CHECK(!f.record().resolution&&f.record().local==Second&&f.record().archives.back()==Second);
 });
 test("bidirectional subsequent publication uses per-device counters and retained accepted heads",[&]{
  Fixture first(root(),true,false);saveStorage(first.c,First,first.k->local,first.k->sync);first.action(StateAction::Seed);
  Fixture peer(root(),true,false);peer.c.profile.device="peer-pc";peer.c.profile.transport=first.c.profile.transport;
  peer.c=storageConfiguration(peer.c.profile);CHECK(QFile::remove(peer.filename()));initializeStorage(peer.c,peer.k->local,peer.k->sync);
  CHECK(peer.action(StateAction::Join)==Result::Applied);
  saveStorage(peer.c,Second,peer.k->local,peer.k->sync);CHECK(peer.action(StateAction::Sync)==Result::Applied);
  auto r=peer.record();CHECK(r.schema==6&&r.allocatedSequence==1&&r.head->event.revision.parents==std::vector<std::string>{"test-pc/000000000001"});
  CHECK(first.action(StateAction::Sync)==Result::Applied&&first.record().local==Second);
  saveStorage(first.c,Manual,first.k->local,first.k->sync);CHECK(first.action(StateAction::Sync)==Result::Applied);
  CHECK(first.record().allocatedSequence==2&&first.record().head->event.revision.sequence==2);
  CHECK(peer.action(StateAction::Sync)==Result::Applied&&peer.record().local==Manual);
  CHECK(peer.action(StateAction::Sync)==Result::UpToDate&&first.action(StateAction::Sync)==Result::UpToDate);
  CHECK(cqs::storage::Directory(path(first.c.profile.transport)).scan(first.k->sync).events().size()==3);
 });
 test("publication rejects a reused ID, wrong parent or mismatched captured contents before reservation",[&]{
  Fixture f(root(),true,false);saveStorage(f.c,First,f.k->local,f.k->sync);f.action(StateAction::Seed);
  saveStorage(f.c,Second,f.k->local,f.k->sync);const auto before=f.record();
  const auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  const auto prepared=*preparePublication(f.c,f.k,before,h);const auto disk=read(f.filename());
  auto wrong=prepared;wrong.target.event.revision.sequence=before.allocatedSequence;
  refused([&]{reservePublication(f.c,f.k,before,wrong,nullptr);});CHECK(read(f.filename())==disk);
  wrong=prepared;wrong.target.event.revision.parents.clear();
  refused([&]{reservePublication(f.c,f.k,before,wrong,nullptr);});CHECK(read(f.filename())==disk);
  // A correctly encrypted event from a different capture must also be refused.
  auto otherCapture=before;otherCapture.local=Manual;
  wrong=*preparePublication(f.c,f.k,otherCapture,h);
  refused([&]{reservePublication(f.c,f.k,before,wrong,nullptr);});CHECK(read(f.filename())==disk);
  auto foreign=before;foreign.binding="another-profile";
  refused([&]{reservePublication(f.c,f.k,foreign,prepared,nullptr);});CHECK(read(f.filename())==disk);
 });
 test("repeated delivery confirms identical ciphertext and preserves later local edits",[&]{
  Fixture f(root(),true,false);saveStorage(f.c,First,f.k->local,f.k->sync);f.action(StateAction::Seed);
  saveStorage(f.c,Second,f.k->local,f.k->sync);const auto before=f.record();
  const auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  const auto reserved=reservePublication(f.c,f.k,before,*preparePublication(f.c,f.k,before,h),nullptr);
  saveStorage(f.c,Manual,f.k->local,f.k->sync);
  deliverPublication(f.c,f.k,reserved);
#ifdef Q_OS_WIN
  // Once the final event exists, retry must confirm it without needing staging.
  f.c.profile.publicationStaging=f.root+"/missing-after-publication";
#endif
  for(int i=0;i<2;++i)deliverPublication(f.c,f.k,reserved);
  CHECK(read(f.root+"/transport/events/test-pc/000000000002.cqs").toStdString()==reserved.publication->wire);
  acceptPublication(f.c,f.k,reserved,nullptr);const auto accepted=f.record();
  CHECK(!accepted.publication&&accepted.local==Manual&&accepted.head->snapshot==Second&&accepted.allocatedSequence==2);
  const auto disk=read(f.filename());refused([&]{f.action(StateAction::RetryPublication);});CHECK(read(f.filename())==disk);
  CHECK(cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync).events().size()==2);
 });
#ifdef Q_OS_WIN
 test("Windows separates private state from transport on another fixed NTFS volume",[&]{
  const auto originalDrive=QDir::toNativeSeparators(temporary.path()).left(3).toStdWString();wchar_t originalVolume[64]{};
  CHECK(GetVolumeNameForVolumeMountPointW(originalDrive.c_str(),originalVolume,64));bool exercised=false;
  for(const auto &drive:QDir::drives()){
   const auto name=QDir::toNativeSeparators(drive.absoluteFilePath()).toStdWString();wchar_t volume[64]{},filesystem[32]{};
   if(GetDriveTypeW(name.c_str())!=DRIVE_FIXED||!GetVolumeNameForVolumeMountPointW(name.c_str(),volume,64)||_wcsicmp(volume,originalVolume)==0)continue;
   if(!GetVolumeInformationW(name.c_str(),nullptr,0,nullptr,nullptr,nullptr,filesystem,32)||std::wstring(filesystem)!=L"NTFS")continue;
   QTemporaryDir alternate(drive.absoluteFilePath()+"cqs-publish-XXXXXX");if(!alternate.isValid())continue;
   directory(alternate.path()+"/transport");directory(alternate.path()+"/transport/events");directory(alternate.path()+"/staging");
   Fixture f(root(),true,false,alternate.path()+"/transport");saveStorage(f.c,First,f.k->local,f.k->sync);
   const auto binding=f.c.binding;const auto disk=read(f.filename());
   refused([&]{f.action(StateAction::Seed);});CHECK(read(f.filename())==disk&&f.record().allocatedSequence==0);
   f.c.profile.publicationStaging=alternate.path()+"/staging";
   CHECK(storageConfiguration(f.c.profile).binding==binding);CHECK(f.action(StateAction::Seed)==Result::Applied);
   saveStorage(f.c,Second,f.k->local,f.k->sync);CHECK(f.action(StateAction::Publish)==Result::Applied);
   CHECK(f.record().allocatedSequence==2&&f.record().head->snapshot==Second&&QDir(f.c.profile.publicationStaging).isEmpty());
   CHECK(cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync).events().size()==2);
   exercised=true;break;
  }
  std::cout<<(exercised?"VERIFIED_CROSS_VOLUME_STAGING":"SKIP_CROSS_VOLUME_STAGING_NO_SECOND_WRITABLE_NTFS")<<std::endl;
 });
 test("Windows staging can be corrected without changing vault identity or consuming an ID",[&]{
  Fixture f(root(),true,false);saveStorage(f.c,First,f.k->local,f.k->sync);
  const auto binding=f.c.binding;const auto original=read(f.filename());
  f.c.profile.publicationStaging=f.root+"/missing-stage";
  refused([&]{f.action(StateAction::Seed);});CHECK(read(f.filename())==original);
  directory(f.root+"/publish-stage");f.c.profile.publicationStaging=f.root+"/publish-stage";
  CHECK(storageConfiguration(f.c.profile).binding==binding);CHECK(f.action(StateAction::Seed)==Result::Applied);
  saveStorage(f.c,Second,f.k->local,f.k->sync);const auto before=f.record();
  const auto h=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);
  const auto planned=*preparePublication(f.c,f.k,before,h);const auto clean=read(f.filename());
  f.c.profile.publicationStaging=f.root+"/unavailable-stage";
  refused([&]{reservePublication(f.c,f.k,before,planned,nullptr);});CHECK(read(f.filename())==clean&&f.record().allocatedSequence==1);
  f.c.profile.publicationStaging=f.root+"/publish-stage";
  const auto reserved=reservePublication(f.c,f.k,before,planned,nullptr);
  f.c.profile.publicationStaging=f.root+"/missing-again";
  refused([&]{deliverPublication(f.c,f.k,reserved);});CHECK(f.record().publication->wire==reserved.publication->wire);
  directory(f.root+"/replacement-stage");f.c.profile.publicationStaging=f.root+"/replacement-stage";
  CHECK(storageConfiguration(f.c.profile).binding==binding);CHECK(f.action(StateAction::RetryPublication)==Result::Applied);
  CHECK(f.record().allocatedSequence==2&&f.record().head->snapshot==Second);
  CHECK(QDir(f.root+"/publish-stage").isEmpty()&&QDir(f.root+"/replacement-stage").isEmpty());
 });
#endif
 test("all ten subsequent-publication state crash boundaries preserve head, counter and later edits",[&]{
  for(int commit=1;commit<=2;++commit)for(auto point:{cqs::state::testing::Point::StageSynced,cqs::state::testing::Point::StageLinked,cqs::state::testing::Point::BeforePublish,cqs::state::testing::Point::Published,cqs::state::testing::Point::DirectorySynced}){
   Fixture f(root(),true,false);saveStorage(f.c,First,f.k->local,f.k->sync);f.action(StateAction::Seed);
   saveStorage(f.c,Second,f.k->local,f.k->sync);crash(f.root,commit,point,StateAction::Publish);
   auto r=f.record();if(r.publication){CHECK(r.schema==6&&r.head->snapshot==First&&r.allocatedSequence==2);
    const auto wire=r.publication->wire;saveStorage(f.c,Manual,f.k->local,f.k->sync);
    CHECK(f.action(StateAction::RetryPublication)==Result::Applied);CHECK(f.record().local==Manual&&f.record().head->snapshot==Second);
    CHECK(read(f.root+"/transport/events/test-pc/000000000002.cqs").toStdString()==wire);
   }else if(r.head->snapshot==First)CHECK(f.action(StateAction::Publish)==Result::Applied);
   CHECK(f.record().allocatedSequence==2&&!f.record().publication);
   CHECK(cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync).events().size()==2);
  }
 });
 test("subsequent transport crashes reuse exact ciphertext without allocating another revision",[&]{
  for(auto point:{cqs::storage::testing::Point::PublishWritten,cqs::storage::testing::Point::PublishReady,cqs::storage::testing::Point::PublishLinked}){
   Fixture f(root(),true,false);saveStorage(f.c,First,f.k->local,f.k->sync);f.action(StateAction::Seed);
   saveStorage(f.c,Second,f.k->local,f.k->sync);QProcess child;
   child.start(QCoreApplication::applicationFilePath(),{"--update-publish-crash",f.root,QString::number(int(point))});
   CHECK(child.waitForFinished(30000));CHECK(child.exitCode()==86);const auto r=f.record();
   CHECK(r.publication&&r.head->snapshot==First&&r.allocatedSequence==2);
   CHECK(f.action(StateAction::RetryPublication)==Result::Applied);
   CHECK(read(f.root+"/transport/events/test-pc/000000000002.cqs").toStdString()==r.publication->wire);
   CHECK(f.record().head->snapshot==Second&&f.record().allocatedSequence==2);
  }
 });
 test("automatic cycle retains observed remote work and refuses withheld history or unfinished intents",[&]{
  Fixture f(root());f.action(StateAction::Join);saveStorage(f.c,Manual,f.k->local,f.k->sync);f.remote(2,Second);
  const auto before=f.record();refused([&]{f.action(StateAction::Sync);});const auto observed=f.record();
  CHECK(observed.local==Manual&&observed.head->event.revision.id==before.head->event.revision.id);
  CHECK(observed.allocatedSequence==before.allocatedSequence&&!observed.publication&&observed.witnessed.size()==2);
  CHECK(QFile::remove(f.root+"/transport/events/remote-pc/000000000002.cqs"));
  const auto retained=read(f.filename());refused([&]{f.action(StateAction::Publish);});CHECK(read(f.filename())==retained);
  Fixture g(root());g.action(StateAction::Join);saveStorage(g.c,Manual,g.k->local,g.k->sync);
  crash(g.root,1,cqs::state::testing::Point::Published,StateAction::Publish);
  const auto reserved=read(g.filename());refused([&]{g.action(StateAction::Sync);});CHECK(read(g.filename())==reserved);
  CHECK(QFile::remove(g.root+"/transport/events/remote-pc/000000000001.cqs"));
  refused([&]{g.action(StateAction::RetryPublication);});CHECK(read(g.filename())==reserved);
 });
 test("Seed reserves exact ciphertext and Join connects two independently encrypted devices",[&]{
  Fixture first(root(),true,false);saveStorage(first.c,First,first.k->local,first.k->sync);
  CHECK(first.action(StateAction::Seed)==Result::Applied);auto r=first.record();
  CHECK(r.schema==6&&r.allocatedSequence==1&&r.head&&r.local==First&&!r.publication);
  const auto wire=read(first.root+"/transport/events/test-pc/000000000001.cqs");
  CHECK(first.action(StateAction::RetrySeed)==Result::UpToDate);refused([&]{first.action(StateAction::Seed);});
  CHECK(read(first.root+"/transport/events/test-pc/000000000001.cqs")==wire);
  Fixture second(root(),true,false);second.c.profile.device="second-pc";second.c.profile.transport=first.c.profile.transport;
  second.c=storageConfiguration(second.c.profile);second.k->local=Bytes(32,0x92);CHECK(QFile::remove(second.filename()));
  initializeStorage(second.c,second.k->local,second.k->sync);CHECK(second.action(StateAction::Join)==Result::Applied);
  CHECK(second.record().local==First&&second.record().head->event.revision.device=="test-pc");
  CHECK(read(second.filename())!=read(first.filename()));
  first.remote(1,Manual);refused([&]{first.action(StateAction::RetrySeed);});
  CHECK(first.record().head&&first.record().local==First);
 });
 test("all ten Seed state-commit crash boundaries reconcile without another revision",[&]{
  for(int commit=1;commit<=2;++commit)for(auto point:{cqs::state::testing::Point::StageSynced,cqs::state::testing::Point::StageLinked,cqs::state::testing::Point::BeforePublish,cqs::state::testing::Point::Published,cqs::state::testing::Point::DirectorySynced}){
   Fixture f(root(),true,false);saveStorage(f.c,First,f.k->local,f.k->sync);crash(f.root,commit,point,StateAction::Seed);
   auto r=f.record();if(r.publication)CHECK(f.action(StateAction::RetrySeed)==Result::Applied);else if(!r.head)CHECK(f.action(StateAction::Seed)==Result::Applied);
   CHECK(f.record().local==First&&f.record().allocatedSequence==1&&f.record().head&&!f.record().publication);
   const auto history=cqs::storage::Directory(path(f.c.profile.transport)).scan(f.k->sync);CHECK(history.events().size()==1);
  }
 });
 test("all three transport-publication crash boundaries reuse reserved ciphertext",[&]{
  for(auto point:{cqs::storage::testing::Point::PublishWritten,cqs::storage::testing::Point::PublishReady,cqs::storage::testing::Point::PublishLinked}){
   Fixture f(root(),true,false);saveStorage(f.c,First,f.k->local,f.k->sync);QProcess child;
   child.start(QCoreApplication::applicationFilePath(),{"--seed-publish-crash",f.root,QString::number(int(point))});CHECK(child.waitForFinished(30000));CHECK(child.exitCode()==86);
   const auto before=f.record();CHECK(before.publication&&before.local==First);const auto wire=before.publication->wire;
   CHECK(f.action(StateAction::RetrySeed)==Result::Applied);
   CHECK(read(f.root+"/transport/events/test-pc/000000000001.cqs").toStdString()==wire&&f.record().allocatedSequence==1);
  }
 });
 test("changed ciphertext and unavailable transport retain intent; later Seed edits remain local",[&]{
  Fixture f(root(),true,false);saveStorage(f.c,First,f.k->local,f.k->sync);
  crash(f.root,1,cqs::state::testing::Point::Published,StateAction::Seed);const auto r=f.record();CHECK(r.publication);
  directory(f.root+"/transport/events/test-pc");write(f.root+"/transport/events/test-pc/000000000001.cqs",QByteArray::fromStdString(r.publication->wire)+"\n");
  refused([&]{f.action(StateAction::RetrySeed);});CHECK(f.record().publication);
  CHECK(QDir().rename(f.root+"/transport",f.root+"/offline"));refused([&]{f.action(StateAction::RetrySeed);});CHECK(f.record().publication&&f.record().local==First);
  CHECK(QDir().rename(f.root+"/offline",f.root+"/transport"));write(f.root+"/transport/events/test-pc/000000000001.cqs",QByteArray::fromStdString(r.publication->wire));
  saveStorage(f.c,Manual,f.k->local,f.k->sync);CHECK(f.action(StateAction::RetrySeed)==Result::Applied);
  CHECK(f.record().local==Manual&&f.record().head->snapshot==First&&!f.record().publication&&f.record().allocatedSequence==1);
  refused([&]{f.action(StateAction::Join);});refused([&]{f.action(StateAction::JoinPreserve);});
 });
 test("Seed refuses existing history and Join refuses a reused device identity",[&]{
  Fixture f(root());const auto wire=read(f.filename());refused([&]{f.action(StateAction::Seed);});CHECK(read(f.filename())==wire);
  f.c.profile.device="remote-pc";f.c=storageConfiguration(f.c.profile);CHECK(QFile::remove(f.filename()));initializeStorage(f.c,f.k->local,f.k->sync);
  refused([&]{f.action(StateAction::Join);});CHECK(f.record().local==Snapshot{}&&!f.record().head);
 });
 test("adoption retains source snapshot, preserved Join archives it, restore refuses newer edits",[&]{
  Fixture f(root());const auto packs=checkpointRecord("public-fixture","legacy-pc",Manual,1).head->event.items;
  CHECK(adoptPackedSnapshot(f.c,f.k,packs)==Result::Applied);CHECK(f.record().local==Manual&&f.record().preserved==Manual);
  CHECK(adoptPackedSnapshot(f.c,f.k,packs)==Result::UpToDate);const auto wire=read(f.filename());
  refused([&]{adoptPackedSnapshot(f.c,f.k,{"!!!"});});CHECK(read(f.filename())==wire);refused([&]{f.action(StateAction::Join);});
  CHECK(f.action(StateAction::JoinPreserve)==Result::Applied);CHECK(f.record().local==First&&f.record().preserved==Manual&&f.record().head);
  saveStorage(f.c,Second,f.k->local,f.k->sync);refused([&]{f.action(StateAction::RestorePreserved);});CHECK(f.record().local==Second&&f.record().preserved==Manual);
  saveStorage(f.c,First,f.k->local,f.k->sync);CHECK(f.action(StateAction::RestorePreserved)==Result::Restored);CHECK(f.record().local==Manual&&f.record().head->snapshot==First);
  CHECK(f.action(StateAction::RestorePreserved)==Result::UpToDate);
 });
 test("preserved Join interruption retains nonempty original and supports explicit restoration",[&]{
  Fixture f(root());saveStorage(f.c,Manual,f.k->local,f.k->sync);crash(f.root,2,cqs::state::testing::Point::Published,StateAction::JoinPreserve);
  CHECK(f.record().pending&&f.record().preserved==Manual&&f.record().local==First);
  CHECK(f.action(StateAction::RestoreOriginal)==Result::Restored);CHECK(f.record().local==Manual&&f.record().preserved==Manual&&!f.record().head);
  CHECK(f.action(StateAction::JoinPreserve)==Result::Applied);CHECK(f.record().local==First&&f.record().preserved==Manual);
 });
 test("local-key rotation keeps reserved Seed and archives; retirement refuses pending publication",[&]{
  Fixture f(root(),true,false);const Bytes password(24,'p');auto k=createVault(f.c,password,f.k->sync);
  CHECK(QFile::remove(f.filename()));initializeStorage(f.c,k->local,k->sync);
  adoptPackedSnapshot(f.c,k,checkpointRecord("public-fixture","legacy-pc",First,1).head->event.items);
  cqs::storage::testing::hook=[](auto p){if(p==cqs::storage::testing::Point::PublishReady)throw cqs::crypto::Error("Public fixture interruption");};
  refused([&]{runStateAction(f.c,k,StateAction::Seed);});cqs::storage::testing::hook={};
  const auto before=readStorage(f.c,k->local,k->sync);CHECK(before.publication&&before.preserved==First);
  refused([&]{setVaultRetirement(f.c,password,true);});
  auto rotated=rotateStorageKey(f.c,password);const auto after=readStorage(f.c,rotated->local,rotated->sync);
  CHECK(after.publication->wire==before.publication->wire&&after.allocatedSequence==1&&after.preserved==First&&after.local==First);
  CHECK(runStateAction(f.c,rotated,StateAction::RetrySeed)==Result::Applied);
 });
 test("local generations are independent of accepted authenticated revisions",[&]{Fixture f(root());CHECK(f.action(StateAction::Join)==Result::Applied);
  CHECK(syncKeyIdentity(f.k->sync)=="4312dec9a216ecf94478adf20482f373fb34d2df376860efb545b2402cbad1f4");
  auto r=f.record();CHECK(r.schema==6&&r.local==First&&!r.pending&&r.head->event.revision.sequence==1&&r.generation==3);
  saveStorage(f.c,Manual,f.k->local,f.k->sync);r=f.record();CHECK(r.local==Manual&&r.head->snapshot==First&&r.head->event.revision.sequence==1);
  const auto wire=read(f.filename());f.remote(2,Second);refused([&]{f.action(StateAction::FastForward);});CHECK(read(f.filename())==wire);
 });
 test("fast-forward preserves exact binary, empty item and empty MIME distinctions",[&]{Fixture f(root());f.action(StateAction::Join);f.remote(2,Second);
  CHECK(f.action(StateAction::FastForward)==Result::Applied);auto r=f.record();CHECK(r.local==Second&&r.head->snapshot==Second&&r.head->event.revision.sequence==2);
  const auto wire=read(f.filename());CHECK(f.action(StateAction::FastForward)==Result::UpToDate);CHECK(read(f.filename())==wire);
 });
 test("all 15 join process-interruption boundaries retain a complete recoverable record",[&]{
  for(int commit=1;commit<=3;++commit)for(auto point:{cqs::state::testing::Point::StageSynced,cqs::state::testing::Point::StageLinked,cqs::state::testing::Point::BeforePublish,cqs::state::testing::Point::Published,cqs::state::testing::Point::DirectorySynced}){
   Fixture f(root());crash(f.root,commit,point);const auto r=f.record();CHECK(r.local==Snapshot{}||r.local==First);
   if(r.pending)CHECK(f.action(StateAction::RetryImport)==Result::Applied);else if(!r.head)f.action(StateAction::Join);
   CHECK(f.record().local==First&&f.record().head&&!f.record().pending);
  }
 });
 test("restore intent survives termination and works with transport unavailable",[&]{Fixture f(root());crash(f.root,2,cqs::state::testing::Point::Published);
  CHECK(f.record().pending&&f.record().local==First);
  crash(f.root,1,cqs::state::testing::Point::Published,StateAction::RestoreOriginal);CHECK(f.record().pending->phase==Phase::Restore);
  CHECK(QDir().rename(f.root+"/transport",f.root+"/offline"));refused([&]{f.action(StateAction::AcceptTarget);});
  CHECK(f.action(StateAction::RestoreOriginal)==Result::Restored);CHECK(f.record().local==Snapshot{}&&!f.record().head&&!f.record().pending);
 });
 test("ordinary local saves retain recovery intent and reject discarding divergent data",[&]{Fixture f(root());crash(f.root,1,cqs::state::testing::Point::Published);
  saveStorage(f.c,Manual,f.k->local,f.k->sync);const auto r=f.record();const auto wire=read(f.filename());CHECK(r.pending&&r.pending->original.empty()&&r.local==Manual);
  for(auto a:{StateAction::AcceptTarget,StateAction::RetryImport,StateAction::RestoreOriginal})refused([&]{f.action(a);});CHECK(read(f.filename())==wire);
 });
 test("explicit legacy migration preserves data without inventing a remote head",[&]{Fixture f(root());CHECK(QFile::remove(f.filename()));
  {cqs::state::FileStore file(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),f.k->local);auto lease=file.lock();file.initialize(checkpointRecord(f.c.binding.toStdString(),"cqs-storage",Manual,41));}
  refused([&]{f.record();});migrateStorageState(f.c,f.k->local,f.k->sync);const auto r=f.record();CHECK(r.schema==2&&r.local==Manual&&!r.head&&!r.pending&&r.generation==42);
  const auto wire=read(f.filename());migrateStorageState(f.c,f.k->local,f.k->sync);CHECK(read(f.filename())==wire);refused([&]{f.action(StateAction::Join);});
 });
 test("wrong key identity, changed profile, missing and corrupt state never reset data",[&]{Fixture f(root());const auto wire=read(f.filename());
  refused([&]{readStorage(f.c,f.k->local,Bytes(32,0x22));});auto wrong=f.c;wrong.profile.device="other-pc";wrong=storageConfiguration(wrong.profile);
  refused([&]{readStorage(wrong,f.k->local,f.k->sync);});CHECK(read(f.filename())==wire);
  auto corrupt=wire;corrupt[corrupt.size()-1]^=1;write(f.filename(),corrupt);refused([&]{f.action(StateAction::Join);});CHECK(read(f.filename())==corrupt);
  CHECK(QFile::remove(f.filename()));refused([&]{f.action(StateAction::Join);});CHECK(!QFile::exists(f.filename()));
 });
 test("all five migration termination boundaries preserve data and no accepted remote head",[&]{
  for(auto point:{cqs::state::testing::Point::StageSynced,cqs::state::testing::Point::StageLinked,cqs::state::testing::Point::BeforePublish,cqs::state::testing::Point::Published,cqs::state::testing::Point::DirectorySynced}){
   Fixture f(root());CHECK(QFile::remove(f.filename()));
   {cqs::state::FileStore file(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),f.k->local);auto lease=file.lock();file.initialize(checkpointRecord(f.c.binding.toStdString(),"cqs-storage",Manual,41));}
   QProcess child;child.start(QCoreApplication::applicationFilePath(),{"--migrate-crash",f.root,QString::number(int(point))});CHECK(child.waitForFinished(30000));CHECK(child.exitCode()==86);
   migrateStorageState(f.c,f.k->local,f.k->sync);const auto r=f.record();CHECK(r.local==Manual&&r.generation==42&&!r.head&&!r.pending);
  }
 });
 test("local key rotation preserves accepted head, local data and recovery journal together",[&]{Fixture f(root());const Bytes password(24,'p');
  auto k=createVault(f.c,password,f.k->sync);CHECK(QFile::remove(f.filename()));initializeStorage(f.c,k->local,k->sync);runStateAction(f.c,k,StateAction::Join);f.remote(2,Second);
  {cqs::state::FileStore file(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),k->local);auto lease=file.lock();const auto before=file.load();auto next=before;++next.generation;
   const auto target=checkpointRecord("public-fixture","remote-pc",Second,2,{"remote-pc/000000000001"}).head;next.pending=Pending{*target,First,Phase::Import};
   next.schema=std::max(5u,next.schema);next.archives={Manual,Second};file.commit(before,next);}
  const auto before=readStorage(f.c,k->local,k->sync);auto rotated=rotateStorageKey(f.c,password);const auto after=readStorage(f.c,rotated->local,rotated->sync);
  CHECK(after.local==before.local&&after.head->event.revision.id==before.head->event.revision.id&&after.pending->original==First&&after.keyIdentity==before.keyIdentity);
  CHECK(after.schema==6&&after.archives==before.archives);
  CHECK(runStateAction(f.c,rotated,StateAction::RetryImport)==Result::Applied);CHECK(readStorage(f.c,rotated->local,rotated->sync).local==Second);
 });
 test("cross-process lease refuses another writer while preserving the whole record",[&]{Fixture f(root());
  cqs::state::FileStore held(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),f.k->local);auto lease=held.lock();CHECK(lease);
  refused([&]{f.action(StateAction::Join);});refused([&]{saveStorage(f.c,Manual,f.k->local,f.k->sync);});CHECK(held.load().local==Snapshot{});
  QProcess child;child.start(QCoreApplication::applicationFilePath(),{"--busy",f.root});CHECK(child.waitForFinished(30000));CHECK(child.exitCode()==0);
 });
 test("profile session lease excludes state operations and cannot authorize record writes",[&]{Fixture f(root());
  cqs::state::FileStore owner(path(f.c.profile.stateDirectory),f.c.binding.toStdString(),f.k->local,{},cqs::state::Protection::Key,cqs::state::LeaseKind::Session);
  auto held=owner.lock();CHECK(held);refused([&]{owner.load();});refused([&]{f.action(StateAction::Join);});refused([&]{saveStorage(f.c,Manual,f.k->local,f.k->sync);});
  QProcess child;child.start(QCoreApplication::applicationFilePath(),{"--busy",f.root});CHECK(child.waitForFinished(30000));CHECK(child.exitCode()==0);
  held.reset();CHECK(f.action(StateAction::Join)==Result::Applied);
 });
 test("background GUI import preserves journal across edits, editor, cancellation and tab destruction",[&]{
  for(const auto mode:{"success","edit","editor","cancel","delete"}){
   Fixture f(root());f.action(StateAction::Join);f.remote(2,Second);
   cqs::storage::Directory directory(path(f.c.profile.transport));const auto history=directory.scan(f.k->sync);
   QObject context;auto model=std::make_unique<GuiFixtureModel>();bool editor=false;
   ModelAccess setup;setup.readable=setup.writable=[]{return true;};setup.persistAndReadback=[](const View &v,Limits){return v.snapshot;};
   {ModelClipboard initial(model.get(),setup);initial.replace(initial.capture({}),First);}
   auto control=std::make_shared<OperationControl>();ModelAccess access=setup;access.writable=[&]{return !editor;};
   GuiClipboard clipboard(&context,control,model.get(),access);
   QObject::connect(model.get(),&QObject::destroyed,&context,[control]{control->cancel();});
   std::atomic<bool> paused=false,resume=false,done=false;bool refusedImport=false;int commits=0;
   cqs::state::testing::hook=[&](auto point){
    CHECK(QThread::currentThread()!=app.thread());
    if(point==cqs::state::testing::Point::StageSynced&&++commits==1){paused=true;while(!resume)std::this_thread::sleep_for(std::chrono::milliseconds(1));}
   };
   std::thread worker([&]{try{importWorkerHistory(f.c,f.k,history,&clipboard,false,Recovery::RetryImport,{},[control]{control->check();});}
    catch(...){refusedImport=true;}done=true;});
   QElapsedTimer timeout;timeout.start();while(!paused&&timeout.elapsed()<5000){QCoreApplication::processEvents();QThread::msleep(1);}CHECK(paused);
   if(QString(mode)=="edit")CHECK(model->setData(model->index(0,0),QVariantMap{{"text/plain",QByteArray("USER")}},contentType::data));
   if(QString(mode)=="editor")editor=true;
   if(QString(mode)=="cancel")control->cancel();
   if(QString(mode)=="delete")model.reset();
   resume=true;while(!done&&timeout.elapsed()<5000){QCoreApplication::processEvents();QThread::msleep(1);}CHECK(done);worker.join();cqs::state::testing::hook={};
   const auto record=f.record();
   if(QString(mode)=="success"){
    CHECK(!refusedImport&&!record.pending&&record.local==Second&&record.head->event.revision.sequence==2);
   }else{
    CHECK(refusedImport&&record.pending&&record.local==First&&record.head->event.revision.sequence==1);
    CHECK(record.pending->original==First&&record.pending->target.snapshot==Second);
    if(QString(mode)=="edit"){
     ModelClipboard actual(model.get(),setup);const auto newer=actual.capture({}).snapshot;CHECK(newer!=First&&newer!=Second);
     saveStorage(f.c,newer,f.k->local,f.k->sync);refused([&]{f.action(StateAction::RetryImport);});CHECK(f.record().local==newer);
    }else CHECK(f.action(StateAction::RetryImport)==Result::Applied);
   }
  }
 });
 std::cout<<"PASS "<<cases<<" unified state scenarios\n";
}
