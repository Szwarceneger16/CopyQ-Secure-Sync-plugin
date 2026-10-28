// SPDX-License-Identifier: GPL-3.0-or-later
#include "history_transition.h"
#include "history_transition_hooks.h"
#include "unified_state.h"
#include "state_store.h"
#include "storage.h"
#include "test_check.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QDir>
#include <QProcess>
#include <QSettings>
#include <QJsonObject>
#include <QJsonDocument>
#include <numeric>
#include <iostream>
#ifdef Q_OS_WIN
#include "windows_test_acl.h"
#else
#include <sys/stat.h>
#endif
namespace cqs::native::transition_testing { std::function<void(Point)> hook; }
using namespace cqs;
using namespace cqs::native;
using namespace cqs::transaction;
namespace {
const crypto::Bytes Password(16,'s');
const Snapshot First{{{"text/plain",{'A',0,255}},{"application/octet-stream",{0,255,1}}},{},{{"text/html",{}}}};
const Snapshot Second{{{"text/plain",{'B'}}},{}};
std::filesystem::path path(const QString &s){
#ifdef Q_OS_WIN
 return std::filesystem::path(s.toStdWString());
#else
 return std::filesystem::u8path(s.toUtf8().toStdString());
#endif
}
void mkdir(const QString &s){
#ifdef Q_OS_WIN
 testing::directory(path(s));
#else
 CHECK(QDir().mkdir(s));CHECK(::chmod(QFile::encodeName(s).constData(),0700)==0);
#endif
}
Profile profile(const QString &root,const QString &name){
 const auto base=root+'/'+name;Profile p{"test-pc",base+"-transport",{},base+"-data"};p.standaloneStorage=true;p.vaultDirectory=base+"-vault";return p;
}
void directories(const Profile &p){for(const auto &s:{p.transport,p.stateDirectory,p.vaultDirectory})mkdir(s);mkdir(p.transport+"/events");}
StorageKeysPtr setup(const Profile &p){
 const auto c=storageConfiguration(p);auto k=createVault(c,Password);initializeStorage(c,k->local,k->sync);saveStorage(c,First,k->local,k->sync);seedHistory(c,k,false);
 saveStorage(c,Second,k->local,k->sync);publishChanges(c,k,false);return k;
}
template<class F> void refused(F &&f){bool caught=false;try{f();}catch(const std::exception &){caught=true;}CHECK(caught);}
Record read(const Profile &p){const auto c=storageConfiguration(p);const auto k=unlockVault(c,Password);return readStorage(c,k->local,k->sync);}
void confirm(const Profile &source,const HistoryTransitionResult &result,HistoryTransitionMode mode){
 const auto a=storageConfiguration(source),b=storageConfiguration(result.profile);const auto oldKeys=unlockVault(a,Password);
 CHECK(oldKeys->suspended);CHECK(oldKeys->sync!=result.keys->sync);CHECK(oldKeys->local!=result.keys->local);
 const auto old=readStorage(archivedTransitionSource(a,result.profile),oldKeys->local,oldKeys->sync),next=readStorage(b,result.keys->local,result.keys->sync);
 CHECK(next.local==old.local);CHECK(next.generation==old.generation);CHECK(next.binding!=old.binding);CHECK(next.archives==old.archives);CHECK(next.preserved==old.preserved);
 storage::Directory ad(path(source.transport)),bd(path(result.profile.transport));const auto ah=ad.scan(oldKeys->sync),bh=bd.scan(result.keys->sync);
 if(mode==HistoryTransitionMode::Rekey){CHECK(ah.fingerprints()==bh.fingerprints());CHECK(next.witnessed==ah.fingerprints());CHECK(next.head->event.revision.id==old.head->event.revision.id);}
 else {CHECK(bh.graph().size()==1);CHECK(next.head->snapshot==*old.local);CHECK(next.allocatedSequence==1);}
 refused([&]{bd.scan(oldKeys->sync);});refused([&]{ad.scan(result.keys->sync);});
 refused([&]{publishChanges(a,oldKeys,false);});
 auto cached=std::make_shared<StorageKeys>();cached->local=oldKeys->local;cached->sync=oldKeys->sync;
 refused([&]{readStorage(a,cached->local,cached->sync);});refused([&]{saveStorage(a,First,cached->local,cached->sync);});
 refused([&]{publishChanges(a,cached,false);});refused([&]{rotateStorageKey(a,Password);});
 refused([&]{changeVaultPassword(a,Password,crypto::Bytes(16,'n'));});
}
void lifecycle(){

 QTemporaryDir root;CHECK(root.isValid());auto source=profile(root.path(),"old");const auto target=profile(root.path(),"new");
 mkdir(root.path()+"/key-import");source.keyFile=root.path()+"/key-import/original-import.key";
#ifdef Q_OS_WIN
 testing::write(path(source.keyFile),std::string(32,'k'));
#else
 {QFile key(source.keyFile);CHECK(key.open(QIODevice::WriteOnly));CHECK(key.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner));CHECK(key.write(QByteArray(32,'k'))==32);}
#endif
 directories(source);directories(target);const auto keys=setup(source);CHECK(QFile::remove(source.keyFile));
 const auto journal=root.path()+"/journal";mkdir(journal);
 const auto result=startHistoryTransition(storageConfiguration(source),target,Password,path(journal),HistoryTransitionMode::Rekey);confirm(source,result,HistoryTransitionMode::Rekey);
 CHECK(decodeProfile(encodeProfile(result.profile))==result.profile);CHECK(storageConfiguration(decodeProfile(encodeProfile(result.profile))).binding==storageConfiguration(result.profile).binding);CHECK(unlockVault(storageConfiguration(result.profile),Password)->sync==result.keys->sync);const auto retry=resumeHistoryTransition(storageConfiguration(source),Password,path(journal));CHECK(retry.profile==result.profile);CHECK(retry.keys->sync==result.keys->sync);
 refused([&]{startHistoryTransition(storageConfiguration(source),target,Password,path(journal),HistoryTransitionMode::Rekey);});
 refused([&]{cancelHistoryTransition(storageConfiguration(source),Password,path(journal));});
 QSettings settings(root.path()+"/profile.ini",QSettings::IniFormat);saveProfile(settings,source);activateProfile(settings,result.profile);CHECK(loadProfile(settings)==result.profile);
 settings.setValue("transport",source.transport);settings.sync();CHECK(loadProfile(settings)==result.profile);
 saveProfile(settings,result.profile);CHECK(loadProfile(settings)==result.profile);
 finishHistoryTransition(storageConfiguration(result.profile),Password,Password,path(journal));finishHistoryTransition(storageConfiguration(result.profile),Password,Password,path(journal));
 {state::FileStore receipt(path(journal),"CqsHistoryTransitionV1-"+storageConfiguration(source).binding.right(64).toStdString(),Password,{},state::Protection::Password);
  const auto l=receipt.lock();CHECK(l);const auto r=receipt.load();CHECK(r.local->size()==1&&r.local->at(0).size()==1);}
 refused([&]{resumeHistoryTransition(storageConfiguration(source),Password,path(journal));});
 refused([&]{cancelHistoryTransition(storageConfiguration(source),Password,path(journal),true);});
 // A second device explicitly imports the separately delivered new key. Its
 // unsent edits survive in an encrypted archive rather than being published.
 auto peer=profile(root.path(),"peer");peer.device="peer-pc";directories(peer);const auto peerKeys=setup(peer);const auto peerConfig=storageConfiguration(peer);
 saveStorage(peerConfig,First,peerKeys->local,peerKeys->sync);
 // Four protected slots plus a reserved old-key publication must not trap an
 // offline peer. Explicit cleanup may free an unrelated backup without sending.
 {state::FileStore f(path(peer.stateDirectory),peerConfig.binding.toStdString(),peerKeys->local);const auto l=f.lock();CHECK(l);
  const auto before=f.load();auto next=before;next.archives={Second,Second,Second,Second};++next.generation;f.commit(before,next);}
 auto pending=read(peer);
 {storage::Directory old(path(peer.transport));const auto publication=preparePublication(peerConfig,peerKeys,pending,old.scan(peerKeys->sync));CHECK(publication);
  pending=reservePublication(peerConfig,peerKeys,pending,*publication,nullptr);}
 discardArchive(peerConfig,peerKeys,pending,0,nullptr);pending=read(peer);CHECK(pending.publication);CHECK(pending.archives.size()==3);
 CHECK(QDir().rename(peer.transport,peer.transport+"-offline"));
 auto peerTarget=profile(root.path(),"peer-next");peerTarget.device=peer.device;mkdir(peerTarget.stateDirectory);mkdir(peerTarget.vaultDirectory);peerTarget.transport=result.profile.transport;
 const auto peerJournal=root.path()+"/peer-journal";mkdir(peerJournal);
 const auto transfer=root.path()+"/transfer";mkdir(transfer);const crypto::Bytes transferPassword(16,'t');
 exportSyncKey(storageConfiguration(result.profile),Password,transferPassword,path(transfer));
 auto deliveredKey=readTransferredSyncKey(peerConfig,transferPassword,path(transfer));CHECK(deliveredKey==result.keys->sync);
 const auto joined=startHistoryTransition(peerConfig,peerTarget,Password,path(peerJournal),HistoryTransitionMode::Join,deliveredKey);crypto::wipe(deliveredKey);
 const auto joinedRecord=read(joined.profile);CHECK(joinedRecord.local==Second);CHECK(joinedRecord.archives.back()==First);CHECK(joinedRecord.archives.size()==4);CHECK(!joinedRecord.publication);
 const auto archivedPeer=readStorage(archivedTransitionSource(peerConfig,joined.profile),peerKeys->local,peerKeys->sync);
 CHECK(archivedPeer.publication->wire==pending.publication->wire);CHECK(archivedPeer.local==First);
 saveStorage(storageConfiguration(joined.profile),First,joined.keys->local,joined.keys->sync);publishChanges(storageConfiguration(joined.profile),joined.keys,false);
 runStateAction(storageConfiguration(result.profile),result.keys,StateAction::FastForward);CHECK(read(result.profile).local==First);
 // Compact the current local snapshot, including unsent edits, and keep all
 // source history/backups. It also rotates K-SYNC.
 auto compact=profile(root.path(),"compact");directories(compact);const auto compactJournal=root.path()+"/compact-journal";mkdir(compactJournal);
 saveStorage(storageConfiguration(result.profile),Second,result.keys->local,result.keys->sync);
 CHECK(QDir().rename(result.profile.transport,result.profile.transport+"-offline"));
 const auto rolled=startHistoryTransition(storageConfiguration(result.profile),compact,Password,path(compactJournal),HistoryTransitionMode::Compact);
 CHECK(QDir().rename(result.profile.transport+"-offline",result.profile.transport));
 confirm(result.profile,rolled,HistoryTransitionMode::Compact);CHECK(read(rolled.profile).local==Second);
 transition_testing::hook={};
 std::cout<<"PASS rekey preserves graph, explicit peer Join, bidirectional sync and compact rollover\n";
}
void interrupts(){
 for(int point=0;point<10;++point)for(const auto mode:{HistoryTransitionMode::Rekey,HistoryTransitionMode::Compact}){
  QTemporaryDir root;CHECK(root.isValid());const auto source=profile(root.path(),"old"),target=profile(root.path(),"new");directories(source);directories(target);setup(source);mkdir(root.path()+"/journal");
  std::cout<<"  interruption mode="<<int(mode)<<" phase="<<point<<std::endl;
  QProcess child;child.start(QCoreApplication::applicationFilePath(),{"--crash",root.path(),QString::number(point),QString::number(int(mode))});CHECK(child.waitForFinished(60000));
  if(child.exitCode()!=86)std::cerr<<child.readAllStandardError().toStdString()<<std::endl;
  CHECK(child.exitCode()==86);
  if(point==8){
   QSettings activated(root.path()+"/activated.ini",QSettings::IniFormat);const auto active=loadProfile(activated);
   HistoryTransitionResult result{active,unlockVault(storageConfiguration(active),Password)};confirm(source,result,mode);
   refused([&]{resumeHistoryTransition(storageConfiguration(source),Password,path(root.path()+"/journal"));});
   finishHistoryTransition(storageConfiguration(active),Password,Password,path(root.path()+"/journal"));
  }else{const auto result=resumeHistoryTransition(storageConfiguration(source),Password,path(root.path()+"/journal"));confirm(source,result,mode);}
 }
 std::cout<<"PASS 20 real process exits resume exact events/keys and preserve source\n";
}
void cancellation(){
 QTemporaryDir root;CHECK(root.isValid());const auto source=profile(root.path(),"old"),target=profile(root.path(),"new");directories(source);directories(target);setup(source);const auto journal=root.path()+"/journal";mkdir(journal);
 transition_testing::hook=[](auto p){if(p==transition_testing::Point::EventDelivered)throw std::runtime_error("interrupt");};
 refused([&]{startHistoryTransition(storageConfiguration(source),target,Password,path(journal),HistoryTransitionMode::Rekey);});transition_testing::hook={};
 CHECK(unlockVault(storageConfiguration(source),Password)->suspended);
 refused([&]{resumeHistoryTransition(storageConfiguration(source),crypto::Bytes(16,'x'),path(journal));});
 cancelHistoryTransition(storageConfiguration(source),Password,path(journal));
 const auto activeKeys=unlockVault(storageConfiguration(source),Password);saveStorage(storageConfiguration(source),First,activeKeys->local,activeKeys->sync);
 const auto generation=read(source).generation;cancelHistoryTransition(storageConfiguration(source),Password,path(journal));CHECK(read(source).generation==generation);
 saveStorage(storageConfiguration(source),Second,activeKeys->local,activeKeys->sync);
 CHECK(!unlockVault(storageConfiguration(source),Password)->suspended);refused([&]{resumeHistoryTransition(storageConfiguration(source),Password,path(journal));});
 CHECK(read(source).local==Second);
 std::cout<<"PASS wrong password and explicit idempotent cancellation retain source and incomplete destination\n";
}
void fullHistory(){
 QTemporaryDir root;CHECK(root.isValid());const auto source=profile(root.path(),"old"),target=profile(root.path(),"new");directories(source);directories(target);auto keys=setup(source);const auto c=storageConfiguration(source);
 storage::Directory transport(path(source.transport));auto before=read(source);auto latest=*before.head;
 for(std::uint64_t sequence=3;sequence<history::MaxEvents;++sequence){
  auto event=checkpointRecord("fixture",source.device.toStdString(),Second,sequence,{latest.event.revision.id}).head->event;
  const auto wire=encryptHistoryEvent(event,keys->sync);event=events::decode(keys->sync,{event.revision.id,wire});
#ifdef Q_OS_WIN
  transport.publish(keys->sync,{event.revision.id,wire},{},path(source.stateDirectory));
#else
  transport.publish(keys->sync,{event.revision.id,wire});
#endif
  latest={event,Second};
 }
 {state::FileStore file(path(source.stateDirectory),c.binding.toStdString(),keys->local);const auto l=file.lock();CHECK(l);
  auto next=before;next.head=latest;next.allocatedSequence=history::MaxEvents-1;next.schema=6;next.witnessed=transport.scan(keys->sync).fingerprints();++next.generation;file.commit(before,next);}
 saveStorage(c,First,keys->local,keys->sync);
 auto pending=read(source);const auto publication=preparePublication(c,keys,pending,transport.scan(keys->sync));CHECK(publication);
 pending=reservePublication(c,keys,pending,*publication,nullptr);
 // Another device consumes the final slot after this ID has been reserved.
 const auto raced=checkpointRecord("fixture","race-peer",Second,1,{latest.event.revision.id}).head->event;
 const auto racedWire=encryptHistoryEvent(raced,keys->sync);
#ifdef Q_OS_WIN
 transport.publish(keys->sync,{raced.revision.id,racedWire},{},path(source.stateDirectory));
#else
 transport.publish(keys->sync,{raced.revision.id,racedWire});
#endif
 refused([&]{publishChanges(c,keys,true);});CHECK(read(source).publication->wire==pending.publication->wire);
 CHECK(transport.scan(keys->sync).graph().size()==history::MaxEvents);
 const auto journal=root.path()+"/journal";mkdir(journal);
 const auto result=startHistoryTransition(c,target,Password,path(journal),HistoryTransitionMode::Compact);confirm(source,result,HistoryTransitionMode::Compact);
 const auto retained=readStorage(archivedTransitionSource(c,result.profile),keys->local,keys->sync);
 CHECK(retained.publication->wire==pending.publication->wire);CHECK(!read(result.profile).publication);
 CHECK(!transport.scan(keys->sync).graph().contains(pending.publication->target.event.revision.id));
 saveStorage(storageConfiguration(result.profile),Second,result.keys->local,result.keys->sync);CHECK(publishChanges(storageConfiguration(result.profile),result.keys,false)==Result::Applied);
 CHECK(storage::Directory(path(result.profile.transport)).scan(result.keys->sync).graph().size()==2);
 std::cout<<"PASS actual 1000-event ceiling rolls over with unsent data retained and publication resumes\n";
}
void lateSource(){
 QTemporaryDir root;CHECK(root.isValid());const auto source=profile(root.path(),"old"),target=profile(root.path(),"new");directories(source);directories(target);const auto keys=setup(source);const auto c=storageConfiguration(source);mkdir(root.path()+"/journal");
 const auto parent=read(source).head->event.revision.id;
 bool added=false;transition_testing::hook=[&](auto p){if(p!=transition_testing::Point::EventDelivered||added)return;added=true;
  const auto event=checkpointRecord("fixture",source.device.toStdString(),First,3,{parent}).head->event;
  const auto wire=encryptHistoryEvent(event,keys->sync);storage::Directory directory(path(source.transport));
#ifdef Q_OS_WIN
  directory.publish(keys->sync,{event.revision.id,wire},{},path(source.stateDirectory));
#else
  directory.publish(keys->sync,{event.revision.id,wire});
#endif
 };
 refused([&]{startHistoryTransition(c,target,Password,path(root.path()+"/journal"),HistoryTransitionMode::Rekey);});transition_testing::hook={};CHECK(added);
 CHECK(unlockVault(c,Password)->suspended);
 auto archivedTarget=target;archivedTarget.predecessorBinding=c.binding.right(64);archivedTarget.keyFile.clear();
 CHECK(readStorage(archivedTransitionSource(c,archivedTarget),keys->local,keys->sync).local==Second);
 refused([&]{resumeHistoryTransition(c,Password,path(root.path()+"/journal"));});
 cancelHistoryTransition(c,Password,path(root.path()+"/journal"));CHECK(!unlockVault(c,Password)->suspended);
 CHECK(storage::Directory(path(source.transport)).scan(keys->sync).graph().size()==3);
 std::cout<<"PASS late old-peer event prevents activation without losing either history\n";
}
void corruptSourceAndVaultRecovery(){
 QTemporaryDir root;CHECK(root.isValid());const auto source=profile(root.path(),"old"),target=profile(root.path(),"new");directories(source);directories(target);const auto keys=setup(source);const auto c=storageConfiguration(source);
 const auto backup=root.path()+"/backup";mkdir(backup);backupVault(c,Password,path(backup));
 const auto journal=root.path()+"/journal";mkdir(journal);
 // Locate the known fixture event through the protocol layout, never user paths.
 QString damaged;
 {QDir d(source.transport+"/events/"+source.device);const auto files=d.entryList({"*.cqs"},QDir::Files);CHECK(!files.isEmpty());damaged=d.filePath(files.front());}
 {QFile f(damaged);CHECK(f.open(QIODevice::WriteOnly|QIODevice::Truncate));CHECK(f.write("corrupt") == 7);}
 refused([&]{startHistoryTransition(c,target,Password,path(journal),HistoryTransitionMode::Rekey);});CHECK(!unlockVault(c,Password)->suspended);
 const auto result=startHistoryTransition(c,target,Password,path(journal),HistoryTransitionMode::Compact);
 CHECK(read(result.profile).local==Second);{QFile f(damaged);CHECK(f.open(QIODevice::ReadOnly));CHECK(f.readAll()=="corrupt");}
 CHECK(QFile::remove(source.vaultDirectory+"/record-v1.cqr"));
 const auto archived=historyTransitionSourceConfiguration(c,Password,path(journal));
 refused([&]{restoreMissingVault(c,Password,path(backup));});restoreMissingVault(c,Password,path(backup),archived.binding);
 CHECK(unlockVault(c,Password)->suspended);CHECK(resumeHistoryTransition(c,Password,path(journal)).profile==result.profile);
 CHECK(QFile::remove(source.vaultDirectory+"/record-v1.cqr"));
 refused([&]{repairMissingVault(c,keys,Password);});repairMissingVault(c,keys,Password,archived.binding);CHECK(unlockVault(c,Password)->suspended);
 cancelHistoryTransition(c,Password,path(journal),true);CHECK(read(source).local==Second);CHECK(!unlockVault(c,Password)->suspended);
 std::cout<<"PASS corrupt old transport does not block local rollover, restored/repaired source vault stays suspended and cancellation restores source namespace\n";
}

void legacyJournal(){
 QTemporaryDir root;CHECK(root.isValid());const auto source=profile(root.path(),"old"),target=profile(root.path(),"new");directories(source);directories(target);const auto keys=setup(source);const auto c=storageConfiguration(source);const auto journal=root.path()+"/journal";mkdir(journal);
 transition_testing::hook=[](auto p){if(p==transition_testing::Point::JournalCreated)throw std::runtime_error("interrupt");};
 refused([&]{startHistoryTransition(c,target,Password,path(journal),HistoryTransitionMode::Compact);});transition_testing::hook={};
 {state::FileStore file(path(journal),"CqsHistoryTransitionV1-"+c.binding.right(64).toStdString(),Password,{},state::Protection::Password);const auto l=file.lock();CHECK(l);
  const auto before=file.load();auto next=before;auto &field=next.local->at(0).at("application/x-cqs-transition-meta");
  auto meta=QJsonDocument::fromJson(QByteArray(reinterpret_cast<const char *>(field.data()),qsizetype(field.size()))).object();meta["v"]=1;
  crypto::Bytes fingerprints;const auto history=storage::Directory(path(source.transport)).scan(keys->sync);
  for(const auto &entry:history.fingerprints()){fingerprints.insert(fingerprints.end(),entry.first.begin(),entry.first.end());fingerprints.push_back(0);fingerprints.insert(fingerprints.end(),entry.second.begin(),entry.second.end());}
  const auto hash=crypto::sha256(fingerprints);meta["source_history"]=QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(hash.data()),qsizetype(hash.size())).toHex());
  const auto encoded=QJsonDocument(meta).toJson(QJsonDocument::Compact);field=crypto::Bytes(encoded.begin(),encoded.end());++next.generation;file.commit(before,next);}
 const auto result=resumeHistoryTransition(c,Password,path(journal));CHECK(read(source).local==Second);CHECK(read(result.profile).local==Second);
 cancelHistoryTransition(c,Password,path(journal),true);CHECK(!unlockVault(c,Password)->suspended);CHECK(read(source).local==Second);
 std::cout<<"PASS legacy version-1 preparation resumes and cancels without changing its original layout\n";
}

void refusalAndReadyCancel(){
 QTemporaryDir root;CHECK(root.isValid());const auto source=profile(root.path(),"old"),target=profile(root.path(),"new");directories(source);directories(target);setup(source);const auto c=storageConfiguration(source);mkdir(root.path()+"/journal");
 auto overlap=target;overlap.stateDirectory=source.stateDirectory;
 refused([&]{startHistoryTransition(c,overlap,Password,path(root.path()+"/journal"),HistoryTransitionMode::Rekey);});CHECK(!unlockVault(c,Password)->suspended);
 const auto result=startHistoryTransition(c,target,Password,path(root.path()+"/journal"),HistoryTransitionMode::Compact);
 refused([&]{cancelHistoryTransition(c,Password,path(root.path()+"/journal"));});
 // Ready can still be explicitly cancelled when the saved profile has not
 // activated it. The GUI verifies that condition before passing this capability.
 cancelHistoryTransition(c,Password,path(root.path()+"/journal"),true);CHECK(!unlockVault(c,Password)->suspended);
 refused([&]{resumeHistoryTransition(c,Password,path(root.path()+"/journal"));});CHECK(read(source).local==Second);
 std::cout<<"PASS overlapping destination refused and confirmed inactive Ready cancellation is recoverable\n";
}

}
int main(int argc,char **argv){QCoreApplication app(argc,argv);
 try{
 if(app.arguments().value(1)=="--crash"){
  const auto args=app.arguments();const int point=args[3].toInt();transition_testing::hook=[point](auto p){if(int(p)==point)std::_Exit(86);};
  const auto result=startHistoryTransition(storageConfiguration(profile(args[2],"old")),profile(args[2],"new"),Password,path(args[2]+"/journal"),HistoryTransitionMode(args[4].toInt()));
  if(point==8){QSettings activated(args[2]+"/activated.ini",QSettings::IniFormat);activateProfile(activated,result.profile);
   finishHistoryTransition(storageConfiguration(result.profile),Password,Password,path(args[2]+"/journal"));}return 1;
 }
 std::cout<<"RUN lifecycle and explicit peer migration"<<std::endl;lifecycle();
 std::cout<<"RUN interrupted transitions"<<std::endl;interrupts();cancellation();fullHistory();lateSource();corruptSourceAndVaultRecovery();legacyJournal();refusalAndReadyCancel();return 0;
 }catch(const std::exception &e){std::cerr<<"History transition test failed: "<<e.what()<<std::endl;return 1;}
}
