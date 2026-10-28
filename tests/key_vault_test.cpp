// SPDX-License-Identifier: GPL-3.0-or-later
#include "key_vault.h"
#include "standalone_storage.h"
#include "key_vault_hooks.h"
#include "state_store.h"
#include "test_check.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QDir>
#include <QProcess>
#include <iostream>
#include <functional>
#include <algorithm>
#include <cstdlib>
#ifdef Q_OS_WIN
#include "windows_test_acl.h"
#else
#include <sys/stat.h>
#endif
namespace cqs::native::vault_testing { std::function<void(Point)> hook; }
using namespace cqs::native;
using cqs::crypto::Bytes;
using cqs::transaction::Snapshot;
namespace {
int passed=0;
const Bytes Password{'p','u','b','l','i','c','-','f','i','x','t','u','r','e','-','p','a','s','s','w','o','r','d'};
const Bytes NewPassword{'n','e','w','-','p','u','b','l','i','c','-','f','i','x','t','u','r','e','-','p','a','s','s'};
const Snapshot Wanted{{{"application/octet-stream",{0,255,13,10}},{"text/plain",{'K','E','E','P'}}},{}};
std::filesystem::path path(const QString &s) {
#ifdef Q_OS_WIN
return std::filesystem::path(s.toStdWString());
#else
return std::filesystem::u8path(s.toUtf8().toStdString());
#endif
}
void directory(const QString &s){
#ifdef Q_OS_WIN
cqs::testing::directory(path(s));
#else
CHECK(QDir().mkdir(s));CHECK(::chmod(QFile::encodeName(s).constData(),0700)==0);
#endif
}
void write(const QString &s,const Bytes &bytes){
#ifdef Q_OS_WIN
cqs::testing::write(path(s),std::string(bytes.begin(),bytes.end()));
#else
QFile f(s);CHECK(f.open(QIODevice::WriteOnly));CHECK(f.write(reinterpret_cast<const char *>(bytes.data()),bytes.size())==qsizetype(bytes.size()));f.close();CHECK(::chmod(QFile::encodeName(s).constData(),0600)==0);
#endif
}
Bytes read(const QString &s){QFile f(s);CHECK(f.open(QIODevice::ReadOnly));const auto b=f.readAll();return {b.begin(),b.end()};}
void refused(const std::function<void()> &f){bool no=false;try{f();}catch(const std::exception &){no=true;}CHECK(no);}
void test(const char *s,const std::function<void()> &f){vault_testing::hook={};std::cout<<"RUN "<<s<<std::endl;f();vault_testing::hook={};std::cout<<"PASS "<<++passed<<" "<<s<<std::endl;}
Profile profile(const QString &root){Profile p{"vault-pc",root+"/transport",{},root+"/data"};p.standaloneStorage=true;p.vaultDirectory=root+"/vault";return p;}
struct Fixture {
QString root;StorageConfiguration c;StorageKeysPtr k;
Fixture(QString r,bool create=true):root(std::move(r)),c(storageConfiguration(profile(root))){
if(create){directory(root);for(const auto *name:{"transport","data","vault"})directory(root+'/'+name);directory(root+"/transport/events");
k=createVault(c,Password);initializeStorage(c,k->local,k->sync);saveStorage(c,Wanted,k->local,k->sync);}else k=unlockVault(c,Password);
}
QString vault()const{return root+"/vault/record-v1.cqr";}
QString data()const{return root+"/data/record-v1.cqr";}
};
}
int main(int argc,char **argv){QCoreApplication app(argc,argv);
if(argc==4&&QString::fromLocal8Bit(argv[1])=="--rotate-crash"){
const auto c=storageConfiguration(profile(QString::fromLocal8Bit(argv[2])));const auto point=vault_testing::Point(QString::fromLocal8Bit(argv[3]).toInt());
vault_testing::hook=[point](auto p){if(p==point)std::_Exit(86);};rotateStorageKey(c,Password);return 99;}
QTemporaryDir temporary;CHECK(temporary.isValid());int count=0;auto root=[&]{return temporary.path()+"/case-"+QString::number(++count);};
test("independent local/shared keys are encrypted and password authenticated",[&]{Fixture f(root());CHECK(f.k->local.size()==32&&f.k->sync.size()==32&&f.k->local!=f.k->sync);
const auto wire=read(f.vault());CHECK(std::search(wire.begin(),wire.end(),f.k->local.begin(),f.k->local.end())==wire.end());
refused([&]{unlockVault(f.c,NewPassword);});CHECK(read(f.vault())==wire);
CHECK(readStorage(f.c,unlockVault(f.c,Password)->local,f.k->sync).local==Wanted);
refused([&]{readStorage(f.c,f.k->sync,f.k->sync);});});
test("password change rewraps keys without changing local data or shared identity",[&]{Fixture f(root());const auto data=read(f.data());changeVaultPassword(f.c,Password,NewPassword);
refused([&]{unlockVault(f.c,Password);});auto k=unlockVault(f.c,NewPassword);CHECK(k->local==f.k->local&&k->sync==f.k->sync);CHECK(read(f.data())==data);});
test("local key rotation preserves bytes and shared key while invalidating old local key",[&]{Fixture f(root());auto k=rotateStorageKey(f.c,Password);CHECK(k->local!=f.k->local&&k->sync==f.k->sync&&k->pending.empty());
refused([&]{readStorage(f.c,f.k->local,f.k->sync);});CHECK(readStorage(f.c,k->local,k->sync).local==Wanted);});
test("process interruption of prepared or completed data rekey remains recoverable",[&]{
for(auto point:{vault_testing::Point::RotationPrepared,vault_testing::Point::DataRekeyed}){Fixture f(root());QProcess child;
child.start(QCoreApplication::applicationFilePath(),{"--rotate-crash",f.root,QString::number(int(point))});CHECK(child.waitForFinished(30000));CHECK(child.exitCode()==86);
auto k=unlockVault(f.c,Password);CHECK(k->pending.size()==32);const auto actual=point==vault_testing::Point::DataRekeyed?k->pending:k->local;
CHECK(readStorage(f.c,actual,k->sync).local==Wanted);k=rotateStorageKey(f.c,Password);CHECK(k->pending.empty());CHECK(readStorage(f.c,k->local,k->sync).local==Wanted);}});
test("encrypted sharing exports only shared key and creates a different device local key",[&]{Fixture first(root());const auto transfer=first.root+"/transfer";directory(transfer);
exportSyncKey(first.c,Password,NewPassword,path(transfer));
const auto secondRoot=root();directory(secondRoot);for(const auto *n:{"transport","vault","data"})directory(secondRoot+'/'+n);directory(secondRoot+"/transport/events");
auto p=profile(secondRoot);p.device="second-pc";const auto c=storageConfiguration(p);auto second=importSyncVault(c,Password,NewPassword,path(transfer));
CHECK(second->sync==first.k->sync&&second->local!=first.k->local&&second->initializing);
second=finishStorageSetup(c,Password);CHECK(!second->initializing);
cqs::state::FileStore share(path(transfer),"CqsSyncKeyTransferV1",NewPassword,{},cqs::state::Protection::Password);const auto l=share.lock();const auto r=share.load();
CHECK(r.head->snapshot.size()==1&&r.head->snapshot[0].size()==1);CHECK(r.head->snapshot[0].begin()->second==first.k->sync);});
test("encrypted key backup restores only a missing vault without resetting an existing one",[&]{Fixture f(root());const auto backup=f.root+"/backup";directory(backup);backupVault(f.c,Password,path(backup));
CHECK(QFile::remove(f.vault()));restoreMissingVault(f.c,Password,path(backup));const auto wire=read(f.vault());refused([&]{restoreMissingVault(f.c,Password,path(backup));});CHECK(read(f.vault())==wire);
CHECK(readStorage(f.c,unlockVault(f.c,Password)->local,f.k->sync).local==Wanted);});
test("corrupt or missing vault is never silently reprovisioned",[&]{Fixture f(root());auto bad=read(f.vault());bad.back()^=1;write(f.vault(),bad);refused([&]{unlockVault(f.c,Password);});
refused([&]{createVault(f.c,Password);});CHECK(read(f.vault())==bad);CHECK(QFile::remove(f.vault()));refused([&]{unlockVault(f.c,Password);});CHECK(!QFile::exists(f.vault()));});
test("a backup predating local key rotation cannot replace a missing vault",[&]{Fixture f(root());const auto backup=f.root+"/backup";directory(backup);backupVault(f.c,Password,path(backup));
auto current=rotateStorageKey(f.c,Password);CHECK(QFile::remove(f.vault()));refused([&]{restoreMissingVault(f.c,Password,path(backup));});CHECK(!QFile::exists(f.vault()));
repairMissingVault(f.c,current,Password);CHECK(readStorage(f.c,unlockVault(f.c,Password)->local,f.k->sync).local==Wanted);});
test("retirement intent is authenticated and refuses rotation until cancelled",[&]{Fixture f(root());auto k=setVaultRetirement(f.c,Password,true);CHECK(k->retiring);refused([&]{rotateStorageKey(f.c,Password);});
CHECK(unlockVault(f.c,Password)->retiring);k=setVaultRetirement(f.c,Password,false);CHECK(!k->retiring&&k->local==f.k->local);});
test("legacy K-SYNC-encrypted checkpoint migrates atomically to an independent local key",[&]{const auto r=root();directory(r);for(const auto *n:{"transport","data","vault"})directory(r+'/'+n);directory(r+"/transport/events");
auto p=profile(r);p.keyFile=r+"/legacy.key";const Bytes oldKey(32,0x42);write(p.keyFile,oldKey);auto oldProfile=p;oldProfile.schema=2;oldProfile.vaultDirectory.clear();const auto old=storageConfiguration(oldProfile);
{cqs::state::FileStore store(path(p.stateDirectory),old.binding.toStdString(),oldKey);const auto l=store.lock();store.initialize(checkpointRecord(old.binding.toStdString(),"cqs-storage",Wanted,1));}
const auto c=storageConfiguration(p);auto k=migrateLegacyStorage(c,Password);CHECK(k->local!=oldKey&&k->sync==oldKey);CHECK(readStorage(c,k->local,k->sync).local==Wanted);
CHECK(migrateLegacyStorage(c,Password)->local==k->local);});
test("lost vault can be repaired only from authenticated unlocked keys and never overwrite corruption",[&]{Fixture f(root());
const auto original=read(f.vault());refused([&]{repairMissingVault(f.c,f.k,NewPassword);});CHECK(read(f.vault())==original);
CHECK(QFile::remove(f.vault()));repairMissingVault(f.c,f.k,NewPassword);auto k=unlockVault(f.c,NewPassword);
CHECK(k->local==f.k->local&&k->sync==f.k->sync);CHECK(readStorage(f.c,k->local,k->sync).local==Wanted);});
test("short passwords and reused backup or transfer destinations are refused",[&]{Fixture f(root());refused([&]{changeVaultPassword(f.c,Password,Bytes(5,'x'));});
const auto destination=f.root+"/existing";directory(destination);exportSyncKey(f.c,Password,NewPassword,path(destination));const auto bytes=read(destination+"/record-v1.cqr");
refused([&]{exportSyncKey(f.c,Password,NewPassword,path(destination));});CHECK(read(destination+"/record-v1.cqr")==bytes);});
test("key transfers and backups cannot overlap transport, data or the vault",[&]{Fixture f(root());const auto dest=f.root+"/transport/events/key-export";directory(dest);
refused([&]{exportSyncKey(f.c,Password,NewPassword,path(dest));});refused([&]{backupVault(f.c,Password,path(dest));});
CHECK(!QFile::exists(dest+"/record-v1.cqr"));});
test("authenticated setup intent resumes only initial setup and never replaces lost established data",[&]{
const auto r=root();directory(r);for(const auto *n:{"transport","data","vault"})directory(r+'/'+n);directory(r+"/transport/events");
const auto c=storageConfiguration(profile(r));auto k=createVault(c,Password,{},true);CHECK(k->initializing);
k=finishStorageSetup(c,Password);CHECK(!k->initializing);CHECK(readStorage(c,k->local,k->sync).generation==0);
refused([&]{finishStorageSetup(c,Password);});CHECK(QFile::remove(r+"/data/record-v1.cqr"));
refused([&]{finishStorageSetup(c,Password);});CHECK(!QFile::exists(r+"/data/record-v1.cqr"));});
std::cout<<"PASS "<<passed<<" password key-vault scenarios\n";
}
