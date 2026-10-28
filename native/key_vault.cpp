// SPDX-License-Identifier: GPL-3.0-or-later
#include "key_vault.h"
#include "standalone_storage.h"
#include "state_store.h"
#include "packed_items.h"
#include "key_reader.h"
#include <future>
#include <algorithm>
#include <QDir>
#ifdef CQS_VAULT_TESTING
#include "../tests/key_vault_hooks.h"
#define VAULT_HOOK(p) do { if(vault_testing::hook)vault_testing::hook(vault_testing::Point::p); } while(false)
#else
#define VAULT_HOOK(p) do {} while(false)
#endif
namespace cqs::native {
namespace {
using namespace transaction;
using crypto::Bytes;
constexpr auto Local = "application/x-copyq-secure-sync-local-key";
constexpr auto Sync = "application/x-copyq-secure-sync-shared-key";
constexpr auto Pending = "application/x-copyq-secure-sync-pending-key";
constexpr auto Phase = "application/x-copyq-secure-sync-key-phase";
constexpr auto TransferBinding = "CqsSyncKeyTransferV1";
struct Secret { Bytes bytes; ~Secret(){crypto::wipe(bytes);} };
void wipe(Record &r) {
    const auto snapshot=[](Snapshot &s){for(auto &item:s)for(auto &field:item)crypto::wipe(field.second);};
    const auto head=[&](Head &h){snapshot(h.snapshot);
        for(auto &item:h.event.items)std::fill(item.begin(),item.end(),'\0');};
    if(r.head)head(*r.head);if(r.pending){head(r.pending->target);snapshot(r.pending->original);}
    for(auto &archive:r.archives)snapshot(archive);
    if(r.local)snapshot(*r.local);if(r.preserved)snapshot(*r.preserved);if(r.publication)head(r.publication->target);
}
struct PrivateRecord { Record value; ~PrivateRecord(){wipe(value);} };
[[noreturn]] void refuse(){throw crypto::Error("Key vault operation refused; existing encrypted state retained");}
std::filesystem::path path(const QString &s) {
#ifdef Q_OS_WIN
    return std::filesystem::path(s.toStdWString());
#else
    return std::filesystem::u8path(s.toUtf8().toStdString());
#endif
}
Bytes text(const char *s){return {s,s+std::char_traits<char>::length(s)};}
std::string binding(const StorageConfiguration &c){return "CqsLocalKeyVaultV1-"+c.binding.right(64).toStdString();}
state::Limits limits(){state::Limits l;l.recordBytes=65536;l.snapshot.items=2;l.snapshot.formatsPerItem=8;l.snapshot.snapshotBytes=4096;return l;}
void profile(const StorageConfiguration &c){if(c.profile.schema!=3||c.profile.vaultDirectory.isEmpty()||!validateProfile(c.profile,false).isEmpty())refuse();}
void externalDirectory(const StorageConfiguration &c,const std::filesystem::path &directory){
#ifdef Q_OS_WIN
    auto selected=QString::fromStdWString(directory.native()).toCaseFolded();
#else
    auto selected=QString::fromUtf8(directory.native().c_str());
#endif
    selected=QDir::cleanPath(QDir::fromNativeSeparators(selected));
    if(!QDir::isAbsolutePath(selected))refuse();
    for(auto root:{c.profile.transport,c.profile.stateDirectory,c.profile.vaultDirectory}){
#ifdef Q_OS_WIN
        root=root.toCaseFolded();
#endif
        root=QDir::cleanPath(QDir::fromNativeSeparators(root));
        if(selected==root||selected.startsWith(root+'/')||root.startsWith(selected+'/'))refuse();
    }
}
void newPassword(const Bytes &p){if(p.size()<12||p.size()>1024)refuse();}
Record record(const std::string &b,const StorageKeys &k,std::uint64_t generation,const std::vector<std::string> &parents={}){
    Item item{{Local,k.local},{Sync,k.sync},{Phase,text(k.suspended?"suspended":k.initializing?"initializing":k.retiring?"retiring":k.pending.empty()?"active":"rotating")}};
    if(!k.pending.empty())item.emplace(Pending,k.pending);
    return checkpointRecord(b,"cqs-keyvault",{item},generation,parents);
}
StorageKeysPtr keys(const Record &r,const std::string &b){
    if(r.binding!=b||r.pending||!r.head||r.head->event.revision.device!="cqs-keyvault"||
       r.head->event.revision.sequence!=r.generation||!r.generation||
       packed::decode(r.head->event.items,limits().snapshot)!=r.head->snapshot||r.head->snapshot.size()!=1)refuse();
    const auto &item=r.head->snapshot[0];
    if(item.size()!=3&&item.size()!=4)refuse();
    if(!item.count(Local)||!item.count(Sync)||!item.count(Phase)||item.at(Local).size()!=32||item.at(Sync).size()!=32)refuse();
    auto k=std::make_shared<StorageKeys>();k->local=item.at(Local);k->sync=item.at(Sync);
    if(item.count(Pending)){k->pending=item.at(Pending);if(k->pending.size()!=32||k->pending==k->local)refuse();}
    k->retiring=item.at(Phase)==text("retiring");
    k->initializing=item.at(Phase)==text("initializing");
    k->suspended=item.at(Phase)==text("suspended");
    if(item.at(Phase)!=text(k->suspended?"suspended":k->initializing?"initializing":k->retiring?"retiring":k->pending.empty()?"active":"rotating")||
       ((k->retiring||k->initializing||k->suspended)&&!k->pending.empty())||item.size()!=std::size_t(k->pending.empty()?3:4))refuse();
    return k;
}
void verify(state::FileStore &store,const Record &wanted){
    PrivateRecord actual{store.load()};Secret a{state::serialize(actual.value,limits())},b{state::serialize(wanted,limits())};
    if(a.bytes!=b.bytes)refuse();
}
template<class F> auto worker(F f){return std::async(std::launch::async,std::move(f)).get();}
}
StorageKeysPtr createVault(const StorageConfiguration &c,const Bytes &password,const Bytes &importedSync,bool initializing){
    profile(c);newPassword(password);
    return worker([&]{
        auto k=std::make_shared<StorageKeys>();k->local=crypto::random(32);k->initializing=initializing;
        k->sync=!importedSync.empty()?importedSync:c.profile.keyFile.isEmpty()?crypto::random(32):readKeyStrict(path(c.profile.keyFile));
        if(k->sync.size()!=32||k->sync==k->local)refuse();
        state::FileStore vault(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
        const auto lease=vault.lock();if(!lease)refuse();
        PrivateRecord initial{record(binding(c),*k,1)};vault.initialize(initial.value);verify(vault,initial.value);VAULT_HOOK(VaultCreated);return k;
    });
}
StorageKeysPtr unlockVault(const StorageConfiguration &c,const Bytes &password){
    profile(c);return worker([&]{state::FileStore vault(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
        const auto lease=vault.lock();if(!lease)refuse();PrivateRecord r{vault.load()};return keys(r.value,binding(c));});
}
StorageKeysPtr finishStorageSetup(const StorageConfiguration &c,const Bytes &password,const transaction::Store::Lease *ownedSession){
    profile(c);return worker([&]{auto ownership=!ownedSession?acquireStorageSession(c):nullptr;
        state::FileStore vault(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
        const auto lease=vault.lock();if(!lease)refuse();PrivateRecord old{vault.load()};auto k=keys(old.value,binding(c));
        if(!k->initializing)refuse();
        try{readStorage(c,k->local,k->sync);}catch(const state::Error &e){if(e.code()!=state::ErrorCode::Missing)throw;initializeStorage(c,k->local,k->sync,ownedSession?ownedSession:ownership.get());}
        k->initializing=false;
        PrivateRecord next{record(binding(c),*k,old.value.generation+1,{old.value.head->event.revision.id})};
        vault.commit(old.value,next.value);verify(vault,next.value);return k;
    });
}
void changeVaultPassword(const StorageConfiguration &c,const Bytes &oldPassword,const Bytes &newPass){
    profile(c);newPassword(newPass);worker([&]{state::FileStore vault(path(c.profile.vaultDirectory),binding(c),oldPassword,limits(),state::Protection::Password);
        const auto lease=vault.lock();if(!lease)refuse();PrivateRecord old{vault.load()};auto k=keys(old.value,binding(c));
        // Preparation and its destination vault use the journal's original
        // password. Keep it stable until the source transition finishes/cancels.
        if(k->suspended)refuse();
        PrivateRecord next{record(binding(c),*k,old.value.generation+1,{old.value.head->event.revision.id})};
        vault.transition(old.value,next.value,newPass,state::Protection::Password);verify(vault,next.value);});
}
StorageKeysPtr setVaultRetirement(const StorageConfiguration &c,const Bytes &password,bool retiring,const transaction::Store::Lease *ownedSession){
    profile(c);return worker([&]{auto ownership=!ownedSession?acquireStorageSession(c):nullptr;
        state::FileStore vault(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
        const auto lease=vault.lock();if(!lease)refuse();PrivateRecord old{vault.load()};auto k=keys(old.value,binding(c));
        if(k->initializing||k->suspended||!k->pending.empty())refuse();if(k->retiring==retiring)return k;k->retiring=retiring;
        if(retiring){const auto r=readStorage(c,k->local,k->sync);if(r.pending||r.publication||r.resolution)refuse();}
        PrivateRecord next{record(binding(c),*k,old.value.generation+1,{old.value.head->event.revision.id})};
        vault.commit(old.value,next.value);verify(vault,next.value);return k;});
}
StorageKeysPtr rotateStorageKey(const StorageConfiguration &c,const Bytes &password,const transaction::Store::Lease *ownedSession){
    profile(c);return worker([&]{auto ownership=!ownedSession?acquireStorageSession(c):nullptr;
        state::FileStore vault(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
        const auto lease=vault.lock();if(!lease)refuse();PrivateRecord old{vault.load()};auto k=keys(old.value,binding(c));if(k->retiring||k->initializing||k->suspended)refuse();
        if(k->pending.empty()){
            k->pending=crypto::random(32);
            PrivateRecord next{record(binding(c),*k,old.value.generation+1,{old.value.head->event.revision.id})};
            vault.commit(old.value,next.value);verify(vault,next.value);wipe(old.value);old.value=std::move(next.value);
        }
        VAULT_HOOK(RotationPrepared);
        // Check the new key first: an earlier interruption may already have rekeyed data.
        bool done=false;
        {state::FileStore data(path(c.profile.stateDirectory),c.binding.toStdString(),k->pending);const auto l=data.lock();if(!l)refuse();
         try{const auto r=data.load();validateStorageRecord(r,c,k->sync);done=true;}
         catch(const state::Error &e){if(e.code()!=state::ErrorCode::AuthenticationFailed)throw;}}
        if(!done){state::FileStore data(path(c.profile.stateDirectory),c.binding.toStdString(),k->local);const auto l=data.lock();if(!l)refuse();
            const auto before=data.load();validateStorageRecord(before,c,k->sync);
            const auto snapshot=before.schema>=2?*before.local:before.head?before.head->snapshot:Snapshot{};
            auto next=before;++next.generation;
            if(before.schema==1)next=checkpointRecord(c.binding.toStdString(),"cqs-storage",snapshot,before.generation+1,
                before.head?std::vector<std::string>{before.head->event.revision.id}:std::vector<std::string>{});
            data.transition(before,next,k->pending);const auto actual=data.load();validateStorageRecord(actual,c,k->sync);
            if((actual.schema>=2?*actual.local:actual.head->snapshot)!=snapshot)refuse();}
        VAULT_HOOK(DataRekeyed);
        crypto::wipe(k->local);k->local=std::move(k->pending);
        PrivateRecord next{record(binding(c),*k,old.value.generation+1,{old.value.head->event.revision.id})};
        vault.commit(old.value,next.value);verify(vault,next.value);VAULT_HOOK(RotationFinished);return k;
    });
}
void backupVault(const StorageConfiguration &c,const Bytes &password,const std::filesystem::path &destination){
    profile(c);externalDirectory(c,destination);worker([&]{state::FileStore source(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
        const auto lease=source.lock();if(!lease)refuse();PrivateRecord r{source.load()};keys(r.value,binding(c));
        state::FileStore backup(destination,binding(c),password,limits(),state::Protection::Password);const auto l=backup.lock();if(!l)refuse();
        backup.initialize(r.value);verify(backup,r.value);});
}
void restoreMissingVault(const StorageConfiguration &c,const Bytes &password,const std::filesystem::path &backup,const QString &alternateDataBinding){
    profile(c);externalDirectory(c,backup);worker([&]{state::FileStore source(backup,binding(c),password,limits(),state::Protection::Password);
        const auto lease=source.lock();if(!lease)refuse();PrivateRecord r{source.load()};auto k=keys(r.value,binding(c));
        bool archived=false,pending=false;
        const auto authenticate=[&](const StorageConfiguration &data){
            if(!k->pending.empty())try{readStorage(data,k->pending,k->sync);pending=true;return;}
                catch(const state::Error &e){if(e.code()!=state::ErrorCode::AuthenticationFailed)throw;}
            readStorage(data,k->local,k->sync);
        };
        try{authenticate(c);}
        catch(const state::Error &e){if(e.code()!=state::ErrorCode::AuthenticationFailed||alternateDataBinding.isEmpty())throw;
            auto data=c;data.binding=alternateDataBinding;authenticate(data);archived=true;}
        if(archived){if(pending)k->local=k->pending;k->pending.clear();k->suspended=true;k->retiring=false;k->initializing=false;
            r.value=record(binding(c),*k,r.value.generation+1,{r.value.head->event.revision.id});}
        state::FileStore target(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
        const auto l=target.lock();if(!l)refuse();target.initialize(r.value);verify(target,r.value);});
}
void exportSyncKey(const StorageConfiguration &c,const Bytes &password,const Bytes &transferPassword,const std::filesystem::path &destination){
    profile(c);externalDirectory(c,destination);newPassword(transferPassword);worker([&]{auto k=unlockVault(c,password);
        PrivateRecord r{checkpointRecord(TransferBinding,"cqs-keytransfer",{{{Sync,k->sync}}},1)};
        state::FileStore transfer(destination,TransferBinding,transferPassword,limits(),state::Protection::Password);
        const auto lease=transfer.lock();if(!lease)refuse();transfer.initialize(r.value);verify(transfer,r.value);});
}
StorageKeysPtr importSyncVault(const StorageConfiguration &c,const Bytes &password,const Bytes &transferPassword,const std::filesystem::path &source){
    profile(c);externalDirectory(c,source);newPassword(password);return worker([&]{state::FileStore transfer(source,TransferBinding,transferPassword,limits(),state::Protection::Password);
        const auto lease=transfer.lock();if(!lease)refuse();PrivateRecord r{transfer.load()};
        if(r.value.pending||!r.value.head||r.value.head->event.revision.device!="cqs-keytransfer"||
           r.value.head->snapshot.size()!=1||r.value.head->snapshot[0].size()!=1||!r.value.head->snapshot[0].count(Sync)||
           r.value.head->snapshot[0].at(Sync).size()!=32||packed::decode(r.value.head->event.items,limits().snapshot)!=r.value.head->snapshot)refuse();
        return createVault(c,password,r.value.head->snapshot[0].at(Sync),true);});
}
StorageKeysPtr migrateLegacyStorage(const StorageConfiguration &c,const Bytes &password){
    profile(c);return worker([&]{
        const auto ownership=acquireStorageSession(c);
        auto legacy=c.profile;legacy.schema=2;legacy.vaultDirectory.clear();const auto previous=storageConfiguration(legacy);
        StorageKeysPtr k;
        try{k=unlockVault(c,password);}catch(const state::Error &e){if(e.code()!=state::ErrorCode::Missing)throw;
            Secret oldKey{readKeyStrict(path(c.profile.keyFile))};state::FileStore old(path(c.profile.stateDirectory),previous.binding.toStdString(),oldKey.bytes);
            const auto l=old.lock();if(!l)refuse();validateStorageRecord(old.load(),previous);k=createVault(c,password,oldKey.bytes);}
        {state::FileStore data(path(c.profile.stateDirectory),c.binding.toStdString(),k->local);const auto l=data.lock();if(!l)refuse();
         try{validateStorageRecord(data.load(),c,k->sync);return k;}catch(const state::Error &e){if(e.code()!=state::ErrorCode::AuthenticationFailed)throw;}}
        state::FileStore data(path(c.profile.stateDirectory),previous.binding.toStdString(),k->sync);const auto l=data.lock();if(!l)refuse();
        const auto old=data.load();validateStorageRecord(old,previous);const auto snapshot=old.head?old.head->snapshot:Snapshot{};
        Record next{2,c.binding.toStdString(),old.generation+1,{},{}};
        next.local=snapshot;next.keyIdentity=syncKeyIdentity(k->sync);
        data.transition(old,next,k->local);VAULT_HOOK(MigrationRekeyed);const auto actual=data.load();validateStorageRecord(actual,c,k->sync);if((actual.schema>=2?*actual.local:actual.head->snapshot)!=snapshot)refuse();return k;
    });
}
void repairMissingVault(const StorageConfiguration &c,const StorageKeysPtr &unlocked,const Bytes &password,const QString &alternateDataBinding){
    profile(c);newPassword(password);if(!unlocked||unlocked->local.size()!=32||unlocked->sync.size()!=32)refuse();
    worker([&]{bool archived=false;
        try{readStorage(c,unlocked->local,unlocked->sync);}
        catch(const state::Error &e){if(e.code()!=state::ErrorCode::AuthenticationFailed||alternateDataBinding.isEmpty())throw;
            auto data=c;data.binding=alternateDataBinding;readStorage(data,unlocked->local,unlocked->sync);archived=true;}
        auto k=std::make_shared<StorageKeys>();k->local=unlocked->local;k->sync=unlocked->sync;k->retiring=unlocked->retiring;k->suspended=unlocked->suspended||archived;
        state::FileStore vault(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
        const auto l=vault.lock();if(!l)refuse();PrivateRecord initial{record(binding(c),*k,1)};
        vault.initialize(initial.value);verify(vault,initial.value);
    });
}

StorageKeysPtr provisionTransitionVault(const StorageConfiguration &c,const Bytes &password,const StorageKeysPtr &wanted){
    profile(c);newPassword(password);if(!wanted||wanted->local.size()!=32||wanted->sync.size()!=32||wanted->local==wanted->sync)refuse();
    state::FileStore vault(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
    const auto l=vault.lock();if(!l)refuse();
    try{const auto actual=keys(vault.load(),binding(c));
        if(actual->local!=wanted->local||actual->sync!=wanted->sync||actual->suspended||actual->retiring||actual->initializing||!actual->pending.empty())refuse();
        return actual;
    }catch(const state::Error &e){if(e.code()!=state::ErrorCode::Missing)throw;}
    PrivateRecord initial{record(binding(c),*wanted,1)};vault.initialize(initial.value);verify(vault,initial.value);return wanted;
}
StorageKeysPtr suspendVault(const StorageConfiguration &c,const Bytes &password,bool suspend,const Store::Lease *owned){
    profile(c);auto ownership=!owned?acquireStorageSession(c):nullptr;
    state::FileStore vault(path(c.profile.vaultDirectory),binding(c),password,limits(),state::Protection::Password);
    const auto l=vault.lock();if(!l)refuse();PrivateRecord old{vault.load()};auto k=keys(old.value,binding(c));
    if(k->retiring||k->initializing||!k->pending.empty())refuse();
    if(k->suspended==suspend)return k;k->suspended=suspend;
    PrivateRecord next{record(binding(c),*k,old.value.generation+1,{old.value.head->event.revision.id})};
    vault.commit(old.value,next.value);verify(vault,next.value);return k;
}
Bytes readTransferredSyncKey(const StorageConfiguration &c,const Bytes &password,const std::filesystem::path &source){
    profile(c);externalDirectory(c,source);
    state::FileStore transfer(source,TransferBinding,password,limits(),state::Protection::Password);
    const auto l=transfer.lock();if(!l)refuse();PrivateRecord r{transfer.load()};
    if(r.value.pending||!r.value.head||r.value.head->event.revision.device!="cqs-keytransfer"||
       r.value.head->snapshot.size()!=1||r.value.head->snapshot[0].size()!=1||!r.value.head->snapshot[0].count(Sync)||
       r.value.head->snapshot[0].at(Sync).size()!=32||packed::decode(r.value.head->event.items,limits().snapshot)!=r.value.head->snapshot)refuse();
    return r.value.head->snapshot[0].at(Sync);
}

}
