// SPDX-License-Identifier: GPL-3.0-or-later
#include "history_transition.h"
#include "unified_state.h"
#include "state_store.h"
#include "storage.h"
#include "packed_items.h"
#include <QDir>
#include <QFileInfo>
#include <QJsonObject>
#include <QJsonDocument>
#include <QScopeGuard>
#include <algorithm>
#include <limits>
#include <set>
#ifdef CQS_TRANSITION_TESTING
#include "../tests/history_transition_hooks.h"
#define TRANSITION_HOOK(p) do{if(transition_testing::hook)transition_testing::hook(transition_testing::Point::p);}while(false)
#else
#define TRANSITION_HOOK(p) do{}while(false)
#endif
namespace cqs::native {
StorageConfiguration archivedTransitionSource(const StorageConfiguration &source,const Profile &successor){
    const auto target=storageConfiguration(successor);auto archived=source;
    auto input=QByteArray("CopyQ-Secure-Sync-retired-source-v1");input.append('\0');
    input.append(source.binding.toUtf8());input.append('\0');input.append(target.binding.toUtf8());
    const auto hash=crypto::sha256({input.begin(),input.end()});
    archived.binding="CqsArchivedStorageV1-"+QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(hash.data()),qsizetype(hash.size())).toHex());
    return archived;
}
namespace {
using namespace transaction;
using crypto::Bytes;
constexpr const char *Meta="application/x-cqs-transition-meta";
constexpr const char *Local="application/x-cqs-transition-local-key";
constexpr const char *Sync="application/x-cqs-transition-sync-key";
constexpr const char *Wire="application/x-cqs-transition-wire";
[[noreturn]] void refuse(){throw crypto::Error("History transition refused; retain all profiles and resume or cancel the recorded transition");}
std::filesystem::path path(const QString &s){
#ifdef Q_OS_WIN
    return std::filesystem::path(s.toStdWString());
#else
    return std::filesystem::u8path(s.toUtf8().toStdString());
#endif
}
QString string(const std::filesystem::path &p){
#ifdef Q_OS_WIN
    return QString::fromStdWString(p.native());
#else
    return QString::fromUtf8(p.native().c_str());
#endif
}
Bytes bytes(const QByteArray &v){return {v.begin(),v.end()};}
QByteArray array(const Bytes &v){return {reinterpret_cast<const char *>(v.data()),qsizetype(v.size())};}
std::string journalBinding(const StorageConfiguration &c){return "CqsHistoryTransitionV1-"+c.binding.right(64).toStdString();}
std::string digest(const Record &r){auto plain=state::serialize(r);const auto wipe=qScopeGuard([&]{crypto::wipe(plain);});return array(crypto::sha256(plain)).toHex().toStdString();}
std::string digest(const events::AuthenticatedHistory &h){
    Bytes input;for(const auto &entry:h.fingerprints()){input.insert(input.end(),entry.first.begin(),entry.first.end());input.push_back(0);input.insert(input.end(),entry.second.begin(),entry.second.end());}
    return array(crypto::sha256(input)).toHex().toStdString();
}
void disjoint(const QStringList &roots,const QString &allowedMissing={}){
    QStringList seen;
    for(auto root:roots){
        const auto lexical=QDir::fromNativeSeparators(root);
        if(lexical.size()>4096||!QDir::isAbsolutePath(lexical)||lexical.startsWith("//")||lexical.contains("://"))refuse();
        for(auto ch:lexical)if(ch.unicode()<32||ch.unicode()==127)refuse();
        for(const auto &part:lexical.split('/'))if(part=="."||part=="..")refuse();
        const QFileInfo info(root);if(!info.isDir()&&(root!=allowedMissing||info.exists()))refuse();
        // Runtime backends additionally open every path component without links.
        root=QDir::cleanPath(info.isDir()?info.canonicalFilePath():lexical);if(root.isEmpty()||QDir(root).isRoot())refuse();
#ifdef Q_OS_WIN
        root=root.toCaseFolded();
#endif
        for(const auto &other:seen)if(root==other||root.startsWith(other+'/')||other.startsWith(root+'/'))refuse();seen.append(root);
    }
}
void profiles(const StorageConfiguration &source,const StorageConfiguration &target,const std::filesystem::path &journal,bool localSource=false){
    // The optional raw import file is no longer a credential once the vault
    // exists. Keep its original path in the binding, without requiring the
    // user to retain/recreate plaintext key material for migration.
    auto sourcePaths=source.profile;sourcePaths.keyFile.clear();
    if(localSource){sourcePaths.transport=target.profile.transport;sourcePaths.publicationStaging.clear();}
    if(!source.profile.standaloneStorage||!target.profile.standaloneStorage||!target.profile.keyFile.isEmpty()||
       source.profile.device!=target.profile.device||target.profile.predecessorBinding!=source.binding.right(64)||
       !validateProfile(source.profile,false).isEmpty()||!validateProfile(sourcePaths,true).isEmpty()||!validateProfile(target.profile,true).isEmpty())refuse();
    // Reject unroundtrippable/oversized metadata before suspending either
    // profile. Existing bindings distinguish null and empty QString values.
    if(storageConfiguration(decodeProfile(encodeProfile(source.profile))).binding!=source.binding||
       storageConfiguration(decodeProfile(encodeProfile(target.profile))).binding!=target.binding)refuse();
    disjoint({source.profile.transport,source.profile.stateDirectory,source.profile.vaultDirectory,
        target.profile.transport,target.profile.stateDirectory,target.profile.vaultDirectory,string(journal)},localSource?source.profile.transport:QString{});
    // Staging is private and may equal the target state folder, but cannot touch
    // old state/transport/vault, either vault, the journal or the new transport.
    if(!target.profile.publicationStaging.isEmpty()&&target.profile.publicationStaging!=target.profile.stateDirectory)
        disjoint({source.profile.transport,source.profile.stateDirectory,source.profile.vaultDirectory,target.profile.transport,
            target.profile.vaultDirectory,string(journal),target.profile.publicationStaging},localSource?source.profile.transport:QString{});
}
void checkEmpty(const StorageConfiguration &c){
    for(const auto &directory:{c.profile.stateDirectory,c.profile.vaultDirectory}){
        state::FileStore file(path(directory),c.binding.toStdString(),Bytes(32));const auto l=file.lock();if(!l)refuse();file.checkInitializable();
    }
}
struct Journal {
    Record record;
    QJsonObject meta;
    StorageKeysPtr keys=std::make_shared<StorageKeys>();
    ~Journal(){if(record.local)for(auto &item:*record.local)for(auto &field:item)crypto::wipe(field.second);}
    void parse(){
        if(record.schema!=2||record.head||record.pending||!record.local||record.local->size()!=1)refuse();
        const auto &item=record.local->at(0);if((item.size()!=3&&item.size()!=4)||(item.size()==4&&!item.count(Wire)))refuse();
        if(!item.count(Meta)||!item.count(Local)||!item.count(Sync)||item.at(Local).size()!=32||item.at(Sync).size()!=32)refuse();
        keys->local=item.at(Local);keys->sync=item.at(Sync);if(keys->local==keys->sync||record.keyIdentity!=syncKeyIdentity(keys->sync))refuse();
        if(item.at(Meta).size()>65536)refuse();meta=QJsonDocument::fromJson(array(item.at(Meta))).object();
        if(meta.size()!=9||(meta.value("v").toInt()!=1&&meta.value("v").toInt()!=2)||meta.value("mode").toInt(-1)<0||meta.value("mode").toInt()>2||
           meta.value("phase").toInt(-1)<0||meta.value("phase").toInt()>2||meta.value("index").toInt(-1)<0)refuse();
    }
    void encode(){const auto encoded=QJsonDocument(meta).toJson(QJsonDocument::Compact);if(encoded.size()>65536)refuse();
        record.local=Snapshot{{{Meta,bytes(encoded)},{Local,keys->local},{Sync,keys->sync}}};}
};
void verified(state::FileStore &store,const Record &wanted){if(digest(store.load())!=digest(wanted))refuse();}
void commit(state::FileStore &store,Journal &j,QJsonObject next,std::optional<std::string> wire={}){
    const auto before=j.record;j.meta=std::move(next);j.encode();++j.record.generation;
    if(wire)j.record.local->at(0)[Wire]=Bytes(wire->begin(),wire->end());
    store.commit(before,j.record);verified(store,j.record);
}
std::vector<const events::Event *> ordered(const events::AuthenticatedHistory &h){
    std::vector<const events::Event *> result;std::set<std::string> done;
    while(result.size()!=h.events().size()){
        const auto before=result.size();
        for(const auto &e:h.events())if(!done.count(e.revision.id)&&std::all_of(e.revision.parents.begin(),e.revision.parents.end(),[&](const auto &p){return done.count(p);})){
            result.push_back(&e);done.insert(e.revision.id);
        }
        if(before==result.size())refuse();
    }return result;
}
struct Plan { Record record;std::shared_ptr<events::Event> root;std::vector<const events::Event *> events; };
Plan plan(const StorageConfiguration &target,const StorageKeysPtr &keys,const Record &source,const events::AuthenticatedHistory &old,HistoryTransitionMode mode,RowProtection protection,bool legacy=false){
    if(source.schema<2||!source.local||source.generation>std::numeric_limits<std::uint64_t>::max()-2||
       ((mode==HistoryTransitionMode::Rekey||legacy)&&(source.pending||source.publication||source.resolution||!source.head)))refuse();
    Plan p;p.record=source;p.record.schema=6;p.record.binding=target.binding.toStdString();p.record.keyIdentity=syncKeyIdentity(keys->sync);++p.record.generation;
    if(mode!=HistoryTransitionMode::Rekey){p.record.pending.reset();p.record.publication.reset();p.record.resolution.reset();}
    if(mode==HistoryTransitionMode::Rekey){p.events=ordered(old);p.record.witnessed=old.fingerprints();}
    else if(mode==HistoryTransitionMode::Compact){
        // The user explicitly chooses the current local snapshot. Remote/conflict
        // branches and unsent edits remain recoverable in the retained source.
        const auto head=checkpointRecord("transition-packing",target.profile.device.toStdString(),*source.local,1).head;
        p.record.head=head;p.record.allocatedSequence=1;p.record.witnessed={{head->event.revision.id,eventFingerprint(head->event)}};p.root=std::make_shared<events::Event>(head->event);p.events={p.root.get()};
    }else{
        storage::Directory directory(path(target.profile.transport));const auto history=directory.scan(keys->sync);
        if(history.graph().tips().size()!=1)refuse();
        const auto id=history.graph().tips().front();const auto found=std::find_if(history.events().begin(),history.events().end(),[&](const auto &e){return e.revision.id==id;});
        const auto snapshot=packed::decode(found->items,storageLimits());protection.validate(*source.local,snapshot);
        const bool saved=std::find(p.record.archives.begin(),p.record.archives.end(),*source.local)!=p.record.archives.end()||
            (p.record.preserved&&*p.record.preserved==*source.local);
        if(snapshot!=*source.local&&(legacy||!saved)){
            if(p.record.archives.size()==4)throw Error(ErrorCode::BackupLimit,"Free one protected backup slot before Join successor");
            p.record.archives.push_back(*source.local);}
        p.record.local=snapshot;p.record.head=Head{*found,snapshot};p.record.witnessed=history.fingerprints();
        p.record.allocatedSequence=history.graph().nextSequence(target.profile.device.toStdString())-1;
    }
    validateStorageRecord(p.record,target,keys->sync);
    auto encoded=state::serialize(p.record);crypto::wipe(encoded);return p;
}
HistoryTransitionResult run(const StorageConfiguration &source,const Bytes &password,const std::filesystem::path &journal,
    const std::optional<Profile> &requested,HistoryTransitionMode requestedMode,const Bytes &joinKey,RowProtection protection,std::function<void()> check){
    const auto poll=[&]{if(check)check();};poll();
    auto sourceSession=acquireStorageSession(source);const auto oldKeys=unlockVault(source,password);
    if(oldKeys->initializing||oldKeys->retiring||!oldKeys->pending.empty())refuse();
    disjoint({source.profile.transport,source.profile.stateDirectory,source.profile.vaultDirectory,string(journal)},source.profile.transport);
    state::FileStore store(journal,journalBinding(source),password,{},state::Protection::Password);const auto journalLease=store.lock();if(!journalLease)refuse();
    Journal j;StorageConfiguration target;HistoryTransitionMode mode;
    bool legacy=false;
    if(requested){
        if(oldKeys->suspended)refuse();target=storageConfiguration(*requested);mode=requestedMode;
    }else{
        j.record=store.load();j.parse();if(j.meta.value("phase").toInt()==2)refuse();
        if(decodeProfile(j.meta.value("source").toString().toUtf8())!=source.profile)refuse();
        target=storageConfiguration(decodeProfile(j.meta.value("target").toString().toUtf8()));
        mode=HistoryTransitionMode(j.meta.value("mode").toInt());legacy=j.meta.value("v").toInt()==1;
    }
    const bool localSource=!legacy&&mode!=HistoryTransitionMode::Rekey;
    profiles(source,target,journal,localSource);
    const auto archive=archivedTransitionSource(source,target.profile);
    bool retired=false;Record before;
    try{before=readStorage(source,oldKeys->local,oldKeys->sync);}
    catch(const state::Error &e){
        if(e.code()!=state::ErrorCode::AuthenticationFailed||requested||legacy)throw;
        before=readStorage(archive,oldKeys->local,oldKeys->sync);if(!before.generation)refuse();
        before.binding=source.binding.toStdString();--before.generation;retired=true;
    }
    std::unique_ptr<storage::Directory> original;
    events::AuthenticatedHistory history(oldKeys->sync,{});
    if(!localSource){original=std::make_unique<storage::Directory>(path(source.profile.transport));history=original->scan(oldKeys->sync);verifyHistory(before,history);}
    if(requested){
        checkEmpty(target);store.checkInitializable();
        j.keys->local=crypto::random(32);j.keys->sync=mode==HistoryTransitionMode::Join?joinKey:crypto::random(32);
        if(j.keys->sync.size()!=32||j.keys->sync==oldKeys->sync)refuse();
        storage::Directory destination(path(target.profile.transport));const auto existing=destination.scan(j.keys->sync);
        if(mode!=HistoryTransitionMode::Join&&existing.graph().size())refuse();
        if(mode!=HistoryTransitionMode::Join){destination.checkPublicationDevice(target.profile.device.toStdString());
#ifdef Q_OS_WIN
            destination.checkPublicationStaging(path(target.profile.publicationStaging.isEmpty()?target.profile.stateDirectory:target.profile.publicationStaging));
#else
            destination.checkPublicationStaging();
#endif
        }
        plan(target,j.keys,before,history,mode,protection); // Capacity/protection checks precede freezing.
        j.record={2,journalBinding(source),0,{},{}};j.record.keyIdentity=syncKeyIdentity(j.keys->sync);
        j.meta={{"v",2},{"source",QString::fromUtf8(encodeProfile(source.profile))},{"target",QString::fromUtf8(encodeProfile(target.profile))},
            {"mode",int(mode)},{"source_record",QString::fromStdString(digest(before))},{"source_history",QString::fromStdString(digest(history))},
            {"target_history",QString::fromStdString(digest(existing))},{"phase",0},{"index",0}};
        if(QJsonDocument(j.meta).toJson(QJsonDocument::Compact).size()>65520)refuse();
        j.encode();store.initialize(j.record);verified(store,j.record);TRANSITION_HOOK(JournalCreated);
    }
    if(j.meta.value("source_record").toString()!=QString::fromStdString(digest(before))||j.meta.value("source_history").toString()!=QString::fromStdString(digest(history)))refuse();
    auto targetSession=acquireStorageSession(target);
    poll();suspendVault(source,password,true,sourceSession.get());TRANSITION_HOOK(SourceVaultSuspended);
    if(!legacy&&!retired){
        state::FileStore data(path(source.profile.stateDirectory),source.binding.toStdString(),oldKeys->local);const auto l=data.lock();if(!l)refuse();
        auto next=before;next.binding=archive.binding.toStdString();++next.generation;
        data.transition(before,next,oldKeys->local);verified(data,next);
    }
    TRANSITION_HOOK(SourceSuspended);poll();
    const auto prepared=plan(target,j.keys,before,history,mode,protection,legacy);
    provisionTransitionVault(target,password,j.keys);TRANSITION_HOOK(VaultCreated);poll();
    storage::Directory destination(path(target.profile.transport));const auto existing=destination.scan(j.keys->sync);
    if(mode==HistoryTransitionMode::Join){if(j.meta.value("target_history").toString()!=QString::fromStdString(digest(existing)))refuse();}
    else {
        const auto index=std::size_t(j.meta.value("index").toInt());if(index>prepared.events.size())refuse();
        std::map<std::string,Bytes> expected;
        for(std::size_t i=0;i<index;++i)expected.emplace(prepared.events[i]->revision.id,eventFingerprint(*prepared.events[i]));
        // A process may die after delivery but before advancing the journal.
        if(j.record.local->at(0).count(Wire)&&index<prepared.events.size()&&existing.graph().contains(prepared.events[index]->revision.id))
            expected.emplace(prepared.events[index]->revision.id,eventFingerprint(*prepared.events[index]));
        if(existing.fingerprints()!=expected)refuse();
        for(std::size_t i=index;i<prepared.events.size();++i){
            poll();const auto &event=*prepared.events[i];std::string wire;
            if(j.record.local->at(0).count(Wire))wire=std::string(j.record.local->at(0).at(Wire).begin(),j.record.local->at(0).at(Wire).end());
            else {wire=encryptHistoryEvent(event,j.keys->sync);commit(store,j,j.meta,wire);TRANSITION_HOOK(EventReserved);}
            if(eventFingerprint(events::decode(j.keys->sync,{event.revision.id,wire}))!=eventFingerprint(event))refuse();
            try{
#ifdef Q_OS_WIN
                const auto staging=path(target.profile.publicationStaging.isEmpty()?target.profile.stateDirectory:target.profile.publicationStaging);
#else
                const std::filesystem::path staging;
#endif
                destination.publish(j.keys->sync,{event.revision.id,wire},{},staging);
            }catch(const storage::Error &e){if(e.code()!=storage::ErrorCode::AlreadyExists&&e.code()!=storage::ErrorCode::PublishedUnconfirmed)throw;}
            destination.confirm(j.keys->sync,{event.revision.id,wire});TRANSITION_HOOK(EventDelivered);poll();
            auto meta=j.meta;meta["index"]=int(i+1);commit(store,j,meta);TRANSITION_HOOK(EventRecorded);
        }
    }
    poll();const auto final=destination.scan(j.keys->sync);
    if(final.fingerprints()!=prepared.record.witnessed)refuse();
    state::FileStore data(path(target.profile.stateDirectory),target.binding.toStdString(),j.keys->local);const auto l=data.lock();if(!l)refuse();
    try{if(digest(data.load())!=digest(prepared.record))refuse();}
    catch(const state::Error &e){if(e.code()!=state::ErrorCode::Missing)throw;data.initialize(prepared.record);}
    verified(data,prepared.record);TRANSITION_HOOK(StateCreated);poll();
    // Catch old peers adding/replacing/withholding data while the copy was running.
    if(original&&digest(original->scan(oldKeys->sync))!=digest(history))refuse();
    auto retained=readStorage(legacy?source:archive,oldKeys->local,oldKeys->sync);
    if(!legacy){if(!retained.generation)refuse();retained.binding=source.binding.toStdString();--retained.generation;}
    if(digest(retained)!=digest(before))refuse();
    if(j.meta.value("phase").toInt()!=1){auto meta=j.meta;meta["phase"]=1;commit(store,j,meta);}
    TRANSITION_HOOK(Ready);poll();return {target.profile,j.keys};
}
}
HistoryTransitionResult startHistoryTransition(const StorageConfiguration &source,Profile target,const Bytes &password,const std::filesystem::path &journal,
 HistoryTransitionMode mode,const Bytes &joinKey,RowProtection protection,std::function<void()> check){
    target.predecessorBinding=source.binding.right(64);target.keyFile.clear();
    return run(source,password,journal,target,mode,joinKey,std::move(protection),std::move(check));
}
HistoryTransitionResult resumeHistoryTransition(const StorageConfiguration &source,const Bytes &password,const std::filesystem::path &journal,RowProtection protection,std::function<void()> check){
    return run(source,password,journal,{},HistoryTransitionMode::Rekey,{},std::move(protection),std::move(check));
}
void cancelHistoryTransition(const StorageConfiguration &source,const Bytes &password,const std::filesystem::path &journal,bool sourceStillActive){
    auto ownership=acquireStorageSession(source);const auto keys=unlockVault(source,password);
    state::FileStore store(journal,journalBinding(source),password,{},state::Protection::Password);const auto l=store.lock();if(!l)refuse();
    Journal j;j.record=store.load();j.parse();
    if(decodeProfile(j.meta.value("source").toString().toUtf8())!=source.profile||(j.meta.value("phase").toInt()==1&&!sourceStillActive))refuse();
    const auto target=storageConfiguration(decodeProfile(j.meta.value("target").toString().toUtf8()));
    std::unique_ptr<Store::Lease> targetSession;
    if(j.meta.value("phase").toInt()!=2){
        profiles(source,target,journal,j.meta.value("v").toInt()>=2&&j.meta.value("mode").toInt()!=int(HistoryTransitionMode::Rekey));
        targetSession=acquireStorageSession(target);
    }
    // Record cancellation before allowing old-profile edits. Retrying cancellation
    // is safe; a cancelled journal can never resume or activate its destination.
    if(j.meta.value("phase").toInt()!=2){auto meta=j.meta;meta["phase"]=2;commit(store,j,meta);}
    if(j.meta.value("v").toInt()>=2){
        try{readStorage(source,keys->local,keys->sync);}
        catch(const state::Error &e){
            if(e.code()!=state::ErrorCode::AuthenticationFailed)throw;
            const auto archive=archivedTransitionSource(source,target.profile);
            state::FileStore data(path(source.profile.stateDirectory),archive.binding.toStdString(),keys->local);const auto lease=data.lock();if(!lease)refuse();
            const auto before=data.load();validateStorageRecord(before,archive,keys->sync);
            auto next=before;next.binding=source.binding.toStdString();++next.generation;
            data.transition(before,next,keys->local);verified(data,next);
        }
    }
    suspendVault(source,password,false,ownership.get());
}
StorageConfiguration historyTransitionSourceConfiguration(const StorageConfiguration &source,const Bytes &password,const std::filesystem::path &journal){
    disjoint({source.profile.stateDirectory,source.profile.vaultDirectory,string(journal)});
    state::FileStore store(journal,journalBinding(source),password,{},state::Protection::Password);const auto lease=store.lock();if(!lease)refuse();
    Journal j;j.record=store.load();
    if(!j.record.local||j.record.local->size()!=1||!j.record.local->at(0).count(Meta))refuse();
    const auto meta=QJsonDocument::fromJson(array(j.record.local->at(0).at(Meta))).object();
    if(meta.size()!=9||(meta.value("v").toInt()!=1&&meta.value("v").toInt()!=2)||
        decodeProfile(meta.value("source").toString().toUtf8())!=source.profile)refuse();
    if(meta.value("v").toInt()==1||meta.value("phase").toInt()==2)return source;
    return archivedTransitionSource(source,decodeProfile(meta.value("target").toString().toUtf8()));
}
void finishHistoryTransition(const StorageConfiguration &active,const Bytes &vaultPassword,const Bytes &journalPassword,const std::filesystem::path &journal){
    if(active.profile.predecessorBinding.isEmpty()||!active.profile.standaloneStorage||!validateProfile(active.profile,false).isEmpty())refuse();
    disjoint({active.profile.transport,active.profile.stateDirectory,active.profile.vaultDirectory,string(journal)});
    const auto session=acquireStorageSession(active);const auto keys=unlockVault(active,vaultPassword);
    if(keys->suspended||keys->retiring||keys->initializing||!keys->pending.empty())refuse();
    readStorage(active,keys->local,keys->sync);
    state::FileStore store(journal,"CqsHistoryTransitionV1-"+active.profile.predecessorBinding.toStdString(),journalPassword,{},state::Protection::Password);
    const auto l=store.lock();if(!l)refuse();Journal j;j.record=store.load();
    if(!j.record.local||j.record.local->size()!=1||!j.record.local->at(0).count(Meta))refuse();
    auto meta=QJsonDocument::fromJson(array(j.record.local->at(0).at(Meta))).object();
    if(decodeProfile(meta.value("target").toString().toUtf8())!=active.profile||j.record.keyIdentity!=syncKeyIdentity(keys->sync))refuse();
    if(meta.value("phase").toInt(-1)==3){if(j.record.local->at(0).size()!=1)refuse();return;}
    j.parse();if(j.meta.value("phase").toInt()!=1||j.keys->sync!=keys->sync)refuse();
    meta["phase"]=3;auto next=j.record;++next.generation;
    next.local=Snapshot{{{Meta,bytes(QJsonDocument(meta).toJson(QJsonDocument::Compact))}}};
    store.commit(j.record,next);verified(store,next);TRANSITION_HOOK(JournalSealed);
}

}
