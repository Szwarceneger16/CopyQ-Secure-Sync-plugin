// SPDX-License-Identifier: GPL-3.0-or-later
#include "unified_state.h"
#include "state_store.h"
#include "storage.h"
#include "packed_items.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <future>
#include <limits>
#include <algorithm>
#include <QScopeGuard>

namespace cqs::native {
std::string encryptHistoryEvent(const events::Event &event,const crypto::Bytes &key){
    QJsonArray items,parents;
    for(const auto &s:event.items)items.append(QString::fromStdString(s));
    for(const auto &s:event.revision.parents)parents.append(QString::fromStdString(s));
    const QJsonObject header{{"device",QString::fromStdString(event.revision.device)},{"parents",parents},
        {"protocol","copyq-secure-sync-v1"},{"seq",qint64(event.revision.sequence)}};
    const auto canonical=QJsonDocument(header).toJson(QJsonDocument::Compact);
    constexpr char domain[]="CopyQ-Secure-Sync-event-v1";
    crypto::Bytes aad(domain,domain+sizeof(domain));aad.insert(aad.end(),canonical.begin(),canonical.end());
    auto plain=QJsonDocument(QJsonObject{{"items",items},{"tab","synced_tray"},{"v",1}}).toJson(QJsonDocument::Compact);
    if(std::size_t(plain.size())>events::Limits{}.plaintextBytes)throw packed::Error();
    crypto::Bytes bytes(plain.begin(),plain.end());plain.fill(0);
    const auto wipe=qScopeGuard([&]{crypto::wipe(bytes);});
    auto compressed=crypto::zlibCompress(bytes);const auto wipeCompressed=qScopeGuard([&]{crypto::wipe(compressed);});
    const auto nonce=crypto::random(12),cipher=crypto::aes256GcmEncrypt(key,nonce,compressed,aad);
    const auto b64=[](const crypto::Bytes &b){return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(b.data()),qsizetype(b.size())).toBase64());};
    const auto wire=QJsonDocument(QJsonObject{{"header",header},{"nonce",b64(nonce)},{"ciphertext",b64(cipher)}}).toJson(QJsonDocument::Compact).toStdString();
    const auto actual=events::decode(key,{event.revision.id,wire});
    if(events::fingerprint(actual)!=events::fingerprint(event))throw packed::Error();return wire;
}
namespace {
using namespace transaction;
struct SecretBytes { crypto::Bytes bytes; ~SecretBytes(){crypto::wipe(bytes);} };
std::filesystem::path path(const QString &s) {
#ifdef Q_OS_WIN
    return std::filesystem::path(s.toStdWString());
#else
    return std::filesystem::u8path(s.toUtf8().toStdString());
#endif
}
[[noreturn]] void fail(ErrorCode code,const char *message){throw Error(code,message);}
std::filesystem::path staging(const StorageConfiguration &c){
#ifdef Q_OS_WIN
    return path(c.profile.publicationStaging.isEmpty()?c.profile.stateDirectory:c.profile.publicationStaging);
#else
    (void)c;return {};
#endif
}
void checkStaging(const storage::Directory &directory,const StorageConfiguration &c){
    directory.checkPublicationDevice(c.profile.device.toStdString());
#ifdef Q_OS_WIN
    try{directory.checkPublicationStaging(staging(c));}
    catch(const storage::Error &){fail(ErrorCode::PublicationStaging,"Private publication staging is unavailable, unsafe or on another volume");}
#else
    directory.checkPublicationStaging(staging(c));
#endif
}
void checkStaging(const StorageConfiguration &c){storage::Directory directory(path(c.profile.transport));checkStaging(directory,c);}
Record publicationWitness(Record record){
    if(record.publication){record.schema=std::max(6u,record.schema);
        const auto &event=record.publication->target.event;
        record.witnessed.emplace(event.revision.id,eventFingerprint(event));}
    return record;
}
void checkPublicationRecordCapacity(const Record &record){
    // Prospective only: a reserved-but-not-yet-delivered ID is not a required
    // history witness until publication. Reserve room for that future witness.
    const SecretBytes capacity{state::serialize(publicationWitness(record))};
}
void advance(Record &r){if(r.generation==std::numeric_limits<std::uint64_t>::max())fail(ErrorCode::GenerationExhausted,"Private generation exhausted");++r.generation;}
Publication prepare(const StorageConfiguration &c,const StorageKeysPtr &keys,const Snapshot &local,std::uint64_t sequence=1,const std::vector<std::string> &parentIds={}) {
    const auto head=checkpointRecord("public-packing-context",c.profile.device.toStdString(),local,sequence,parentIds).head;
    const auto wire=encryptHistoryEvent(head->event,keys->sync);
    auto event=events::decode(keys->sync,{head->event.revision.id,wire});
    if(packed::decode(event.items,storageLimits())!=local)throw packed::Error();
    return {Head{std::move(event),local},wire};
}
}
transaction::Result seedHistory(const StorageConfiguration &c,const StorageKeysPtr &keys,bool retry,const Store::Lease *ownedSession){
    if(!keys||keys->initializing||keys->retiring||keys->suspended||!keys->pending.empty()||!c.profile.standaloneStorage||
       !validateProfile(c.profile,false).isEmpty())throw crypto::Error("Seed requires an active profile");
    return std::async(std::launch::async,[&]{
        auto ownership=!ownedSession?acquireStorageSession(c):nullptr;
        state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);
        auto lease=store.lock();if(!lease)fail(ErrorCode::Busy,"Busy profile");
        auto record=store.load();validateStorageRecord(record,c,keys->sync);
        if(record.schema<2)fail(ErrorCode::InvalidRecord,"Migrate local state first");
        if(record.pending)fail(ErrorCode::PendingRecovery,"Finish import recovery first");
        storage::Directory directory(path(c.profile.transport));
        auto history=directory.scan(keys->sync);verifyHistory(record,history);
        if(history.graph().hasConflict())fail(ErrorCode::Conflict,"Concurrent roots require conflict resolution");
        if(!record.publication){
            if(retry){
                if(record.allocatedSequence==1 && record.head && record.head->event.revision.device==c.profile.device.toStdString() &&
                   record.head->event.revision.sequence==1 && history.graph().contains(record.head->event.revision.id)) {
                    const auto found=std::find_if(history.events().begin(),history.events().end(),[&](const auto &e){return e.revision.id==record.head->event.revision.id;});
                    if(found->items==record.head->event.items && found->revision.parents==record.head->event.revision.parents)return Result::UpToDate;
                }
                fail(ErrorCode::NoPending,"No reserved Seed to recover");
            }
            if(record.head||record.allocatedSequence)fail(ErrorCode::AlreadyJoined,"Seed already allocated or joined");
            if(history.graph().size())fail(ErrorCode::HistoryExists,"Seed requires empty authenticated history; use Join");
            if(record.generation>std::numeric_limits<std::uint64_t>::max()-2)fail(ErrorCode::GenerationExhausted,"Private generation exhausted");
            checkStaging(directory,c);
            auto next=record;next.schema=std::max(3u,record.schema);next.allocatedSequence=1;next.publication=prepare(c,keys,*record.local);advance(next);
            checkPublicationRecordCapacity(next);
            store.commit(record,next);record=store.load();validateStorageRecord(record,c,keys->sync);
            const SecretBytes actualReservation{state::serialize(record)},wantedReservation{state::serialize(next)};
            if(actualReservation.bytes!=wantedReservation.bytes)fail(ErrorCode::VerificationFailed,"Reservation readback differs");
        }else if(!retry)fail(ErrorCode::PendingRecovery,"Retry the exact reserved Seed");
        const auto &pending=*record.publication;
        // Publication never replaces local contents. Later edits stay in local
        // and become LocalChanges relative to this exact reserved/accepted head.
        const auto &id=pending.target.event.revision.id;
        if(history.graph().hasConflict())fail(ErrorCode::Conflict,"Concurrent roots require conflict resolution");
        if(history.graph().size() && !history.graph().contains(id))fail(ErrorCode::Conflict,"History appeared after Seed reservation");
        if(!history.graph().contains(id)) {
            directory.publish(keys->sync,{id,pending.wire},{},staging(c));
        }
        directory.confirm(keys->sync,{id,pending.wire});
        history=directory.scan(keys->sync);
        if(history.graph().hasConflict()||!history.graph().contains(id))fail(ErrorCode::Conflict,"Publication history changed; retain intent");
        const auto found=std::find_if(history.events().begin(),history.events().end(),[&](const auto &e){return e.revision.id==id;});
        if(found->items!=pending.target.event.items || found->revision.parents!=pending.target.event.revision.parents)
            fail(ErrorCode::Equivocation,"Reserved publication changed");
        auto next=record;next.head=pending.target;next.publication.reset();rememberHistory(next,history);advance(next);
        store.commit(record,next);const auto actual=store.load();validateStorageRecord(actual,c,keys->sync);
        const SecretBytes actualBytes{state::serialize(actual)},wantedBytes{state::serialize(next)};
        if(actualBytes.bytes!=wantedBytes.bytes)fail(ErrorCode::VerificationFailed,"Seed commit readback differs");
        return Result::Applied;
    }).get();
}
namespace {
bool sameHead(const std::optional<Head> &a,const std::optional<Head> &b){
    if(a.has_value()!=b.has_value())return false;if(!a)return true;
    return a->snapshot==b->snapshot&&a->event.items==b->event.items&&a->event.revision.id==b->event.revision.id&&
        a->event.revision.parents==b->event.revision.parents;
}
void verified(state::FileStore &store,const Record &before,const Record &next,const StorageConfiguration &c,const StorageKeysPtr &keys){
    store.commit(before,next);const auto actual=store.load();validateStorageRecord(actual,c,keys->sync);
    const SecretBytes actualBytes{state::serialize(actual)},wantedBytes{state::serialize(next)};
    if(actualBytes.bytes!=wantedBytes.bytes)fail(ErrorCode::VerificationFailed,"Publication commit readback differs");
}
void active(const StorageConfiguration &c,const StorageKeysPtr &keys){
    if(!keys||keys->initializing||keys->retiring||keys->suspended||!keys->pending.empty()||!c.profile.standaloneStorage||
       !validateProfile(c.profile,false).isEmpty())throw crypto::Error("Publication requires an active profile");
}
void base(const Record &r,const events::AuthenticatedHistory &h){
    if(r.pending)fail(ErrorCode::PendingRecovery,"Finish import recovery first");
    if(!r.head)fail(ErrorCode::NotJoined,"Explicit Seed/Join required");
    verifyHistory(r,h);
    if(h.graph().hasConflict())fail(ErrorCode::Conflict,"Multiple tips require resolution");
    const auto &head=r.head->event;
    const auto found=std::find_if(h.events().begin(),h.events().end(),[&](const auto &e){return e.revision.id==head.revision.id;});
    if(found==h.events().end())fail(ErrorCode::MissingHead,"Accepted head missing");
    if(found->items!=head.items||found->revision.parents!=head.revision.parents)fail(ErrorCode::Equivocation,"Accepted head changed");
}
}
void verifyAcceptedHead(const Record &r,const events::AuthenticatedHistory &h){
    if(!r.head)fail(ErrorCode::NotJoined,"Accepted head unavailable");
    verifyHistory(r,h);
}
Record observeHistory(const StorageConfiguration &c,const StorageKeysPtr &keys,const events::AuthenticatedHistory &h,const Store::Lease *owned){
    active(c,keys);auto ownership=!owned?acquireStorageSession(c):nullptr;
    state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);
    auto lease=store.lock();if(!lease)fail(ErrorCode::Busy,"Busy profile");
    const auto before=store.load();validateStorageRecord(before,c,keys->sync);auto next=before;
    if(rememberHistory(next,h)){advance(next);verified(store,before,next,c,keys);}
    return next;
}
void checkHistoryCapacity(const events::AuthenticatedHistory &h,const Publication &p,std::size_t additionalEvents,events::Limits limits){
    if(h.graph().contains(p.target.event.revision.id))return; // exact confirmation adds nothing
    std::size_t plain=0;for(const auto &e:h.events())plain+=e.plaintextBytes;
    if(!additionalEvents||additionalEvents>limits.events||h.graph().size()>limits.events-additionalEvents||
       h.wireBytes()>limits.historyBytes||p.wire.size()>limits.historyBytes-h.wireBytes()||
       plain>limits.historyPlaintextBytes||p.target.event.plaintextBytes>limits.historyPlaintextBytes-plain)
        fail(ErrorCode::HistoryLimit,"History capacity reached; retain files and export before starting a new history");
}
Publication prepareResolution(const StorageConfiguration &c,const StorageKeysPtr &keys,const Record &r,const events::AuthenticatedHistory &h,const Snapshot &chosen){
    active(c,keys);validateStorageRecord(r,c,keys->sync);
    if(r.pending||r.publication||!r.head||!h.graph().contains(r.head->event.revision.id))fail(ErrorCode::PendingRecovery,"Resolution base unavailable");
    verifyAcceptedHead(r,h);
    if(h.graph().size()+h.graph().tips().size()-1>history::MaxEvents)fail(ErrorCode::HistoryLimit,"History has no merge capacity");
    if(r.allocatedSequence==history::MaxSequence)fail(ErrorCode::GenerationExhausted,"Outbound counter exhausted");
    const auto &tips=h.graph().tips();if(tips.empty())fail(ErrorCode::NoRemote,"No resolution tips");
    std::vector<std::string> parents;
    if(r.resolution&&tips.size()>1&&std::find(tips.begin(),tips.end(),r.head->event.revision.id)!=tips.end()){
        parents.push_back(r.head->event.revision.id);for(const auto &tip:tips)if(tip!=parents.front()){parents.push_back(tip);break;}
    }else {parents.push_back(tips[0]);if(tips.size()>1)parents.push_back(tips[1]);}
    std::sort(parents.begin(),parents.end());
    checkStaging(c);
    auto p=prepare(c,keys,chosen,std::max(r.allocatedSequence+1,h.graph().nextSequence(c.profile.device.toStdString())),parents);
    checkHistoryCapacity(h,p,std::max(std::size_t{1},tips.size()-1));return p;
}
Record reserveResolution(const StorageConfiguration &c,const StorageKeysPtr &keys,const Record &expected,const events::AuthenticatedHistory &h,
 const Publication &p,bool newDecision,const Store::Lease *owned,std::optional<std::size_t> restoredArchive){
    active(c,keys);auto ownership=!owned?acquireStorageSession(c):nullptr;
    state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);auto lease=store.lock();if(!lease)fail(ErrorCode::Busy,"Busy profile");
    const auto before=store.load();validateStorageRecord(before,c,keys->sync);
    const SecretBytes beforeBytes{state::serialize(before)},expectedBytes{state::serialize(expected)};
    if(beforeBytes.bytes!=expectedBytes.bytes||before.pending||before.publication)fail(ErrorCode::LocalChanges,"Decision changed; compare again");
    if(before.generation>std::numeric_limits<std::uint64_t>::max()-2)fail(ErrorCode::GenerationExhausted,"No finalization generation available");
    if(p.target.event.revision.sequence<=before.allocatedSequence)fail(ErrorCode::InvalidRecord,"Resolution must allocate a fresh event ID");
    checkStaging(c);
    auto next=before;next.schema=std::max(5u,before.schema);rememberHistory(next,h);
    if(newDecision){
        if(restoredArchive){if(*restoredArchive>=before.archives.size()||p.target.snapshot!=before.archives[*restoredArchive])fail(ErrorCode::InvalidRecord,"Restore selection changed");
            next.archives.erase(next.archives.begin()+*restoredArchive);}
        if(next.archives.size()==4)fail(ErrorCode::BackupLimit,"Keep or export existing protected conflict archives first");next.archives.push_back(*before.local);}
    else if(!next.resolution||next.resolution->tips!=h.graph().tips())fail(ErrorCode::Conflict,"Confirmed resolution tips changed");
    next.resolution=Resolution{h.graph().tips()};next.allocatedSequence=p.target.event.revision.sequence;next.publication=p;advance(next);
    checkPublicationRecordCapacity(next);
    // Refuse before publishing if the eventual import journal cannot fit.
    // Merge events are irreversible; capacity must cover every projection phase.
    if(p.target.snapshot!=*before.local){auto projection=publicationWitness(next);projection.head=p.target;projection.publication.reset();
        projection.resolution=Resolution{{p.target.event.revision.id}};projection.pending=Pending{p.target,next.archives.back(),Phase::Import};
        const SecretBytes preparedProjection{state::serialize(projection)};
        projection.local=p.target.snapshot;const SecretBytes checkpointProjection{state::serialize(projection)};}
    validateStorageRecord(next,c,keys->sync);verified(store,before,next,c,keys);return next;
}
void prepareResolutionProjection(const StorageConfiguration &c,const StorageKeysPtr &keys,const Store::Lease *owned){
    active(c,keys);auto ownership=!owned?acquireStorageSession(c):nullptr;
    state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);auto lease=store.lock();if(!lease)fail(ErrorCode::Busy,"Busy profile");
    const auto before=store.load();validateStorageRecord(before,c,keys->sync);
    if(!before.resolution||before.pending||before.publication||!before.head||before.archives.empty()||
       before.resolution->tips!=std::vector<std::string>{before.head->event.revision.id})fail(ErrorCode::PendingRecovery,"Resolution not ready");
    if(*before.local!=before.archives.back())fail(ErrorCode::LocalChanges,"New local edits require another explicit decision");
    auto next=before;
    if(*before.local==before.head->snapshot)next.resolution.reset();
    else next.pending=Pending{*before.head,before.archives.back(),Phase::Import};
    advance(next);verified(store,before,next,c,keys);
}
void discardArchive(const StorageConfiguration &c,const StorageKeysPtr &keys,const Record &expected,std::size_t index,const Store::Lease *owned){
    active(c,keys);auto ownership=!owned?acquireStorageSession(c):nullptr;
    state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);auto lease=store.lock();if(!lease)fail(ErrorCode::Busy,"Busy profile");
    const auto before=store.load();validateStorageRecord(before,c,keys->sync);
    const SecretBytes actual{state::serialize(before)},wanted{state::serialize(expected)};
    if(actual.bytes!=wanted.bytes||index>=before.archives.size()||
        (before.resolution&&index==before.archives.size()-1))
        fail(ErrorCode::PendingRecovery,"Archive decision changed");
    auto next=before;next.archives.erase(next.archives.begin()+index);advance(next);verified(store,before,next,c,keys);
}
std::optional<Publication> preparePublication(const StorageConfiguration &c,const StorageKeysPtr &keys,const Record &r,const events::AuthenticatedHistory &h){
    active(c,keys);validateStorageRecord(r,c,keys->sync);base(r,h);
    if(r.publication||r.resolution)fail(ErrorCode::PendingRecovery,"Finish reserved publication/resolution first");
    if(h.graph().tips()!=std::vector<std::string>{r.head->event.revision.id})fail(ErrorCode::LocalChanges,"Remote history advanced");
    if(*r.local==r.head->snapshot)return {};
    if(r.generation>std::numeric_limits<std::uint64_t>::max()-2||r.allocatedSequence==history::MaxSequence)
        fail(ErrorCode::GenerationExhausted,"Outbound counter exhausted");
    checkStaging(c);
    auto p=prepare(c,keys,*r.local,std::max(r.allocatedSequence+1,h.graph().nextSequence(c.profile.device.toStdString())),{r.head->event.revision.id});
    checkHistoryCapacity(h,p);return p;
}
Record reservePublication(const StorageConfiguration &c,const StorageKeysPtr &keys,const Record &expected,const Publication &publication,const Store::Lease *owned){
    active(c,keys);auto ownership=!owned?acquireStorageSession(c):nullptr;
    state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);auto lease=store.lock();if(!lease)fail(ErrorCode::Busy,"Busy profile");
    const auto before=store.load();validateStorageRecord(before,c,keys->sync);
    if(before.pending||before.publication||!before.head||!expected.head||expected.binding!=before.binding||expected.keyIdentity!=before.keyIdentity||
       !sameHead(before.head,expected.head)||before.allocatedSequence!=expected.allocatedSequence)
        fail(ErrorCode::PendingRecovery,"Publication base changed");
    if(before.generation>std::numeric_limits<std::uint64_t>::max()-2)fail(ErrorCode::GenerationExhausted,"No finalization generation available");
    if(publication.target.event.revision.sequence<=before.allocatedSequence||!expected.local||publication.target.snapshot!=*expected.local||
       publication.target.event.revision.parents!=std::vector<std::string>{before.head->event.revision.id})
        fail(ErrorCode::InvalidRecord,"Publication must reserve fresh identity, parents and captured contents");
    checkStaging(c);
    auto next=before;next.schema=std::max(4u,before.schema);next.allocatedSequence=publication.target.event.revision.sequence;next.publication=publication;advance(next);checkPublicationRecordCapacity(next);
    validateStorageRecord(next,c,keys->sync);verified(store,before,next,c,keys);return next;
}
void deliverPublication(const StorageConfiguration &c,const StorageKeysPtr &keys,const Record &r,bool reviewedContext){
    active(c,keys);validateStorageRecord(r,c,keys->sync);if(!r.publication)fail(ErrorCode::NoPending,"No reserved publication");
    storage::Directory directory(path(c.profile.transport));auto history=directory.scan(keys->sync);
    if(r.head)verifyAcceptedHead(r,history);
    if(reviewedContext){
        for(const auto &parent:r.publication->target.event.revision.parents)if(!history.graph().contains(parent))fail(ErrorCode::MissingHead,"Reserved parent missing");
    }else if(r.resolution){
        auto expectedTips=r.resolution->tips;
        if(history.graph().contains(r.publication->target.event.revision.id)){
            for(const auto &parent:r.publication->target.event.revision.parents)expectedTips.erase(std::remove(expectedTips.begin(),expectedTips.end(),parent),expectedTips.end());
            expectedTips.push_back(r.publication->target.event.revision.id);std::sort(expectedTips.begin(),expectedTips.end());
        }
        if(history.graph().tips()!=expectedTips)fail(ErrorCode::Conflict,"New conflict tips require another review");
    }else if(r.head)base(r,history);
    else if(history.graph().hasConflict()||(history.graph().size()&&!history.graph().contains(r.publication->target.event.revision.id)))
        fail(ErrorCode::Conflict,"History changed after Seed reservation");
    const auto &p=*r.publication;const auto &id=p.target.event.revision.id;
    checkHistoryCapacity(history,p);
    if(!history.graph().contains(id)){
        if(!reviewedContext&&r.head&&!r.resolution&&history.graph().tips()!=std::vector<std::string>{r.head->event.revision.id})fail(ErrorCode::Conflict,"History changed after reservation");
        directory.publish(keys->sync,{id,p.wire},{},staging(c));
    }
    directory.confirm(keys->sync,{id,p.wire});history=directory.scan(keys->sync);
    if(r.head)verifyAcceptedHead(r,history);
    if(!reviewedContext&&r.resolution){auto expected=r.resolution->tips;
        for(const auto &parent:p.target.event.revision.parents)expected.erase(std::remove(expected.begin(),expected.end(),parent),expected.end());
        expected.push_back(id);std::sort(expected.begin(),expected.end());
        if(history.graph().tips()!=expected)fail(ErrorCode::Conflict,"New conflict appeared after publication");}
    if((!reviewedContext&&!r.resolution&&history.graph().hasConflict())||!history.graph().contains(id))fail(ErrorCode::Conflict,"Publication conflict; intent retained");
    if(!reviewedContext&&!r.resolution&&!history.graph().isAncestor(id,history.graph().tips().front()))fail(ErrorCode::Rollback,"Publication not on current history");
}
Record acceptPublication(const StorageConfiguration &c,const StorageKeysPtr &keys,const Record &expected,const Store::Lease *owned){
    active(c,keys);auto ownership=!owned?acquireStorageSession(c):nullptr;
    state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);auto lease=store.lock();if(!lease)fail(ErrorCode::Busy,"Busy profile");
    const auto before=store.load();validateStorageRecord(before,c,keys->sync);
    if(!before.publication||!expected.publication||before.publication->wire!=expected.publication->wire||
        before.publication->target.event.revision.id!=expected.publication->target.event.revision.id||!sameHead(before.head,expected.head))
        fail(ErrorCode::PendingRecovery,"Reserved publication changed");
    auto next=before;next.head=before.publication->target;
    if(next.resolution){for(const auto &parent:before.publication->target.event.revision.parents)
        next.resolution->tips.erase(std::remove(next.resolution->tips.begin(),next.resolution->tips.end(),parent),next.resolution->tips.end());
        next.resolution->tips.push_back(next.head->event.revision.id);std::sort(next.resolution->tips.begin(),next.resolution->tips.end());}
    next.schema=std::max(6u,next.schema);next.witnessed.emplace(next.head->event.revision.id,eventFingerprint(next.head->event));
    next.publication.reset();advance(next);verified(store,before,next,c,keys);return next;
}
transaction::Result publishChanges(const StorageConfiguration &c,const StorageKeysPtr &keys,bool retry,const Store::Lease *ownedSession){
    active(c,keys);
    return std::async(std::launch::async,[&]{
        auto ownership=!ownedSession?acquireStorageSession(c):nullptr;const auto session=ownedSession?ownedSession:ownership.get();
        auto record=readStorage(c,keys->local,keys->sync);
        if(!record.head)fail(ErrorCode::NotJoined,"Explicit Seed/Join required");
        if(!record.publication){
            if(retry)fail(ErrorCode::NoPending,"No reserved publication");
            storage::Directory directory(path(c.profile.transport));const auto h=directory.scan(keys->sync);
            record=observeHistory(c,keys,h,session);
            const auto planned=preparePublication(c,keys,record,h);if(!planned)return Result::UpToDate;
            record=reservePublication(c,keys,record,*planned,session);
        }else if(!retry)fail(ErrorCode::PendingRecovery,"Recover exact publication first");
        deliverPublication(c,keys,record);acceptPublication(c,keys,record,session);return Result::Applied;
    }).get();
}
}
