// SPDX-License-Identifier: GPL-3.0-or-later
#include "unified_state.h"
#include "state_store.h"
#include "storage.h"
#include "packed_items.h"
#include "model_clipboard.h"
#include "gui_clipboard.h"
#include <future>
#include <algorithm>
#include <QScopeGuard>

namespace cqs::native {
namespace {
using namespace transaction;
struct SecretBytes {crypto::Bytes bytes;~SecretBytes(){crypto::wipe(bytes);}};
std::filesystem::path path(const QString &s) {
#ifdef Q_OS_WIN
    return std::filesystem::path(s.toStdWString());
#else
    return std::filesystem::u8path(s.toUtf8().toStdString());
#endif
}
class BoundStore final : public Store {
public:
    BoundStore(state::FileStore &file,const StorageConfiguration &c,const crypto::Bytes &sync,std::function<void()> check={})
        : file_(file),configuration_(c),sync_(sync),check_(std::move(check)) {}
    std::unique_ptr<Lease> lock() override { check();return file_.lock(); }
    Record load() override {
        check();auto r=file_.load();validate(r);return r;
    }
    void checkCapacity(const Record &record) override {
        check();validate(record);const SecretBytes bounded{state::serialize(record)};
    }
    void commit(const Record &expected,const Record &next) override {
        check();validate(expected);validate(next);file_.commit(expected,next);
    }
private:
    void check(){if(check_)check_();}
    void validate(const Record &r) {
        validateStorageRecord(r,configuration_,sync_);
        if(r.schema<2 || r.schema>6)throw state::Error(state::ErrorCode::InvalidRecord,"Explicit state migration required");
    }
    state::FileStore &file_;
    const StorageConfiguration &configuration_;
    const crypto::Bytes &sync_;
    std::function<void()> check_;
};
// No CopyQ/GUI object is touched here. The one leased encrypted record is the
// source of local contents and the durability barrier, including pending state.
class DetachedContents final : public Clipboard {
public:
    explicit DetachedContents(Store &store,RowProtection protection):store_(store),protection_(std::move(protection)) {}
    void preflight(const View &expected,const Snapshot &desired) override { match(expected);protection_.validate(expected.snapshot,desired); }
    Snapshot decode(const std::vector<std::string> &items,Limits limits) override {return packed::decode(items,limits);}
    View capture(Limits limits) override {
        view_.snapshot=*store_.load().local;packed::validateSnapshot(view_.snapshot,limits);return view_;
    }
    View replace(const View &expected,const Snapshot &desired) override {
        preflight(expected,desired);packed::validateSnapshot(desired,{});view_.snapshot=desired;++view_.epoch;return view_;
    }
    Snapshot persist(const View &expected,Limits limits) override {
        match(expected);const auto actual=*store_.load().local;packed::validateSnapshot(actual,limits);
        if(actual!=expected.snapshot)throw Error(ErrorCode::VerificationFailed,"Unified durable readback mismatch");
        return actual;
    }
private:
    void match(const View &expected) {
        if(expected.epoch!=view_.epoch||expected.snapshot!=view_.snapshot)
            throw Error(ErrorCode::LocalChanges,"Detached contents changed");
    }
    Store &store_;View view_;RowProtection protection_;
};
}
transaction::Result runStateAction(const StorageConfiguration &c,const StorageKeysPtr &keys,StateAction action,const transaction::Store::Lease *ownedSession,RowProtection protection,std::function<void()> check) {
    if(!keys||keys->local.size()!=32||keys->sync.size()!=32||keys->initializing||keys->retiring||keys->suspended||!keys->pending.empty()||
        !c.profile.standaloneStorage||!validateProfile(c.profile,false).isEmpty())
        throw crypto::Error("State action requires an active applied profile");
    return std::async(std::launch::async,[c,keys,action,ownedSession,protection,check]() mutable {
        if(check)check();
        if(action==StateAction::Seed||action==StateAction::RetrySeed)return seedHistory(c,keys,action==StateAction::RetrySeed,ownedSession);
        auto ownership=!ownedSession?acquireStorageSession(c):nullptr;
        const auto session=ownedSession?ownedSession:ownership.get();
        if(action==StateAction::Publish||action==StateAction::RetryPublication)
            return publishChanges(c,keys,action==StateAction::RetryPublication,session);
        if(action==StateAction::Sync){
            const auto r=readStorage(c,keys->local,keys->sync);
            if(r.pending||r.publication)throw Error(ErrorCode::PendingRecovery,"Explicit recovery required");
            if(!r.head)throw Error(ErrorCode::NotJoined,"Explicit Seed/Join required");
            if(*r.local!=r.head->snapshot)return publishChanges(c,keys,false,session);
            action=StateAction::FastForward;
        }
        state::FileStore file(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);
        BoundStore store(file,c,keys->sync,check);DetachedContents contents(store,protection);
        Importer importer(c.binding.toStdString(),store,contents,storageLimits());
        switch(action) {
        case StateAction::Join:
        case StateAction::JoinPreserve:
        case StateAction::FastForward: {
            storage::Directory directory(path(c.profile.transport));
            const auto history=directory.scan(keys->sync);
            if(action!=StateAction::FastForward)for(const auto &e:history.events())
                if(e.revision.device==c.profile.device.toStdString())throw Error(ErrorCode::DeviceInUse,"Use a new device ID when joining existing history");
            return importer.importTip(history,action==StateAction::Join?ImportMode::Join:action==StateAction::JoinPreserve?ImportMode::JoinPreserve:ImportMode::FastForward);
        }
        case StateAction::RestorePreserved:{
            auto lease=store.lock();if(!lease)throw Error(ErrorCode::Busy,"Busy profile");
            const auto before=store.load();if(before.pending||before.publication||!before.preserved)
                throw Error(ErrorCode::PendingRecovery,"No available preserved contents or unfinished operation");
            if(before.local==before.preserved)return Result::UpToDate;
            if(before.head ? *before.local!=before.head->snapshot : !before.local->empty())
                throw Error(ErrorCode::LocalChanges,"Preserve newer local edits before restoring the backup");
            protection.validate(*before.local,*before.preserved);
            auto next=before;++next.generation;next.local=before.preserved;store.commit(before,next);
            const auto actual=store.load();const SecretBytes actualBytes{state::serialize(actual)},wantedBytes{state::serialize(next)};
            if(actualBytes.bytes!=wantedBytes.bytes)throw Error(ErrorCode::VerificationFailed,"Restoration readback differs");
            return Result::Restored;
        }
        case StateAction::AcceptTarget:return importer.recover(Recovery::AcceptTarget);
        case StateAction::RetryImport:return importer.recover(Recovery::RetryImport);
        case StateAction::RestoreOriginal:return importer.recover(Recovery::RestoreOriginal);
        case StateAction::PreserveAndRetry:return importer.recover(Recovery::PreserveAndRetry);
        case StateAction::PreserveAndRestore:return importer.recover(Recovery::PreserveAndRestore);
        case StateAction::Seed:case StateAction::RetrySeed:case StateAction::Publish:case StateAction::RetryPublication:case StateAction::Sync:break;
        }
        throw crypto::Error("Unknown state action");
    }).get();
}
transaction::Result importWorkerHistory(const StorageConfiguration &c,const StorageKeysPtr &keys,const events::AuthenticatedHistory &history,GuiClipboard *gui,
    bool recovery,Recovery action,RowProtection protection,const std::function<void()> &check){
    check();state::FileStore file(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);
    BoundStore store(file,c,keys->sync,check);DetachedContents detached(store,std::move(protection));
    if(gui)gui->readDurable=[&]{return *store.load().local;};
    const auto clear=qScopeGuard([&]{if(gui)gui->readDurable={};});
    Importer importer(c.binding.toStdString(),store,gui?static_cast<Clipboard &>(*gui):static_cast<Clipboard &>(detached),storageLimits());
    return recovery?importer.recover(action):importer.importTip(history,ImportMode::FastForward);
}
transaction::Result importDetachedHistory(const StorageConfiguration &c,const StorageKeysPtr &keys,const events::AuthenticatedHistory &history,bool recovery,Recovery recoveryAction,RowProtection protection){
    state::FileStore file(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);BoundStore store(file,c,keys->sync);DetachedContents contents(store,protection);
    Importer importer(c.binding.toStdString(),store,contents,storageLimits());return recovery?importer.recover(recoveryAction):importer.importTip(history,ImportMode::FastForward);
}
transaction::Result adoptPackedSnapshot(const StorageConfiguration &c,const StorageKeysPtr &keys,const std::vector<std::string> &packedItems,const transaction::Store::Lease *ownedSession){
    if(!keys||keys->initializing||keys->retiring||keys->suspended||!keys->pending.empty()||!c.profile.standaloneStorage||
       !validateProfile(c.profile,false).isEmpty())throw crypto::Error("Adoption requires an active profile");
    const auto snapshot=packed::decode(packedItems,storageLimits());
    return std::async(std::launch::async,[&]{auto ownership=!ownedSession?acquireStorageSession(c):nullptr;
        state::FileStore store(path(c.profile.stateDirectory),c.binding.toStdString(),keys->local);auto lease=store.lock();
        if(!lease)throw Error(ErrorCode::Busy,"Busy profile");
        const auto before=store.load();validateStorageRecord(before,c,keys->sync);
        if(before.schema<2||before.head||before.pending||before.publication||before.allocatedSequence)
            throw Error(ErrorCode::AlreadyJoined,"Adoption requires an unjoined unused profile");
        if(before.local==snapshot&&before.preserved==snapshot)return Result::UpToDate;
        if(!before.local->empty()||before.preserved)throw Error(ErrorCode::LocalChanges,"Adoption never overwrites existing local data or backup");
        auto next=before;next.schema=std::max(3u,before.schema);++next.generation;next.local=snapshot;next.preserved=snapshot;
        store.commit(before,next);const auto actual=store.load();validateStorageRecord(actual,c,keys->sync);
        const SecretBytes actualBytes{state::serialize(actual)},wantedBytes{state::serialize(next)};
        if(actualBytes.bytes!=wantedBytes.bytes)throw Error(ErrorCode::VerificationFailed,"Adoption durable readback differs");
        return Result::Applied;
    }).get();
}
}
