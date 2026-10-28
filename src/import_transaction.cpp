// SPDX-License-Identifier: GPL-3.0-or-later
#include "import_transaction.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace cqs::transaction {
namespace {
[[noreturn]] void fail(ErrorCode code, const char *text) { throw Error(code, text); }
bool sameEvent(const events::Event &a, const events::Event &b) {
    return a.revision.id == b.revision.id && a.revision.device == b.revision.device &&
           a.revision.sequence == b.revision.sequence && a.revision.parents == b.revision.parents &&
           a.items == b.items; // immutable REMOTE payload, never locally repacked bytes
}
void reserveGenerations(const Record &record, unsigned count) {
    if (record.generation > std::numeric_limits<std::uint64_t>::max() - count)
        fail(ErrorCode::GenerationExhausted, "Private state generation exhausted");
}
void checkBinding(const std::string &binding) {
    if (binding.empty() || binding.size() > 128 ||
        !std::all_of(binding.begin(), binding.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '_';
        }))
        fail(ErrorCode::WrongBinding, "Invalid private state binding");
}
} // namespace

crypto::Bytes eventFingerprint(const events::Event &event) { return events::fingerprint(event); }
void verifyHistory(const Record &record,const events::AuthenticatedHistory &history) {
    std::map<std::string,const events::Event *> available;
    for(const auto &event:history.events())available.emplace(event.revision.id,&event);
    if(record.head){const auto found=available.find(record.head->event.revision.id);
        if(found==available.end())fail(ErrorCode::MissingHead,"Accepted head missing from delivered history");
        if(!sameEvent(record.head->event,*found->second))fail(ErrorCode::Equivocation,"Accepted head changed");}
    if(record.publication){const auto found=available.find(record.publication->target.event.revision.id);
        if(found!=available.end()&&!sameEvent(record.publication->target.event,*found->second))
            fail(ErrorCode::Equivocation,"Reserved publication content changed");}
    for(const auto &entry:record.witnessed){const auto found=available.find(entry.first);
        if(found==available.end())fail(ErrorCode::MissingHead,"Previously witnessed event missing; restore delivered history");
        if(history.fingerprints().at(entry.first)!=entry.second)fail(ErrorCode::Equivocation,"Previously witnessed event changed");}
}
bool rememberHistory(Record &record,const events::AuthenticatedHistory &history) {
    verifyHistory(record,history);
    // Historical schema-1 adapters do not own authoritative local storage.
    if(record.schema<2)return false;
    bool changed=false;
    for(const auto &event:history.events())if(!record.witnessed.count(event.revision.id)){
        record.witnessed.emplace(event.revision.id,history.fingerprints().at(event.revision.id));changed=true;}
    if(changed)record.schema=std::max(6u,record.schema);
    return changed;
}

Importer::Importer(std::string binding, Store &store, Clipboard &clipboard, Limits limits)
    : binding_(std::move(binding)), store_(store), clipboard_(clipboard), limits_(limits) {
    checkBinding(binding_);
    const Limits ceiling;
    if (limits.items > ceiling.items || !limits.formatsPerItem ||
        limits.formatsPerItem > ceiling.formatsPerItem || !limits.mimeNameBytes ||
        limits.mimeNameBytes > ceiling.mimeNameBytes || !limits.snapshotBytes ||
        limits.snapshotBytes > ceiling.snapshotBytes)
        fail(ErrorCode::InvalidLimits, "Invalid import resource limits");
}
std::unique_ptr<Store::Lease> Importer::lock() {
    auto lease = store_.lock();
    if (!lease) fail(ErrorCode::Busy, "Another operation holds the private state lease");
    return lease;
}
void Importer::validateSnapshot(const Snapshot &snapshot) const {
    if (snapshot.size() > limits_.items)
        fail(ErrorCode::InvalidRecord, "Snapshot item limit exceeded");
    std::size_t total = 0;
    auto account = [&](std::size_t n) {
        if (n > limits_.snapshotBytes - total)
            fail(ErrorCode::InvalidRecord, "Snapshot byte limit exceeded");
        total += n;
    };
    for (const auto &item : snapshot) {
        if (item.size() > limits_.formatsPerItem)
            fail(ErrorCode::InvalidRecord, "Snapshot MIME limit exceeded");
        for (const auto &field : item) {
            if (field.first.empty() || field.first.size() > limits_.mimeNameBytes ||
                !std::all_of(field.first.begin(), field.first.end(), [](unsigned char c) {
                    return c >= 0x21 && c <= 0x7e;
                }))
                fail(ErrorCode::InvalidRecord, "Invalid snapshot MIME name");
            account(field.first.size());
            account(field.second.size());
        }
    }
}
void Importer::validateHead(const Head &head) {
    history::validateRevision(head.event.revision);
    if (head.event.items.size() > limits_.items)
        fail(ErrorCode::InvalidRecord, "Stored event item limit exceeded");
    std::size_t packedBytes = 0;
    for (const auto &item : head.event.items) {
        if (item.size() > events::Limits{}.plaintextBytes - packedBytes)
            fail(ErrorCode::InvalidRecord, "Stored packed event exceeds limit");
        packedBytes += item.size();
    }
    validateSnapshot(head.snapshot);
    // A private record is authenticated by Store, but also verify internal
    // consistency. Recovery must not trust a backup/target paired with the wrong
    // event by a buggy adapter or a mismatched codec version.
    const auto decoded = clipboard_.decode(head.event.items, limits_);
    validateSnapshot(decoded);
    if (decoded.size() != head.event.items.size() || decoded != head.snapshot)
        fail(ErrorCode::InvalidRecord, "Stored event disagrees with its MIME snapshot");
}
Record Importer::load() {
    auto r = store_.load();
    if (r.binding != binding_) fail(ErrorCode::WrongBinding, "Private state belongs to another binding");
    if (r.schema < 1 || r.schema > 6) fail(ErrorCode::InvalidRecord, "Unsupported private state schema");
    if(r.publication)fail(ErrorCode::PendingRecovery,"Finish pending publication first");
    if (r.schema >= 2) {
        if(!r.local || r.keyIdentity.size()!=64 || !std::all_of(r.keyIdentity.begin(),r.keyIdentity.end(),
            [](unsigned char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}))
            fail(ErrorCode::InvalidRecord,"Invalid unified state context");
        validateSnapshot(*r.local);
    } else if(r.local || !r.keyIdentity.empty())fail(ErrorCode::InvalidRecord,"Legacy state carries unified fields");
    if (r.head) validateHead(*r.head);
    if (r.pending) {
        if (r.pending->phase != Phase::Import && r.pending->phase != Phase::Restore)
            fail(ErrorCode::InvalidRecord, "Unknown pending transaction phase");
        validateHead(r.pending->target);
        validateSnapshot(r.pending->original);
        const Snapshot empty;
        if (r.pending->original != (r.head ? r.head->snapshot : empty) &&
            (r.head || !r.preserved || r.pending->original!=*r.preserved) &&
            (!r.resolution || r.archives.empty() || r.pending->original!=r.archives.back()))
            fail(ErrorCode::InvalidRecord, "Pending backup disagrees with the previous checkpoint");
        if (r.head && !r.resolution && r.pending->target.event.revision.id == r.head->event.revision.id)
            fail(ErrorCode::InvalidRecord, "Pending import cannot reuse the current event ID");
    }
    return r;
}
void Importer::save(Record &record, Record &&replacement) {
    reserveGenerations(record, 1);
    replacement.generation = record.generation + 1;
    store_.commit(record, replacement);
    // If commit throws after persisting, do not assume it did not happen.
    // Stop here; the next explicit operation reloads the authoritative record.
    record = std::move(replacement);
}
void Importer::persist(Record &record, View view, const Snapshot &desired) {
    if (view.snapshot != desired) view = clipboard_.replace(view, desired);
    validateSnapshot(view.snapshot);
    if (view.snapshot != desired)
        fail(ErrorCode::VerificationFailed, "Clipboard replacement verification failed");
    if(record.schema >= 2 && *record.local != desired) {
        auto checkpoint = record; checkpoint.local = desired;
        save(record, std::move(checkpoint)); // Same AEAD record retains head + recovery intent.
    }
    const auto durable = clipboard_.persist(view, limits_);
    validateSnapshot(durable);
    if (durable != desired)
        fail(ErrorCode::VerificationFailed, "Persisted clipboard differs from requested snapshot");
}

Result Importer::importTip(const events::AuthenticatedHistory &history, ImportMode mode) {
    auto lease = lock();
    auto record = load();
    if (record.pending||record.resolution) fail(ErrorCode::PendingRecovery, "Resolve the pending transaction first");
    if (mode != ImportMode::Join && mode != ImportMode::FastForward && mode != ImportMode::JoinPreserve)
        fail(ErrorCode::InvalidRecord, "Unknown import mode");
    if (mode != ImportMode::FastForward && record.head)
        fail(ErrorCode::AlreadyJoined, "Device is already joined");
    if (mode == ImportMode::FastForward && !record.head)
        fail(ErrorCode::NotJoined, "Explicit join is required");
    const auto &graph = history.graph();
    verifyHistory(record,history);
    if (graph.tips().empty()) fail(ErrorCode::NoRemote, "No remote event to import");
    if (graph.hasConflict()) {
        auto observed=record;if(rememberHistory(observed,history))save(record,std::move(observed));
        fail(ErrorCode::Conflict, "Multiple history tips require explicit resolution");
    }
    const auto &tip = graph.tips().front();
    if (record.head && !graph.isAncestor(record.head->event.revision.id, tip))
        fail(ErrorCode::Rollback, "Remote tip does not extend the local head");
    const auto current = clipboard_.capture(limits_);
    validateSnapshot(current.snapshot);
    if(record.local && *record.local != current.snapshot)
        fail(ErrorCode::LocalChanges,"Clipboard disagrees with authoritative local contents");
    const Snapshot empty;
    if (mode != ImportMode::JoinPreserve && current.snapshot != (record.head ? record.head->snapshot : empty))
        fail(ErrorCode::LocalChanges, "Local changes must be preserved before an import");
    if (record.head && tip == record.head->event.revision.id) {
        auto observed=record;if(rememberHistory(observed,history))save(record,std::move(observed));
        return Result::UpToDate;
    }
    const auto targetEvent = std::find_if(history.events().begin(), history.events().end(),
        [&](const events::Event &e) { return e.revision.id == tip; });
    if (targetEvent == history.events().end()) fail(ErrorCode::InvalidRecord, "Authenticated tip unavailable");
    Head target{*targetEvent, clipboard_.decode(targetEvent->items, limits_)};
    validateHead(target);
    clipboard_.preflight(current,target.snapshot);
    // Reserve prepare + optional rollback decision + completion generations.
    reserveGenerations(record, record.schema >= 2 ? 4 : 3);
    auto prepared = record;prepared.generation=record.generation+1;rememberHistory(prepared,history);
    if(mode==ImportMode::JoinPreserve){
        if(record.schema<2 || (record.preserved && *record.preserved!=current.snapshot))fail(ErrorCode::InvalidRecord,"Preserved Join requires unused native backup");
        prepared.schema=std::max(3u,prepared.schema);prepared.preserved=current.snapshot;
    }
    prepared.pending = Pending{target, current.snapshot, Phase::Import};
    store_.checkCapacity(prepared);
    if(prepared.local){auto checkpoint=prepared;checkpoint.local=target.snapshot;store_.checkCapacity(checkpoint);}
    save(record, std::move(prepared)); // durable backup/journal BEFORE touching CopyQ
    persist(record, current, target.snapshot);
    auto committed = record; committed.head = std::move(target); committed.pending.reset();committed.resolution.reset();
    save(record, std::move(committed)); // head and journal retirement are ONE commit
    return Result::Applied;
}

Result Importer::recover(Recovery action) {
    auto lease = lock();
    auto record = load();
    if (!record.pending) fail(ErrorCode::NoPending, "No pending import to recover");
    const bool preserve=action==Recovery::PreserveAndRetry||action==Recovery::PreserveAndRestore;
    if(action==Recovery::PreserveAndRetry)action=Recovery::RetryImport;
    if(action==Recovery::PreserveAndRestore)action=Recovery::RestoreOriginal;
    if (action != Recovery::AcceptTarget && action != Recovery::RetryImport && action != Recovery::RestoreOriginal)
        fail(ErrorCode::InvalidRecord, "Unknown recovery action");
    const auto view = clipboard_.capture(limits_);
    validateSnapshot(view.snapshot);
    if(record.local && *record.local != view.snapshot)
        fail(ErrorCode::LocalChanges,"Clipboard disagrees with authoritative recovery contents");
    const auto pending = *record.pending;
    if(action!=Recovery::RestoreOriginal&&pending.phase!=Phase::Import)
        fail(ErrorCode::WrongPhase,"An interrupted restore must finish as a restore");
    if (view.snapshot != pending.original && view.snapshot != pending.target.snapshot) {
        if(!preserve||record.schema<2)fail(ErrorCode::LocalChanges,"Use explicit preserve-and-recover for divergent local edits");
        // Preflight all model/protection checks and reserve every generation
        // before committing a backup. Never change the journal's original.
        clipboard_.preflight(view,action==Recovery::RestoreOriginal?pending.original:pending.target.snapshot);
        reserveGenerations(record,4);
        if(std::find(record.archives.begin(),record.archives.end(),view.snapshot)==record.archives.end()){
            if(record.archives.size()==4)fail(ErrorCode::BackupLimit,"Protected backup capacity reached; no data discarded");
            auto preserved=record;preserved.schema=std::max(5u,record.schema);
            // Keep archive.back() as the active resolution's original backup.
            preserved.archives.insert(preserved.archives.begin(),view.snapshot);
            store_.checkCapacity(preserved);
            auto checkpoint=preserved;checkpoint.local=action==Recovery::RestoreOriginal?pending.original:pending.target.snapshot;
            store_.checkCapacity(checkpoint);
            save(record,std::move(preserved)); // durable before any model replacement
        }
    }
    if(record.local){auto checkpoint=record;checkpoint.local=action==Recovery::RestoreOriginal?pending.original:pending.target.snapshot;
        store_.checkCapacity(checkpoint);}
    if (action == Recovery::RestoreOriginal) {
        clipboard_.preflight(view,pending.original);
        reserveGenerations(record, (pending.phase == Phase::Restore ? 1 : 2) + (record.schema >= 2 ? 1 : 0));
        if (pending.phase != Phase::Restore) {
            auto restoring = record;
            restoring.pending->phase = Phase::Restore;
            save(record, std::move(restoring)); // persist rollback intent before it starts
        }
        const auto original = record.pending->original; // persist can replace record.
        persist(record, view, original);
        // Keep the previous head, including an unjoined state.
        auto restored = record; restored.pending.reset();restored.resolution.reset();
        save(record, std::move(restored));
        return Result::Restored;
    }
    if (pending.phase != Phase::Import)
        fail(ErrorCode::WrongPhase, "An interrupted restore must be finished as a restore");
    if (action == Recovery::AcceptTarget && view.snapshot != pending.target.snapshot)
        fail(ErrorCode::VerificationFailed, "Target is not present; explicit retry or restore is required");
    reserveGenerations(record, record.schema >= 2 ? 2 : 1);
    const auto targetSnapshot = pending.target.snapshot;
    clipboard_.preflight(view,targetSnapshot);
    persist(record, view, targetSnapshot);
    auto committed = record; committed.head = record.pending->target; committed.pending.reset();committed.resolution.reset();
    save(record, std::move(committed));
    return Result::Applied;
}
} // namespace cqs::transaction
