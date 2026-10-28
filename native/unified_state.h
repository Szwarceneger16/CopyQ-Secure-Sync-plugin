// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "standalone_storage.h"
#include <QAbstractListModel>
namespace cqs::native {
std::string encryptHistoryEvent(const events::Event &,const crypto::Bytes &);
class GuiClipboard;
transaction::Result importWorkerHistory(const StorageConfiguration &,const StorageKeysPtr &,const events::AuthenticatedHistory &,GuiClipboard *,
    bool recovery,transaction::Recovery,RowProtection,const std::function<void()> &check);
enum class StateAction { Join, FastForward, AcceptTarget, RetryImport, RestoreOriginal, PreserveAndRetry, PreserveAndRestore, Seed, RetrySeed, JoinPreserve, RestorePreserved, Publish, RetryPublication, Sync };
transaction::Record observeHistory(const StorageConfiguration &,const StorageKeysPtr &,const events::AuthenticatedHistory &,const transaction::Store::Lease *);
void checkHistoryCapacity(const events::AuthenticatedHistory &,const transaction::Publication &,std::size_t additionalEvents=1,events::Limits limits={});
void verifyAcceptedHead(const transaction::Record &,const events::AuthenticatedHistory &);
// Staged publication: only transport inspection/delivery runs in background.
// Reservation/finalization are serialized with GUI saves and preserve newer local data.
transaction::Publication prepareResolution(const StorageConfiguration &,const StorageKeysPtr &,const transaction::Record &,const events::AuthenticatedHistory &,const transaction::Snapshot &);
transaction::Record reserveResolution(const StorageConfiguration &,const StorageKeysPtr &,const transaction::Record &,const events::AuthenticatedHistory &,const transaction::Publication &,bool newDecision,const transaction::Store::Lease *,std::optional<std::size_t> restoredArchive={});
void prepareResolutionProjection(const StorageConfiguration &,const StorageKeysPtr &,const transaction::Store::Lease *);
void discardArchive(const StorageConfiguration &,const StorageKeysPtr &,const transaction::Record &,std::size_t,const transaction::Store::Lease *);
std::optional<transaction::Publication> preparePublication(const StorageConfiguration &,const StorageKeysPtr &,const transaction::Record &,const events::AuthenticatedHistory &);
transaction::Record reservePublication(const StorageConfiguration &,const StorageKeysPtr &,const transaction::Record &,const transaction::Publication &,const transaction::Store::Lease *);
void deliverPublication(const StorageConfiguration &,const StorageKeysPtr &,const transaction::Record &,bool reviewedContext=false);
transaction::Record acceptPublication(const StorageConfiguration &,const StorageKeysPtr &,const transaction::Record &,const transaction::Store::Lease *);
transaction::Result importDetachedHistory(const StorageConfiguration &,const StorageKeysPtr &,const events::AuthenticatedHistory &,bool recovery=false,transaction::Recovery recoveryAction=transaction::Recovery::RetryImport,RowProtection protection={});
transaction::Result publishChanges(const StorageConfiguration &, const StorageKeysPtr &, bool retry,const transaction::Store::Lease *ownedSession = nullptr);
transaction::Result seedHistory(const StorageConfiguration &, const StorageKeysPtr &, bool retry,const transaction::Store::Lease *ownedSession = nullptr);
transaction::Result adoptPackedSnapshot(const StorageConfiguration &,const StorageKeysPtr &,const std::vector<std::string> &,const transaction::Store::Lease *ownedSession = nullptr);
// Disk-only operation on authoritative contents. Caller must first checkpoint
// and ordinarily unload the bound tab; it must not replace a loaded GUI model.
transaction::Result runStateAction(const StorageConfiguration &, const StorageKeysPtr &, StateAction,const transaction::Store::Lease *ownedSession = nullptr,RowProtection protection={},std::function<void()> check={});
}
