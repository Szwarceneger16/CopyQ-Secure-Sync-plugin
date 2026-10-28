// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "crypto.h"
#include "profile.h"
#include "import_transaction.h"
#include <memory>
#include <filesystem>
namespace cqs::native {
struct StorageConfiguration;
struct StorageKeys {
    crypto::Bytes local, sync, pending;
    bool retiring = false, initializing = false, suspended = false;
    ~StorageKeys() { crypto::wipe(local); crypto::wipe(sync); crypto::wipe(pending); }
};
using StorageKeysPtr = std::shared_ptr<StorageKeys>;
StorageKeysPtr createVault(const StorageConfiguration &, const crypto::Bytes &password,
                          const crypto::Bytes &importedSync = {}, bool initializing = false);
StorageKeysPtr finishStorageSetup(const StorageConfiguration &, const crypto::Bytes &password,const transaction::Store::Lease *ownedSession = nullptr);
StorageKeysPtr unlockVault(const StorageConfiguration &, const crypto::Bytes &password);
void changeVaultPassword(const StorageConfiguration &, const crypto::Bytes &oldPassword, const crypto::Bytes &newPassword);
StorageKeysPtr rotateStorageKey(const StorageConfiguration &, const crypto::Bytes &password,const transaction::Store::Lease *ownedSession = nullptr);
StorageKeysPtr setVaultRetirement(const StorageConfiguration &, const crypto::Bytes &password, bool retiring,const transaction::Store::Lease *ownedSession = nullptr);
void backupVault(const StorageConfiguration &, const crypto::Bytes &password, const std::filesystem::path &destination);
void restoreMissingVault(const StorageConfiguration &, const crypto::Bytes &password, const std::filesystem::path &backup,const QString &alternateDataBinding = {});
void exportSyncKey(const StorageConfiguration &, const crypto::Bytes &password, const crypto::Bytes &transferPassword,
                   const std::filesystem::path &destination);
StorageKeysPtr importSyncVault(const StorageConfiguration &, const crypto::Bytes &password, const crypto::Bytes &transferPassword,
                              const std::filesystem::path &source);
StorageKeysPtr migrateLegacyStorage(const StorageConfiguration &, const crypto::Bytes &password);
// History transitions provision exact journaled keys, never adopt an unrelated vault.
StorageKeysPtr provisionTransitionVault(const StorageConfiguration &,const crypto::Bytes &,const StorageKeysPtr &);
StorageKeysPtr suspendVault(const StorageConfiguration &,const crypto::Bytes &,bool,const transaction::Store::Lease *);
crypto::Bytes readTransferredSyncKey(const StorageConfiguration &,const crypto::Bytes &,const std::filesystem::path &);
void repairMissingVault(const StorageConfiguration &, const StorageKeysPtr &unlocked, const crypto::Bytes &newPassword,const QString &alternateDataBinding = {});
}
