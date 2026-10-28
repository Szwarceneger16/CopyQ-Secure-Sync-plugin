// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "standalone_storage.h"
#include <filesystem>
namespace cqs::native {
enum class HistoryTransitionMode { Rekey, Compact, Join };
struct HistoryTransitionResult { Profile profile; StorageKeysPtr keys; };
// Source contents remain encrypted at their original path, under a retired
// namespace. Cached keys from another process cannot reopen the active profile.
StorageConfiguration archivedTransitionSource(const StorageConfiguration &,const Profile &successor);
StorageConfiguration historyTransitionSourceConfiguration(const StorageConfiguration &,const crypto::Bytes &password,const std::filesystem::path &journal);
// Caller checkpoints and ordinarily unloads the GUI tab. All I/O runs on a
// worker under both profile sessions. Journal, state and vault are private,
// disjoint existing directories; no history or key file is removed/overwritten.
HistoryTransitionResult startHistoryTransition(const StorageConfiguration &,Profile target,
    const crypto::Bytes &password,const std::filesystem::path &journal,HistoryTransitionMode,
    const crypto::Bytes &joinKey={},RowProtection protection={},std::function<void()> check={});
HistoryTransitionResult resumeHistoryTransition(const StorageConfiguration &,const crypto::Bytes &password,
    const std::filesystem::path &journal,RowProtection protection={},std::function<void()> check={});
void cancelHistoryTransition(const StorageConfiguration &,const crypto::Bytes &password,const std::filesystem::path &journal,bool sourceStillActive=false);
// After activation replace journal keys with a receipt. Before activation the
// journal must retain them so interruption cannot orphan the successor vault.
void finishHistoryTransition(const StorageConfiguration &active,const crypto::Bytes &vaultPassword,
    const crypto::Bytes &journalPassword,const std::filesystem::path &journal);
}
