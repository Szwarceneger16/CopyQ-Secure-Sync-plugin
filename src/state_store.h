// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "state_record.h"
#include <filesystem>

namespace cqs::state {
enum class LeaseKind { Record, Session };
// Concrete transaction::Store adapter; CMake selects Linux or Windows/NTFS.
// Windows permissions, sharing and durability limits: docs/STATE-WINDOWS.md.
// An existing private directory, outside the transport, must be provisioned by
// setup. Constructing/loading never initializes or resets a missing record.
// Run disk operations in the plugin worker, never on the GUI thread. A lease is
// tied to its acquiring thread/process; contending public operations fail fast.
// Destruction waits for an in-flight call if the caller releases a lease from
// another thread. Do not fork concurrently with an active call.
class FileStore final : public transaction::Store {
public:
    FileStore(const std::filesystem::path &privateDirectory, std::string binding,
              const crypto::Bytes &key, Limits limits = {}, Protection protection = Protection::Key, LeaseKind kind = LeaseKind::Record);
    ~FileStore() override;
    FileStore(const FileStore &) = delete;
    FileStore &operator=(const FileStore &) = delete;
    std::unique_ptr<Lease> lock() override;
    transaction::Record load() override;
    void commit(const transaction::Record &expected, const transaction::Record &replacement) override;
    // Explicit create-only provisioning, under a lease. Initial state is empty,
    // unjoined, generation 0. Never used automatically after a failed load.
    void initialize();
    // Explicit create-only provisioning of a fully formed record (e.g. key vault).
    void initialize(const transaction::Record &initial);
    // Validate create-only setup under the same lease before provisioning keys.
    void checkInitializable();
    // Atomic whole-record CAS + generation increment, with a new key/password or
    // binding. Ambiguous failures require reopening with old/new credentials.
    void transition(const transaction::Record &expected, const transaction::Record &replacement,
                    const crypto::Bytes &newSecret, Protection newProtection = Protection::Key);
    static constexpr const char *RecordName = "record-v1.cqr";
    static constexpr const char *LockName = ".cqs-state.lock";
    static constexpr const char *SessionLockName = ".cqs-session.lock";
private:
    struct Impl;
    struct FileLease;
    std::shared_ptr<Impl> impl_;
};
} // namespace cqs::state
