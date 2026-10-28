// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "events.h"
#include <map>
#include <memory>
#include <optional>

namespace cqs::transaction {

// Effective MIME bytes, NOT CopyQ pack() bytes. Item order is significant;
// MIME map order is not. The CopyQ adapter must preserve every supported format
// and reject unsupported QVariant values rather than silently stringify/drop them.
using Item = std::map<std::string, crypto::Bytes>;
using Snapshot = std::vector<Item>;
struct Limits {
    std::size_t items = 10000;
    std::size_t formatsPerItem = 256;
    std::size_t mimeNameBytes = 1024;
    std::size_t snapshotBytes = 32 * 1024 * 1024;
};

struct Head {
    events::Event event; // retain the accepted event to detect head equivocation
    Snapshot snapshot; // canonical, decoded data corresponding to that event
};
enum class Phase { Import, Restore };
struct Pending {
    Head target;
    Snapshot original;
    Phase phase = Phase::Import;
};
struct Publication {
    Head target;
    std::string wire; // Exact encrypted envelope reserved before publication.
};
struct Resolution { std::vector<std::string> tips; };
struct Record {
    unsigned schema = 1;
    // A setup-provisioned identifier binding device, tab, key and transport.
    // It must change when any of those change, not be guessed from a basename.
    std::string binding;
    std::uint64_t generation = 0;
    std::optional<Head> head;
    std::optional<Pending> pending;
    // Schema 2: authoritative local contents, independent of accepted history.
    // Schema 1 remains readable for explicit migrations and historical ports.
    std::optional<Snapshot> local = {};
    std::string keyIdentity = {}; // domain-separated SHA256 identity of K-SYNC
    // Schema 3: outbound allocation/Seed; schema 4: publication extending retained head.
    std::uint64_t allocatedSequence = 0;
    std::optional<Publication> publication = {};
    std::optional<Resolution> resolution = {}; // schema 5, explicit user decision; archive.back() retains prior local data
    std::vector<Snapshot> archives = {}; // schema 5, bounded protected conflict backups
    std::optional<Snapshot> preserved = {}; // explicit pre-Join/local adoption backup
    // Schema 6: authenticated semantic fingerprints, including unaccepted branches.
    std::map<std::string, crypto::Bytes> witnessed = {};
};

// Verify retained accepted content and every previously witnessed event. Missing
// files defer; altered authenticated content refuses. Never forget a witness.
crypto::Bytes eventFingerprint(const events::Event &);
void verifyHistory(const Record &,const events::AuthenticatedHistory &);
bool rememberHistory(Record &,const events::AuthenticatedHistory &);

// A strict production adapter is REQUIRED before wiring this engine to the UI.
// One record contains head + journal + backup, committed atomically under AEAD.
// It must live outside the transport; failed reads MUST NOT create an empty state.
class Store {
public:
    struct Lease { virtual ~Lease() = default; };
    virtual ~Store() = default;
    // Cross-process exclusive lease for the binding; retained for the operation.
    // A busy store throws or returns nullptr. Never wait indefinitely on the GUI.
    virtual std::unique_ptr<Lease> lock() = 0;
    virtual Record load() = 0; // authenticate, decode and bound before return
    // Atomic compare-and-swap of the complete record, not just its generation.
    // Return ONLY after durable commit. Failure may mean old OR new persisted.
    // Never write unencrypted snapshots or echo them in errors/logs.
    virtual void commit(const Record &expected, const Record &replacement) = 0;
    // Production stores preflight aggregate limits for all projected phases,
    // before the adapter changes a model. Historical in-memory ports may omit it.
    virtual void checkCapacity(const Record &) {}
};

struct View {
    Snapshot snapshot;
    std::uint64_t epoch = 0; // changes on every mutation, including an ABA edit
};
class Clipboard {
public:
    virtual ~Clipboard() = default;
    // Decode detached data in memory; no tab writes, clipboard changes or pack()
    // roundtrip comparisons. Apply Limits DURING decoding, before allocation.
    virtual Snapshot decode(const std::vector<std::string> &packed, Limits limits) = 0;
    virtual View capture(Limits limits) = 0;
    // Validate policy before creating a new durable import/rollback intent.
    // This is read-only; replace() must repeat the check against the live view.
    virtual void preflight(const View &,const Snapshot &) {}
    // Check epoch AND exact data in the GUI-thread critical section. Refuse
    // active editors/locked tabs. On failure a partial write may have happened.
    virtual View replace(const View &expected, const Snapshot &desired) = 0;
    // Refuse changed epoch/data and active editors. Persist and reload from the
    // bound authoritative encrypted store, then return actual durable MIME bytes.
    // A GUI read immediately after replace() is NOT this durability barrier.
    virtual Snapshot persist(const View &expected, Limits limits) = 0;
};

enum class ErrorCode {
    InvalidLimits, InvalidRecord, WrongBinding, Busy, PendingRecovery,
    NotJoined, AlreadyJoined, NoRemote, Conflict, MissingHead, Equivocation,
    Rollback, LocalChanges, VerificationFailed, NoPending, WrongPhase,
    GenerationExhausted, HistoryExists, DeviceInUse, PublicationStaging, HistoryLimit, BackupLimit
};
class Error final : public std::runtime_error {
public:
    Error(ErrorCode code, const char *message) : std::runtime_error(message), code_(code) {}
    ErrorCode code() const noexcept { return code_; }
private:
    ErrorCode code_;
};
enum class ImportMode { Join, FastForward, JoinPreserve };
enum class Recovery { AcceptTarget, RetryImport, RestoreOriginal, PreserveAndRetry, PreserveAndRestore };
enum class Result { Applied, UpToDate, Restored };

// Transaction coordinator, not a daemon. Call only with a freshly authenticated
// history under a serialized runtime. It never chooses a conflict winner, stores
// a K-SYNC, publishes an event, catches-and-rolls-back a failure or changes tabs
// other than the one already bound to the Clipboard adapter.
class Importer final {
public:
    Importer(std::string binding, Store &store, Clipboard &clipboard, Limits limits = {});
    Result importTip(const events::AuthenticatedHistory &history, ImportMode mode);
    // Explicit recovery only; does not depend on Nextcloud being online. Refuses
    // divergent local content in ordinary modes. PreserveAndRetry/Restore explicitly
    // retain a bounded encrypted archive before applying the pending decision.
    Result recover(Recovery action);
private:
    std::unique_ptr<Store::Lease> lock();
    Record load();
    void validateSnapshot(const Snapshot &snapshot) const;
    void validateHead(const Head &head);
    void save(Record &record, Record &&replacement);
    void persist(Record &record, View view, const Snapshot &desired);
    std::string binding_;
    Store &store_;
    Clipboard &clipboard_;
    Limits limits_;
};
} // namespace cqs::transaction
