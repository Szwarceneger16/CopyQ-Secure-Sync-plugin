// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "events.h"
#include <filesystem>
#include <memory>

namespace cqs::storage {

struct Limits {
    events::Limits reader;
    // Count every non-dot directory entry, not only recognized event files.
    std::size_t entries = 4096;
    std::size_t devices = 128;
};

enum class ErrorCode {
    InvalidPath,
    InvalidLimits,
    Unavailable,
    UnsafeEntry,
    Changed,
    ScanLimit,
    Io,
    AlreadyExists,
    UnsupportedFilesystem,
    PublishedUnconfirmed,
};
class Error final : public std::runtime_error {
public:
    Error(ErrorCode code, const char *message) : std::runtime_error(message), code_(code) {}
    ErrorCode code() const noexcept { return code_; }
private:
    ErrorCode code_;
};

// An existing, dedicated transport root with an existing events/ directory.
// Never create a missing root implicitly: a missing mount is not an empty history.
// Holds directory handles, not a K-SYNC. Linux and Windows use separate native
// backends; Windows supports fixed local NTFS, never a path-based stream fallback.
class Directory final {
public:
    explicit Directory(const std::filesystem::path &absoluteRoot);
    ~Directory();
    Directory(const Directory &) = delete;
    Directory &operator=(const Directory &) = delete;

    // Validate the full bounded scan and authenticate every event, or throw.
    // The returned snapshot is observational, not a filesystem transaction and
    // not a guarantee of freshness against replay/withheld events.
    events::AuthenticatedHistory scan(const crypto::Bytes &key, Limits limits = {}) const;
    // Read-only preflight before reserving a new ID. Publish rechecks pinned
    // handles; this call neither creates files nor authorizes a later write.
    void checkPublicationDevice(const std::string &device) const;
    void checkPublicationStaging(const std::filesystem::path &privateStaging = {}) const;

    // Publish an ALREADY ENCRYPTED wire envelope. It is authenticated and bound
    // to expectedId before any write. Bytes must remain immutable during this call.
    // Success means the backend's OS flush/publication barrier completed (Linux
    // file+directory fsync; Windows same-volume WRITE_THROUGH move and file flush).
    // Windows requires an existing private staging folder outside the transport,
    // on that same volume. Linux uses anonymous staging and rejects that option.
    // Existing names NEVER change,
    // even for identical content. PublishedUnconfirmed means the final name may
    // already be visible: reconcile it; do not allocate another revision blindly.
    // No sequence allocation, conflict resolution, CopyQ import or state writes.
    void publish(const crypto::Bytes &key, const events::Envelope &envelope,
                 events::Limits limits = {}, const std::filesystem::path &privateStaging = {}) const;
    // Reconcile an interrupted publication: exact immutable ciphertext readback
    // and a fresh native durability barrier. Never rewrites an existing event.
    void confirm(const crypto::Bytes &key, const events::Envelope &envelope,events::Limits limits = {}) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace cqs::storage
