// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "events.h"
#include <algorithm>
#include <array>
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

inline constexpr std::size_t MaxControlPacketBytes = 4096;
inline constexpr std::size_t MaxSignedEventPacketBytes = 2 * 1024 * 1024;

struct SignedEventScope {
    std::array<std::uint8_t, 32> group{}, root{};
    std::uint64_t generation = 0;
};

struct SignedEventPacket {
    std::string id, wire;
};

inline void validateControlPacketId(const std::string &id) {
    if (id.size() != 64 || !std::all_of(id.begin(), id.end(), [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) throw Error(ErrorCode::InvalidPath, "Invalid control packet address");
}

inline std::string controlPacketId(const crypto::Bytes &packet) {
    if (packet.empty() || packet.size() > MaxControlPacketBytes)
        throw Error(ErrorCode::InvalidLimits, "Invalid control packet size");
    const auto digest = crypto::sha256(packet);
    if (digest.size() != 32) throw Error(ErrorCode::Io, "Cannot address control packet");
    constexpr char hex[] = "0123456789abcdef";
    std::string id; id.reserve(64);
    for (const auto byte : digest) { id.push_back(hex[byte >> 4]); id.push_back(hex[byte & 15]); }
    return id;
}

// The generation directory must be provisioned explicitly under the transport
// root. Its name commits to the exact group, genesis root and key generation.
inline std::string signedEventFolderName(const SignedEventScope &scope) {
    const auto nonzero = [](const auto &token) {
        return std::any_of(token.begin(), token.end(), [](auto byte) { return byte != 0; });
    };
    if (!nonzero(scope.group) || !nonzero(scope.root))
        throw Error(ErrorCode::InvalidPath, "Invalid signed event transport scope");
    constexpr char domain[] = "CopyQ-Secure-Sync-signed-event-transport-lab-v1";
    crypto::Bytes input(domain, domain + sizeof(domain));
    input.insert(input.end(), scope.group.begin(), scope.group.end());
    input.insert(input.end(), scope.root.begin(), scope.root.end());
    for (unsigned shift = 64; shift; shift -= 8)
        input.push_back(static_cast<std::uint8_t>(scope.generation >> (shift - 8)));
    const auto digest = crypto::sha256(input);
    if (digest.size() != 32) throw Error(ErrorCode::Io, "Cannot address signed event scope");
    constexpr char hex[] = "0123456789abcdef";
    std::string name = "signed-";
    for (const auto byte : digest) { name.push_back(hex[byte >> 4]); name.push_back(hex[byte & 15]); }
    return name;
}

namespace detail {
inline constexpr std::size_t SignedDeviceSize = 32, SignedNumberSize = 12;
} // namespace detail

inline bool validSignedEventId(std::string_view id) {
    const auto deviceSize = detail::SignedDeviceSize;
    if (id.size() != deviceSize + 1 + detail::SignedNumberSize || id.front() != 'd' || id[deviceSize] != '/')
        return false;
    const auto number = id.substr(deviceSize + 1);
    return std::all_of(id.begin() + 1, id.begin() + deviceSize, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
    }) && number != "000000000000" && std::all_of(number.begin(), number.end(), [](char c) {
        return c >= '0' && c <= '9';
    });
}

namespace detail {
inline std::string signedEventFilename(std::string_view id) {
    if (!validSignedEventId(id)) throw Error(ErrorCode::InvalidPath, "Invalid signed event revision address");
    std::string name(id);
    name[SignedDeviceSize] = '-';
    return name + ".cqe";
}

inline std::string signedEventIdFromFilename(std::string_view name) {
    constexpr auto size = SignedDeviceSize + 1 + SignedNumberSize;
    if (name.size() != size + 4 || name[SignedDeviceSize] != '-' || name.substr(size) != ".cqe")
        throw Error(ErrorCode::UnsafeEntry, "Unexpected signed event name or conflict copy");
    std::string id(name.substr(0, size));
    id[SignedDeviceSize] = '/';
    if (!validSignedEventId(id)) throw Error(ErrorCode::UnsafeEntry, "Noncanonical signed event filename");
    return id;
}

inline void validateSignedEventScanLimits(Limits limits) {
    const Limits ceiling;
    if (!limits.entries || !limits.devices || limits.entries > ceiling.entries || limits.devices > ceiling.devices ||
        !limits.reader.eventBytes || !limits.reader.historyBytes ||
        limits.reader.eventBytes > ceiling.reader.eventBytes || limits.reader.historyBytes > ceiling.reader.historyBytes ||
        limits.reader.events > ceiling.reader.events)
        throw Error(ErrorCode::InvalidLimits, "Invalid signed event transport limits");
}
} // namespace detail

// An existing, dedicated transport root with an existing events/ directory.
// Never create a missing root implicitly: a missing mount is not an empty history.
// Holds directory handles, not a K-SYNC. Linux and Windows use separate native
// backends; Windows supports fixed local NTFS, never a path-based stream fallback.
class Directory final {
    struct Impl;
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
    // Targeted opaque packets under an existing control/ directory. The address
    // is SHA-256 of the bytes. Protocol authentication belongs to the caller.
    // Repeating publication confirms the exact existing file without replacing it.
    void publishControl(const crypto::Bytes &packet, const std::filesystem::path &privateStaging = {}) const;
    crypto::Bytes readControl(const std::string &packetId) const;
    // Opaque signed-event transport for an explicitly provisioned generation.
    // The caller authenticates the independently mapped revision ID and packet.
    class SignedEvents final {
    public:
        ~SignedEvents();
        SignedEvents(const SignedEvents &) = delete;
        SignedEvents &operator=(const SignedEvents &) = delete;
        std::vector<SignedEventPacket> scan(Limits limits = {}) const;
        // Keep supplied bytes immutable during the call. Repeating publication
        // confirms the exact existing bytes without replacing them.
        void publish(const events::Envelope &envelope, const std::filesystem::path &privateStaging = {}) const;
    private:
        friend class Directory;
        struct Impl;
        SignedEvents(std::shared_ptr<Directory::Impl> owner, const SignedEventScope &scope);
        std::unique_ptr<Impl> impl_;
    };
    // Hold one pinned generation folder through scan, authorization and publish.
    std::unique_ptr<SignedEvents> openSignedEvents(const SignedEventScope &scope) const;
    // One-shot helpers. A compound operation must use one SignedEvents handle.
    void publishSignedEvent(const SignedEventScope &scope, const events::Envelope &envelope,
                            const std::filesystem::path &privateStaging = {}) const;
    std::vector<SignedEventPacket> scanSignedEvents(const SignedEventScope &scope, Limits limits = {}) const;
private:
    std::shared_ptr<Impl> impl_;
};

} // namespace cqs::storage
