// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_signed_event.h"
#include "import_transaction.h"

namespace cqs::storage { class Directory; }

namespace cqs::trust {
struct LegacyArchiveSource {
    transaction::Store &store;
    const storage::Directory &transport;
    const crypto::Bytes &legacyKey;
    std::string binding;
};

// Qt-free equivalent of the legacy private record's K-SYNC identity.
std::string legacyArchiveKeyIdentity(const crypto::Bytes &legacyKey);

// Read-only source proof. The caller supplies trusted local pins, a live key
// and an authenticated Store. The proof owns the Store lease until destruction.
class VerifiedLegacyArchive final {
public:
    explicit VerifiedLegacyArchive(const LegacyArchiveSource &source);
    ~VerifiedLegacyArchive();
    VerifiedLegacyArchive(const VerifiedLegacyArchive &) = delete;
    VerifiedLegacyArchive &operator=(const VerifiedLegacyArchive &) = delete;

    const std::vector<std::string> &packedItems() const noexcept { return items_; }
    // The successor context comes from independently pinned local membership.
    Token confirmation(const SignedEventContext &successor) const;
private:
    std::unique_ptr<transaction::Store::Lease> lease_;
    Token proofKey_{};
    Token archiveDigest_{};
    std::vector<std::string> items_;
};
} // namespace cqs::trust
