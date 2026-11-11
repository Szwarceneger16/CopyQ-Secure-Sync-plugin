// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "device_identity.h"
#include "state_record.h"
#include <filesystem>
#include <string>

namespace cqs::trust {
struct IdentityVaultPins {
    Token group{}, root{};
    Member member;
};

// Lab-only private identity storage. The caller provisions a dedicated private
// directory outside transport and provides trusted pins from local setup. The
// credential must be an independent local key or password. Opening a vault
// authenticates its identity against the pins; it cannot grant membership.
class IdentityVault final {
public:
    static std::string binding(const IdentityVaultPins &pins);
    static void initialize(const std::filesystem::path &directory,
                           const IdentityVaultPins &pins, const crypto::Bytes &credential,
                           const Identity &identity,
                           state::Protection protection = state::Protection::Key);
    static std::unique_ptr<Identity> load(const std::filesystem::path &directory,
                                         const IdentityVaultPins &pins, const crypto::Bytes &credential,
                                         state::Protection protection = state::Protection::Key);
};
} // namespace cqs::trust
