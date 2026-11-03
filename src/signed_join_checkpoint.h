// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "device_trust_journal.h"

namespace cqs::trust {

// Experimental encrypted destination for an explicit signed Join. The
// caller must provision a separate private directory outside transport and
// call apply() only from the freshly revalidated trust-journal operation.
class SignedJoinCheckpoint final {
public:
    SignedJoinCheckpoint(const std::filesystem::path &privateDirectory,
                         const crypto::Bytes &localCredential, std::string profileBinding,
                         state::Protection protection = state::Protection::Key);
    void apply(const JoinActivation &verified, const events::Event &tip,
               const transaction::Snapshot &snapshot);
    transaction::Snapshot read(const JoinActivation &expected);

private:
    std::string profileBinding_;
    std::string binding_;
    state::FileStore session_;
    state::FileStore store_;
};

} // namespace cqs::trust
