// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust_journal.h"
#include <filesystem>
#include <functional>
#include <memory>

namespace cqs::trust {

enum class SignedSetupRole { Founder, Applicant };
struct SignedSetupPaths {
    std::filesystem::path root, identity, journal, checkpoint, staging, transport;
};

// One password-protected local setup record owns the generated credentials.
// The transport receives only public control packets and encrypted history.
class SignedSetup final {
public:
    using PathValidator = std::function<bool(const std::filesystem::path &, const std::filesystem::path &)>;
    static std::filesystem::path createPrivateRoot(const std::filesystem::path &parent);
    static std::unique_ptr<SignedSetup> createFounder(const std::filesystem::path &privateRoot,
        const crypto::Bytes &password, const std::filesystem::path &transport, std::uint64_t trustedNow,
        const PathValidator &validatePaths = {});
    static std::unique_ptr<SignedSetup> createApplicant(const std::filesystem::path &privateRoot,
        const crypto::Bytes &password, const std::filesystem::path &transport, const Genesis &trustedGenesis,
        const Token &confirmedGenesisFingerprint, std::uint64_t trustedNow, const PathValidator &validatePaths = {});
    // A failed open never creates a replacement. An interrupted initial
    // provisioning resumes with the exact identity and credentials already saved.
    static std::unique_ptr<SignedSetup> open(const std::filesystem::path &privateRoot,
        const crypto::Bytes &password, std::uint64_t trustedNow, const PathValidator &validatePaths = {});
    // Authenticate only the ready manifest and immutable activation pins. This
    // local read does not provision or access the vault, journal or transport.
    // The caller must wipe the returned transient plaintext credential.
    static crypto::Bytes unlockCheckpoint(const std::filesystem::path &privateRoot,
        const crypto::Bytes &password, const JoinActivation &expected);
    static std::string invitation(const Genesis &genesis);
    static Genesis parseInvitation(const std::string &invitation);
    static Token fingerprint(const Genesis &genesis);

    ~SignedSetup();
    SignedSetup(const SignedSetup &) = delete;
    SignedSetup &operator=(const SignedSetup &) = delete;
    SignedSetupRole role() const noexcept;
    const Genesis &genesis() const noexcept;
    const Member &member() const noexcept;
    const SignedSetupPaths &paths() const noexcept;
    Identity &identity() const noexcept;
    const SyncKey *founderKey() const noexcept;
    // The caller must wipe the returned transient plaintext credential.
    crypto::Bytes journalCredential() const;
    crypto::Bytes checkpointCredential() const;

private:
    struct Impl;
    explicit SignedSetup(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};
} // namespace cqs::trust
