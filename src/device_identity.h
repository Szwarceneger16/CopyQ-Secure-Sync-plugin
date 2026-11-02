// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust.h"
#include <memory>

namespace cqs::trust {
// Opt-in laboratory adapter, never linked into the shipping plugin. Requires
// libsodium >= 1.0.22; distribution provenance/platform qualification is separate.
class SodiumVerifier final : public SignatureVerifier {
public:
    SodiumVerifier();
    static bool validSigningKey(const Token &key);
    static bool validEncryptionKey(const Token &key);
    static bool validMember(const Member &member);
    bool verify(const Token &publicKey, const crypto::Bytes &message,
                const Signature &signature) const override;
    static constexpr std::size_t MaxMessage = 65536;
};

// A low-level identity primitive, not a pairing authorization API. Callers must
// durably reserve the exact verified intent before calling sign(). Secret key
// material stays in guarded, locked libsodium memory until explicit export.
class Identity final {
public:
    static std::unique_ptr<Identity> generate();
    // Only accepts a locally authenticated/decrypted vault record, never cloud
    // input. Restoring a record does not establish membership or trust.
    static std::unique_ptr<Identity> restore(const crypto::Bytes &privateRecord);
    ~Identity();
    Identity(const Identity &) = delete;
    Identity &operator=(const Identity &) = delete;
    Identity(Identity &&) = delete;
    Identity &operator=(Identity &&) = delete;

    const Member &member() const noexcept { return member_; }
    Signature sign(const crypto::Bytes &message) const;
    // Sensitive plaintext; encrypt into the private vault and wipe the returned
    // buffer immediately. Never place this record in transport/logs/clipboard.
    crypto::Bytes exportPrivate() const;
private:
    struct Secrets;
    Identity();
    void derive();
    Member member_;
    Secrets *secrets_ = nullptr;
};
} // namespace cqs::trust
