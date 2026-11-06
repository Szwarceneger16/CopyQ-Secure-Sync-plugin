// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_identity.h"

namespace cqs::trust {
enum class KeyScope : std::uint8_t { CurrentGeneration = 1, CatchUp = 2 };

struct KeyEnvelopeContext {
    Token group{}, root{}, successor{}, proposal{};
    Member recipient;
    Token sender{};
    std::uint64_t generation = 0;
    Token commitment{};
    KeyScope scope = KeyScope::CurrentGeneration;
};

enum class EnvelopeCode { Invalid, ContextMismatch, BadSignature, DecryptionFailed, KeyMismatch };

class EnvelopeError final : public std::runtime_error {
public:
    explicit EnvelopeError(EnvelopeCode code);
    EnvelopeCode code() const noexcept { return code_; }
private:
    EnvelopeCode code_;
};

// One high-entropy 32-byte data key in guarded, locked memory. The caller
// supplies locally authenticated private bytes when importing a persisted key.
class SyncKey final {
public:
    static constexpr std::size_t Size = 32;

    static std::unique_ptr<SyncKey> generate();
    static std::unique_ptr<SyncKey> import(const crypto::Bytes &trustedBytes);
    ~SyncKey();
    SyncKey(const SyncKey &) = delete;
    SyncKey &operator=(const SyncKey &) = delete;
    SyncKey(SyncKey &&) = delete;
    SyncKey &operator=(SyncKey &&) = delete;

    Token commitment(const Token &group, std::uint64_t generation) const;
    bool sameKey(const SyncKey &other) const noexcept;

    // Sensitive plaintext. Encrypt into private storage and wipe immediately.
    crypto::Bytes exportPrivate() const;
private:
    friend class KeyEnvelopeCodec;
    SyncKey();
    std::uint8_t *bytes_ = nullptr;
};

// Cryptographic codec only. The coordinator must authorize the exact context
// against pinned membership before sealing or opening any envelope.
class KeyEnvelopeCodec final {
public:
    static crypto::Bytes seal(const KeyEnvelopeContext &context, const Identity &sender,
                              const SyncKey &key);
    static void verify(const crypto::Bytes &wire, const KeyEnvelopeContext &expected,
                       const Member &authorizedSender);
    static std::unique_ptr<SyncKey> open(const crypto::Bytes &wire, const KeyEnvelopeContext &expected,
                                        const Member &authorizedSender, const Identity &recipient);

    // Parses canonical public metadata. The result has no authority until
    // compared with independently pinned context and authenticated by open().
    static KeyEnvelopeContext inspect(const crypto::Bytes &wire);
};
} // namespace cqs::trust
