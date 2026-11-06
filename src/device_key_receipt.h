// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_key_envelope.h"

namespace cqs::trust {
struct ReceiptContext {
    Token group{}, root{}, successor{}, proposal{}, sender{};
    Member recipient;
    std::uint64_t generation = 0;
    Token commitment{}, envelopeDigest{};
    KeyScope scope = KeyScope::CurrentGeneration;
};

enum class ReceiptCode { Invalid, ContextMismatch, BadSignature };

class ReceiptError final : public std::runtime_error {
public:
    explicit ReceiptError(ReceiptCode code);
    ReceiptCode code() const noexcept { return code_; }
private:
    ReceiptCode code_;
};

// A storage receipt identifies the exact validated envelope durably stored by
// its recipient. The coordinator enforces the durability and membership rules.
class KeyReceiptCodec final {
public:
    static crypto::Bytes sign(const ReceiptContext &context, const Identity &recipient);
    static void verify(const crypto::Bytes &wire, const ReceiptContext &expected);

    // Public metadata without authority. Verify against independently pinned
    // context before using any of these fields to authorize an operation.
    static ReceiptContext inspect(const crypto::Bytes &wire);
};
} // namespace cqs::trust
