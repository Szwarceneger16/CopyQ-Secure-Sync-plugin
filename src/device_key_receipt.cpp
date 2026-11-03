// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_key_receipt.h"
#include <algorithm>

namespace cqs::trust {
namespace {
using crypto::Bytes;

constexpr char ReceiptDomain[] = "CopyQ-Secure-Sync-key-storage-receipt-lab-v1";
constexpr std::array<std::uint8_t, 4> ReceiptVersion{0, 0, 0, 1};
constexpr std::size_t SignedSize = sizeof(ReceiptDomain) + ReceiptVersion.size() + 10 * 32 + 8 + 1;
constexpr std::size_t WireSize = SignedSize + Signature{}.size();

static_assert(SignedSize <= SodiumVerifier::MaxMessage, "Key receipt exceeds signature bound");

[[noreturn]] void fail(ReceiptCode code) { throw ReceiptError(code); }

bool zero(const Token &token) {
    return std::all_of(token.begin(), token.end(), [](std::uint8_t byte) { return byte == 0; });
}

void validate(const ReceiptContext &context) {
    if (zero(context.group) || zero(context.root) || zero(context.successor) || zero(context.proposal) ||
        zero(context.sender) || zero(context.commitment) || zero(context.envelopeDigest) ||
        (context.scope != KeyScope::CurrentGeneration && context.scope != KeyScope::CatchUp) ||
        context.sender == context.recipient.id || !SodiumVerifier::validMember(context.recipient)) {
        fail(ReceiptCode::Invalid);
    }
}

template<class Range> void append(Bytes &out, const Range &bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

Bytes receiptBytes(const ReceiptContext &context) {
    Bytes bytes;
    bytes.reserve(WireSize);
    bytes.insert(bytes.end(), ReceiptDomain, ReceiptDomain + sizeof(ReceiptDomain));
    append(bytes, ReceiptVersion);
    append(bytes, context.group);
    append(bytes, context.root);
    append(bytes, context.successor);
    append(bytes, context.proposal);
    append(bytes, context.sender);
    append(bytes, context.recipient.id);
    append(bytes, context.recipient.signingKey);
    append(bytes, context.recipient.encryptionKey);
    for (unsigned shift = 64; shift != 0; shift -= 8) {
        bytes.push_back(static_cast<std::uint8_t>(context.generation >> (shift - 8)));
    }
    append(bytes, context.commitment);
    append(bytes, context.envelopeDigest);
    bytes.push_back(static_cast<std::uint8_t>(context.scope));
    return bytes;
}
} // namespace

ReceiptError::ReceiptError(ReceiptCode code) : std::runtime_error("Key storage receipt refused"), code_(code) {}

Bytes KeyReceiptCodec::sign(const ReceiptContext &context, const Identity &recipient) {
    validate(context);
    if (recipient.member() != context.recipient) fail(ReceiptCode::ContextMismatch);

    auto wire = receiptBytes(context);
    const auto signature = recipient.sign(wire);
    append(wire, signature);
    return wire;
}

ReceiptContext KeyReceiptCodec::inspect(const Bytes &wire) {
    if (wire.size() != WireSize || !std::equal(ReceiptDomain, ReceiptDomain + sizeof(ReceiptDomain), wire.begin())) {
        fail(ReceiptCode::Invalid);
    }
    auto position = wire.begin() + sizeof(ReceiptDomain);
    if (!std::equal(ReceiptVersion.begin(), ReceiptVersion.end(), position)) fail(ReceiptCode::Invalid);
    position += ReceiptVersion.size();

    const auto readToken = [&position] {
        Token token{};
        std::copy_n(position, token.size(), token.begin());
        position += token.size();
        return token;
    };

    ReceiptContext context;
    context.group = readToken();
    context.root = readToken();
    context.successor = readToken();
    context.proposal = readToken();
    context.sender = readToken();
    context.recipient.id = readToken();
    context.recipient.signingKey = readToken();
    context.recipient.encryptionKey = readToken();
    for (unsigned i = 0; i < 8; ++i) context.generation = (context.generation << 8) | *position++;
    context.commitment = readToken();
    context.envelopeDigest = readToken();
    context.scope = static_cast<KeyScope>(*position);
    validate(context);
    return context;
}

void KeyReceiptCodec::verify(const Bytes &wire, const ReceiptContext &expected) {
    (void)inspect(wire);
    const auto message = receiptBytes(expected);
    if (!std::equal(message.begin(), message.end(), wire.begin())) fail(ReceiptCode::ContextMismatch);

    Signature signature{};
    std::copy_n(wire.begin() + SignedSize, signature.size(), signature.begin());
    const SodiumVerifier verifier;
    if (!verifier.verify(expected.recipient.signingKey, message, signature)) fail(ReceiptCode::BadSignature);
}
} // namespace cqs::trust
