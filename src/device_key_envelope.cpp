// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_key_envelope.h"
#include <sodium.h>
#include <algorithm>
#include <cstring>
#include <new>

namespace cqs::trust {
namespace {
using crypto::Bytes;

constexpr char EnvelopeDomain[] = "CopyQ-Secure-Sync-key-envelope-lab-v1";
constexpr char PlaintextDomain[] = "CopyQ-Secure-Sync-key-envelope-plaintext-lab-v1";
constexpr char CommitmentDomain[] = "CopyQ-Secure-Sync-data-key-commitment-control-v1";
constexpr std::array<std::uint8_t, 4> EnvelopeVersion{0, 0, 0, 1};
constexpr std::size_t ContextSize = EnvelopeVersion.size() + 9 * 32 + 8 + 1;
constexpr std::size_t HeaderSize = sizeof(EnvelopeDomain) + ContextSize;
constexpr std::size_t PlaintextPrefixSize = sizeof(PlaintextDomain) + ContextSize;
constexpr std::size_t PlaintextSize = PlaintextPrefixSize + SyncKey::Size;
constexpr std::size_t SealedSize = PlaintextSize + crypto_box_SEALBYTES;
constexpr std::size_t SignedSize = HeaderSize + SealedSize;
constexpr std::size_t WireSize = SignedSize + Signature{}.size();

static_assert(crypto_box_PUBLICKEYBYTES == Token{}.size() && crypto_box_SEALBYTES == 48,
              "Key envelope sealed-box encoding changed");
static_assert(crypto_hash_sha256_BYTES == Token{}.size(), "Key commitment digest size changed");
static_assert(SignedSize <= SodiumVerifier::MaxMessage, "Key envelope exceeds signature bound");

[[noreturn]] void fail(EnvelopeCode code) { throw EnvelopeError(code); }

std::uint8_t *allocateSecret(std::size_t size) {
    SodiumVerifier{};
    auto *bytes = static_cast<std::uint8_t *>(sodium_malloc(size));
    if (!bytes) throw crypto::Error("Key envelope secret allocation failed");
    if (sodium_mlock(bytes, size) != 0) {
        sodium_free(bytes);
        throw crypto::Error("Key envelope secret memory locking failed");
    }
    sodium_memzero(bytes, size);
    return bytes;
}

void freeSecret(std::uint8_t *bytes, std::size_t size) noexcept {
    sodium_memzero(bytes, size);
    sodium_free(bytes);
}

class SecretBuffer final {
public:
    explicit SecretBuffer(std::size_t size) : size_(size), bytes_(allocateSecret(size)) {}
    ~SecretBuffer() { freeSecret(bytes_, size_); }
    SecretBuffer(const SecretBuffer &) = delete;
    SecretBuffer &operator=(const SecretBuffer &) = delete;
    std::uint8_t *data() const noexcept { return bytes_; }
private:
    std::size_t size_;
    std::uint8_t *bytes_;
};

bool zero(const Token &token) {
    return std::all_of(token.begin(), token.end(), [](std::uint8_t byte) { return byte == 0; });
}

void validate(const KeyEnvelopeContext &context) {
    if (zero(context.group) || zero(context.root) || zero(context.successor) || zero(context.proposal) ||
        zero(context.sender) || zero(context.commitment) || context.scope != KeyScope::CurrentGeneration ||
        !SodiumVerifier::validMember(context.recipient)) {
        fail(EnvelopeCode::Invalid);
    }
}

void validateSender(const KeyEnvelopeContext &context, const Member &sender) {
    if (sender.id != context.sender || (sender.id == context.recipient.id && sender != context.recipient)) {
        fail(EnvelopeCode::ContextMismatch);
    }
    if (!SodiumVerifier::validMember(sender)) fail(EnvelopeCode::Invalid);
}

std::array<std::uint8_t, 8> generationBytes(std::uint64_t generation) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[bytes.size() - 1 - i] = static_cast<std::uint8_t>(generation >> (8 * i));
    }
    return bytes;
}

template<class Range> void append(Bytes &out, const Range &bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

// The same canonical bytes are visible in the header and authenticated again
// inside the sealed payload. Both domain strings include their terminating NUL.
template<std::size_t N> Bytes prefix(const char (&domain)[N], const KeyEnvelopeContext &context) {
    Bytes bytes;
    bytes.reserve(N + ContextSize);
    bytes.insert(bytes.end(), domain, domain + N);
    append(bytes, EnvelopeVersion);
    append(bytes, context.group);
    append(bytes, context.root);
    append(bytes, context.successor);
    append(bytes, context.proposal);
    append(bytes, context.recipient.id);
    append(bytes, context.recipient.signingKey);
    append(bytes, context.recipient.encryptionKey);
    append(bytes, context.sender);
    append(bytes, generationBytes(context.generation));
    append(bytes, context.commitment);
    bytes.push_back(static_cast<std::uint8_t>(context.scope));
    return bytes;
}
} // namespace

EnvelopeError::EnvelopeError(EnvelopeCode code) : std::runtime_error("Key envelope refused"), code_(code) {}

SyncKey::SyncKey() : bytes_(allocateSecret(Size)) {}
SyncKey::~SyncKey() { freeSecret(bytes_, Size); }

std::unique_ptr<SyncKey> SyncKey::generate() {
    auto key = std::unique_ptr<SyncKey>(new SyncKey);
    randombytes_buf(key->bytes_, Size);
    if (sodium_is_zero(key->bytes_, Size) == 1) fail(EnvelopeCode::KeyMismatch);
    return key;
}

std::unique_ptr<SyncKey> SyncKey::import(const Bytes &trustedBytes) {
    if (trustedBytes.size() != Size) fail(EnvelopeCode::Invalid);
    auto key = std::unique_ptr<SyncKey>(new SyncKey);
    std::memcpy(key->bytes_, trustedBytes.data(), Size);
    if (sodium_is_zero(key->bytes_, Size) == 1) fail(EnvelopeCode::KeyMismatch);
    return key;
}

Bytes SyncKey::exportPrivate() const { return Bytes(bytes_, bytes_ + Size); }

bool SyncKey::sameKey(const SyncKey &other) const noexcept {
    return sodium_memcmp(bytes_, other.bytes_, Size) == 0;
}

Token SyncKey::commitment(const Token &group, std::uint64_t generation) const {
    if (zero(group)) fail(EnvelopeCode::Invalid);
    SecretBuffer memory(sizeof(crypto_hash_sha256_state));
    auto *state = ::new (memory.data()) crypto_hash_sha256_state{};
    const auto generationEncoding = generationBytes(generation);
    Token digest{};
    if (crypto_hash_sha256_init(state) != 0 ||
        crypto_hash_sha256_update(state, reinterpret_cast<const std::uint8_t *>(CommitmentDomain),
                                  sizeof(CommitmentDomain)) != 0 ||
        crypto_hash_sha256_update(state, group.data(), group.size()) != 0 ||
        crypto_hash_sha256_update(state, generationEncoding.data(), generationEncoding.size()) != 0 ||
        crypto_hash_sha256_update(state, bytes_, Size) != 0 ||
        crypto_hash_sha256_final(state, digest.data()) != 0) {
        throw crypto::Error("Key commitment calculation failed");
    }
    return digest;
}

Bytes KeyEnvelopeCodec::seal(const KeyEnvelopeContext &context, const Identity &sender, const SyncKey &key) {
    validate(context);
    validateSender(context, sender.member());
    if (key.commitment(context.group, context.generation) != context.commitment) fail(EnvelopeCode::KeyMismatch);
    auto wire = prefix(EnvelopeDomain, context);
    wire.reserve(WireSize);
    wire.resize(SignedSize);
    {
        SecretBuffer plaintext(PlaintextSize);
        const auto header = prefix(PlaintextDomain, context);
        std::memcpy(plaintext.data(), header.data(), header.size());
        std::memcpy(plaintext.data() + PlaintextPrefixSize, key.bytes_, SyncKey::Size);
        if (crypto_box_seal(wire.data() + HeaderSize, plaintext.data(), PlaintextSize,
                            context.recipient.encryptionKey.data()) != 0) {
            throw crypto::Error("Key envelope sealing failed");
        }
    }
    const auto signature = sender.sign(wire);
    append(wire, signature);
    return wire;
}

KeyEnvelopeContext KeyEnvelopeCodec::inspect(const Bytes &wire) {
    if (wire.size() != WireSize || !std::equal(EnvelopeDomain, EnvelopeDomain + sizeof(EnvelopeDomain), wire.begin())) {
        fail(EnvelopeCode::Invalid);
    }
    auto position = wire.begin() + sizeof(EnvelopeDomain);
    if (!std::equal(EnvelopeVersion.begin(), EnvelopeVersion.end(), position)) fail(EnvelopeCode::Invalid);
    position += EnvelopeVersion.size();
    const auto readToken = [&position] {
        Token result{};
        std::copy_n(position, result.size(), result.begin());
        position += result.size();
        return result;
    };
    KeyEnvelopeContext context;
    context.group = readToken();
    context.root = readToken();
    context.successor = readToken();
    context.proposal = readToken();
    context.recipient.id = readToken();
    context.recipient.signingKey = readToken();
    context.recipient.encryptionKey = readToken();
    context.sender = readToken();
    for (unsigned i = 0; i < 8; ++i) context.generation = (context.generation << 8) | *position++;
    context.commitment = readToken();
    context.scope = static_cast<KeyScope>(*position);
    validate(context);
    return context;
}

void KeyEnvelopeCodec::verify(const Bytes &wire, const KeyEnvelopeContext &expected, const Member &authorizedSender) {
    const auto context = inspect(wire);
    const auto header = prefix(EnvelopeDomain, expected);
    if (!std::equal(header.begin(), header.end(), wire.begin())) fail(EnvelopeCode::ContextMismatch);
    validateSender(context, authorizedSender);

    Signature signature{};
    std::copy_n(wire.begin() + SignedSize, signature.size(), signature.begin());
    const Bytes signedBytes(wire.begin(), wire.begin() + SignedSize);
    const SodiumVerifier verifier;
    if (!verifier.verify(authorizedSender.signingKey, signedBytes, signature)) fail(EnvelopeCode::BadSignature);

    Token ephemeral{};
    std::copy_n(wire.begin() + HeaderSize, ephemeral.size(), ephemeral.begin());
    if (!SodiumVerifier::validEncryptionKey(ephemeral)) fail(EnvelopeCode::Invalid);
}

std::unique_ptr<SyncKey> KeyEnvelopeCodec::open(const Bytes &wire, const KeyEnvelopeContext &expected,
                                              const Member &authorizedSender, const Identity &recipient) {
    if (recipient.member() != expected.recipient) fail(EnvelopeCode::ContextMismatch);
    verify(wire, expected, authorizedSender);

    SecretBuffer plaintext(PlaintextSize);
    if (!recipient.openSealed(plaintext.data(), PlaintextSize, wire.data() + HeaderSize, SealedSize)) {
        fail(EnvelopeCode::DecryptionFailed);
    }
    const auto header = prefix(PlaintextDomain, expected);
    if (sodium_memcmp(plaintext.data(), header.data(), header.size()) != 0) fail(EnvelopeCode::ContextMismatch);
    const auto *keyBytes = plaintext.data() + PlaintextPrefixSize;
    if (sodium_is_zero(keyBytes, SyncKey::Size) == 1) fail(EnvelopeCode::KeyMismatch);

    auto key = std::unique_ptr<SyncKey>(new SyncKey);
    std::memcpy(key->bytes_, keyBytes, SyncKey::Size);
    if (key->commitment(expected.group, expected.generation) != expected.commitment) fail(EnvelopeCode::KeyMismatch);
    return key;
}
} // namespace cqs::trust
