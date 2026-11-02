// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_identity.h"
#include <sodium.h>
#include <algorithm>
#include <cstring>
#include <string>

namespace cqs::trust {
namespace {
constexpr char PrivateDomain[] = "CopyQ-Secure-Sync-device-identity-private-lab-v1";
constexpr std::size_t PrivateSize = sizeof(PrivateDomain) + 32 * 3;

void ready() {
    static const bool initialized = [] {
        if (sodium_init() < 0) throw crypto::Error("Device cryptography unavailable");
        // The version string is checked at runtime as well as at configure time:
        // <=1.0.20 point validation admitted mixed-order Ed25519 points.
        const std::string version(sodium_version_string());
        const auto first = version.find('.');
        const auto second = first == std::string::npos ? first : version.find('.', first + 1);
        if (first == std::string::npos || second == std::string::npos)
            throw crypto::Error("Unsupported device cryptography version");
        const auto major = std::stoul(version.substr(0, first));
        const auto minor = std::stoul(version.substr(first + 1, second - first - 1));
        const auto patch = std::stoul(version.substr(second + 1));
        if (major < 1 || (major == 1 && minor == 0 && patch < 22))
            throw crypto::Error("Unsupported device cryptography version");
        return true;
    }();
    (void)initialized;
}
bool zero(const Token &token) { return sodium_is_zero(token.data(), token.size()) == 1; }
bool canonicalX25519(const Token &key) {
    // X25519 masks the top bit and accepts field aliases. Device identities use
    // one canonical public encoding so aliases cannot become distinct voters.
    Token modulus{}; modulus.fill(0xff); modulus[0] = 0xed; modulus[31] = 0x7f;
    for (std::size_t i = key.size(); i > 0; --i) {
        if (key[i - 1] < modulus[i - 1]) return true;
        if (key[i - 1] > modulus[i - 1]) return false;
    }
    return false;
}
} // namespace

static_assert(crypto_sign_PUBLICKEYBYTES == 32 && crypto_sign_SECRETKEYBYTES == 64 &&
              crypto_sign_SEEDBYTES == 32 && crypto_sign_BYTES == 64,
              "Device Ed25519 sizes changed");
static_assert(crypto_scalarmult_BYTES == 32 && crypto_scalarmult_SCALARBYTES == 32,
              "Device X25519 sizes changed");

SodiumVerifier::SodiumVerifier() { ready(); }
bool SodiumVerifier::validSigningKey(const Token &key) {
    ready(); return crypto_core_ed25519_is_valid_point(key.data()) == 1;
}
bool SodiumVerifier::validEncryptionKey(const Token &key) {
    ready();
    if (!canonicalX25519(key)) return false;
    // Fixed public test scalar; no secret/shared key is derived for application
    // use. The library rejects all small-order inputs through a zero result.
    Token scalar{}, shared{}; scalar.fill(0x42);
    const int result = crypto_scalarmult(shared.data(), scalar.data(), key.data());
    sodium_memzero(shared.data(), shared.size());
    return result == 0;
}
bool SodiumVerifier::validMember(const Member &member) {
    ready();
    return !zero(member.id) && member.signingKey != member.encryptionKey &&
        validSigningKey(member.signingKey) && validEncryptionKey(member.encryptionKey);
}
bool SodiumVerifier::verify(const Token &publicKey, const crypto::Bytes &message,
                            const Signature &signature) const {
    if (message.size() > MaxMessage || !validSigningKey(publicKey)) return false;
    Token r{}; std::copy_n(signature.begin(), r.size(), r.begin());
    if (!validSigningKey(r)) return false;
    static const unsigned char Empty = 0;
    return crypto_sign_verify_detached(signature.data(), message.empty() ? &Empty : message.data(),
        static_cast<unsigned long long>(message.size()), publicKey.data()) == 0;
}

struct Identity::Secrets {
    unsigned char seed[crypto_sign_SEEDBYTES];
    unsigned char signing[crypto_sign_SECRETKEYBYTES];
    unsigned char encryption[crypto_scalarmult_SCALARBYTES];
};
Identity::Identity() {
    ready();
    secrets_ = static_cast<Secrets *>(sodium_malloc(sizeof(Secrets)));
    if (!secrets_) throw crypto::Error("Device secret allocation failed");
    if (sodium_mlock(secrets_, sizeof(Secrets)) != 0) {
        sodium_free(secrets_); secrets_ = nullptr;
        throw crypto::Error("Device secret memory locking failed");
    }
    sodium_memzero(secrets_, sizeof(Secrets));
}
Identity::~Identity() {
    if (secrets_) {
        sodium_memzero(secrets_, sizeof(Secrets));
        sodium_free(secrets_);
    }
}
void Identity::derive() {
    if (crypto_sign_seed_keypair(member_.signingKey.data(), secrets_->signing, secrets_->seed) != 0 ||
        crypto_scalarmult_base(member_.encryptionKey.data(), secrets_->encryption) != 0 ||
        !SodiumVerifier::validMember(member_))
        throw crypto::Error("Device identity rejected");
}
std::unique_ptr<Identity> Identity::generate() {
    auto result = std::unique_ptr<Identity>(new Identity);
    randombytes_buf(result->member_.id.data(), result->member_.id.size());
    // Independent RNG calls, not Ed25519-to-X25519 conversion or password keys.
    randombytes_buf(result->secrets_->seed, sizeof(result->secrets_->seed));
    randombytes_buf(result->secrets_->encryption, sizeof(result->secrets_->encryption));
    result->derive(); return result;
}
std::unique_ptr<Identity> Identity::restore(const crypto::Bytes &privateRecord) {
    if (privateRecord.size() != PrivateSize ||
        !std::equal(PrivateDomain, PrivateDomain + sizeof(PrivateDomain), privateRecord.begin()))
        throw crypto::Error("Device private record rejected");
    auto result = std::unique_ptr<Identity>(new Identity);
    const auto *bytes = privateRecord.data() + sizeof(PrivateDomain);
    std::copy_n(bytes, 32, result->member_.id.begin());
    std::memcpy(result->secrets_->seed, bytes + 32, 32);
    std::memcpy(result->secrets_->encryption, bytes + 64, 32);
    result->derive(); return result;
}
crypto::Bytes Identity::exportPrivate() const {
    crypto::Bytes result(PrivateSize);
    std::copy_n(PrivateDomain, sizeof(PrivateDomain), result.begin());
    auto *bytes = result.data() + sizeof(PrivateDomain);
    std::copy(member_.id.begin(), member_.id.end(), bytes);
    std::memcpy(bytes + 32, secrets_->seed, 32);
    std::memcpy(bytes + 64, secrets_->encryption, 32);
    return result;
}
Signature Identity::sign(const crypto::Bytes &message) const {
    if (message.size() > SodiumVerifier::MaxMessage)
        throw crypto::Error("Device signature message rejected");
    Signature signature{}; unsigned long long length = 0;
    static const unsigned char Empty = 0;
    if (crypto_sign_detached(signature.data(), &length, message.empty() ? &Empty : message.data(),
        static_cast<unsigned long long>(message.size()), secrets_->signing) != 0 || length != signature.size())
        throw crypto::Error("Device signature failed");
    return signature;
}
} // namespace cqs::trust
