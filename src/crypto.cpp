// SPDX-License-Identifier: GPL-3.0-or-later
#include "crypto.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <algorithm>
#include <climits>
#include <memory>

namespace cqs::crypto {
namespace {
constexpr std::size_t TAG_SIZE = 16;
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t KEY_SIZE = 32;
using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
void validate(const Bytes &key, const Bytes &nonce) {
    if (key.size() != KEY_SIZE || nonce.size() != NONCE_SIZE)
        throw Error("Invalid K-SYNC key or nonce length");
}
void checkSize(const std::size_t n) {
    if (n > static_cast<std::size_t>(INT_MAX))
        throw Error("Cryptographic input exceeds library bounds");
}
}
Bytes random(const std::size_t n) {
    if (!n || n > static_cast<std::size_t>(INT_MAX)) throw Error("Invalid random byte count");
    Bytes bytes(n);
    if (RAND_bytes(bytes.data(), static_cast<int>(n)) != 1)
        throw Error("Secure randomness unavailable");
    return bytes;
}
Bytes sha256(const Bytes &input) {
    Bytes out(32); unsigned length=0;
    if(EVP_Digest(input.data(),input.size(),out.data(),&length,EVP_sha256(),nullptr)!=1 || length!=32)
        throw Error("SHA-256 unavailable");
    return out;
}
Bytes passwordKey(const Bytes &password, const Bytes &salt, unsigned iterations) {
    if (password.empty() || password.size() > 1024 || salt.size() != 16 || !iterations || iterations > 1000000)
        throw Error("Invalid password derivation parameters");
    Bytes out(32);
    if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password.data()), int(password.size()),
        salt.data(), int(salt.size()), int(iterations), EVP_sha256(), int(out.size()), out.data()) != 1) {
        wipe(out); throw Error("Password derivation failed");
    }
    return out;
}
Bytes aes256GcmEncrypt(const Bytes &key, const Bytes &nonce,
                       const Bytes &plaintext, const Bytes &aad) {
    validate(key, nonce);
    checkSize(plaintext.size()); checkSize(aad.size());
    Context ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw Error("Cannot allocate AES-GCM context");
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw Error("Cannot initialize AES-GCM");
    int ignored=0, written=0, tail=0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &ignored, aad.data(), static_cast<int>(aad.size())) != 1)
        throw Error("Cannot authenticate AES-GCM AAD");
    Bytes out(plaintext.size() + TAG_SIZE);
    if (!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), out.data(), &written, plaintext.data(), static_cast<int>(plaintext.size())) != 1)
        throw Error("Cannot encrypt payload");
    if (EVP_EncryptFinal_ex(ctx.get(), out.data()+written, &tail) != 1)
        throw Error("Cannot finalize AES-GCM encryption");
    if (static_cast<std::size_t>(written + tail) != plaintext.size())
        throw Error("Unexpected AES-GCM ciphertext length");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, out.data()+plaintext.size()) != 1)
        throw Error("Cannot read AES-GCM authentication tag");
    return out;
}
Bytes aes256GcmDecrypt(const Bytes &key, const Bytes &nonce,
                       const Bytes &ciphertextWithTag, const Bytes &aad) {
    validate(key, nonce);
    if (ciphertextWithTag.size() < TAG_SIZE)
        throw Error("Invalid authenticated ciphertext");
    const auto cipherLen = ciphertextWithTag.size()-TAG_SIZE;
    checkSize(cipherLen); checkSize(aad.size());
    Context ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw Error("Cannot allocate AES-GCM context");
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw Error("Cannot initialize AES-GCM");
    int ignored=0, written=0, tail=0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &ignored, aad.data(), static_cast<int>(aad.size())) != 1)
        throw Error("Cannot authenticate AES-GCM AAD");
    Bytes out(cipherLen);
    // OpenSSL requires a writable output pointer even for a zero-byte ciphertext.
    std::uint8_t dummy=0;
    std::uint8_t* ptr = out.empty() ? &dummy : out.data();
    if (cipherLen && EVP_DecryptUpdate(ctx.get(), ptr, &written, ciphertextWithTag.data(), static_cast<int>(cipherLen)) != 1)
        throw Error("Cannot decrypt ciphertext");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                            const_cast<std::uint8_t*>(ciphertextWithTag.data()+cipherLen)) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), ptr+written, &tail) != 1) {
        wipe(out);
        throw Error("AES-GCM authentication failed");
    }
    out.resize(static_cast<std::size_t>(written + tail));
    return out;
}
void wipe(Bytes &bytes) noexcept {
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    bytes.clear();
}
} // namespace cqs::crypto
