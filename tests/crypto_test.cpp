// SPDX-License-Identifier: GPL-3.0-or-later
#include "crypto.h"
#include "test_check.h"
#include <iostream>
#include <utility>

namespace {
template <typename Operation>
void rejects(Operation &&operation) {
    bool rejected = false;
    try {
        std::forward<Operation>(operation)();
    } catch (const cqs::crypto::Error &) {
        rejected = true;
    }
    CHECK(rejected);
}
}

int main() {
    using namespace cqs::crypto;
    // FIPS 180-4 SHA-256("abc"), independent of the active platform provider.
    CHECK(sha256(Bytes{'a','b','c'})==Bytes({0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad}));
    // Fixed keys/nonces are synthetic test vectors, never production credentials.
    const Bytes key(32, 0), nonce(12, 0), aad{'x', 'y', 'z'};
    Bytes text{'s', 'e', 'c', 'r', 'e', 't', 0, '!', 0xFF};
    const auto ciphertext = aes256GcmEncrypt(key, nonce, text, aad);

    CHECK(ciphertext.size() == text.size() + 16);
    CHECK(aes256GcmDecrypt(key, nonce, ciphertext, aad) == text);

    auto tampered = ciphertext;
    tampered.front() ^= 1;
    rejects([&] { (void)aes256GcmDecrypt(key, nonce, tampered, aad); });
    tampered = ciphertext;
    tampered.back() ^= 1;
    rejects([&] { (void)aes256GcmDecrypt(key, nonce, tampered, aad); });
    rejects([&] { (void)aes256GcmDecrypt(key, nonce, ciphertext, Bytes{'n', 'o'}); });
    auto wrongKey = key;
    wrongKey.front() ^= 1;
    rejects([&] { (void)aes256GcmDecrypt(wrongKey, nonce, ciphertext, aad); });
    rejects([&] { (void)aes256GcmEncrypt(Bytes(31), nonce, text, aad); });
    rejects([&] { (void)aes256GcmEncrypt(key, Bytes(11), text, aad); });
    rejects([&] { (void)aes256GcmDecrypt(key, nonce, Bytes(15), aad); });

    // A new/empty tab must also round-trip and authenticate successfully.
    const Bytes empty;
    CHECK(aes256GcmDecrypt(key, nonce, aes256GcmEncrypt(key, nonce, empty, aad), aad).empty());
    CHECK(aes256GcmDecrypt(key, nonce, aes256GcmEncrypt(key, nonce, empty, empty), empty).empty());

    const auto compressed = zlibCompress(text);
    CHECK(zlibDecompressBounded(compressed, 1000) == text);
    CHECK(zlibDecompressBounded(zlibCompress(empty), 0).empty());
    CHECK(zlibDecompressBounded(compressed, text.size()) == text);
    rejects([&] { (void)zlibDecompressBounded(compressed, text.size() - 1); });
    auto invalid = compressed;
    invalid.push_back(0);
    rejects([&] { (void)zlibDecompressBounded(invalid, 1000); });
    invalid = compressed;
    invalid.pop_back();
    rejects([&] { (void)zlibDecompressBounded(invalid, 1000); });

    CHECK(random(32).size() == 32);
    rejects([] { (void)random(0); });
    wipe(text);
    CHECK(text.empty());
    std::cout << "PASS 20 portable cryptographic checks\n";
}
