// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
// Error paths rely on RAII to wipe secrets and release handles/leases. A build
// without C++ stack unwinding is unsafe, even when normal-path tests pass.
#if defined(_MSC_VER) && !defined(_CPPUNWIND)
#error Secure Sync requires MSVC C++ exception unwinding (/EHsc)
#endif
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace cqs::crypto {
using Bytes = std::vector<std::uint8_t>;
class Error final : public std::runtime_error {
public:
    explicit Error(const char *what) : std::runtime_error(what) {}
};
Bytes random(std::size_t n);
Bytes sha256(const Bytes &input);
// Bounded PBKDF2-HMAC-SHA256 for password-protected local key vaults.
Bytes passwordKey(const Bytes &password, const Bytes &salt, unsigned iterations);
Bytes aes256GcmEncrypt(const Bytes &key, const Bytes &nonce, const Bytes &plaintext, const Bytes &aad);
Bytes aes256GcmDecrypt(const Bytes &key, const Bytes &nonce, const Bytes &ciphertextWithTag, const Bytes &aad);
Bytes zlibCompress(const Bytes &input);
Bytes zlibDecompressBounded(const Bytes &input, std::size_t limit);
void wipe(Bytes &bytes) noexcept;
} // namespace cqs::crypto
