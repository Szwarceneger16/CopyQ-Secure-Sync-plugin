// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "import_transaction.h"

namespace cqs::state {
struct Limits {
    // Aggregate plaintext record, including repeated checkpoint/backup data.
    // The 36-byte AEAD envelope overhead is accounted for separately.
    std::size_t recordBytes = 128 * 1024 * 1024;
    transaction::Limits snapshot;
};
enum class ErrorCode {
    InvalidLimits, InvalidKey, InvalidRecord, WrongBinding, AuthenticationFailed,
    SizeLimit, Missing, UnsafePath, Io, Busy, LeaseRequired, Changed, Stale,
    AlreadyInitialized, Generation, UnsupportedFilesystem, CommitUnconfirmed
};
class Error final : public std::runtime_error {
public:
    Error(ErrorCode code, const char *text) : std::runtime_error(text), code_(code) {}
    ErrorCode code() const noexcept { return code_; }
private:
    ErrorCode code_;
};
inline constexpr std::size_t EnvelopeOverhead = 36;
enum class Protection { Key, Password };
inline constexpr unsigned PasswordIterations = 600000;
inline constexpr std::size_t PasswordEnvelopeOverhead = 56;
inline std::size_t envelopeOverhead(Protection p) { return p == Protection::Password ? PasswordEnvelopeOverhead : EnvelopeOverhead; }
void validateSecret(const crypto::Bytes &secret, Protection protection);
void validateLimits(Limits limits);
void validateBinding(const std::string &binding);
// Memory-only canonical binary codec. Returned bytes contain secrets: never
// write them to disk/logs. All on-disk records MUST go through seal().
crypto::Bytes serialize(const transaction::Record &record, Limits limits = {});
transaction::Record parse(const crypto::Bytes &plain, Limits limits = {});
// AES-256-GCM, random 96-bit nonce, distinct state-domain AAD bound to binding.
// No deterministic nonce/counter option exists in the production API.
crypto::Bytes seal(const crypto::Bytes &key, const std::string &binding,
                  const transaction::Record &record, Limits limits = {}, Protection protection = Protection::Key);
transaction::Record unseal(const crypto::Bytes &key, const std::string &binding,
                          const crypto::Bytes &wire, Limits limits = {}, Protection protection = Protection::Key);
} // namespace cqs::state
