// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "crypto.h"
#include "history.h"
#include <istream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace cqs::events {

// v1 protocol ceilings. Callers may lower, but never raise, these limits.
struct Limits {
  std::size_t eventBytes = 25 * 1024 * 1024;
  std::size_t plaintextBytes = 32 * 1024 * 1024;
  std::size_t items = 10000;
  std::size_t historyBytes = 256 * 1024 * 1024;
  std::size_t historyPlaintextBytes = 256 * 1024 * 1024;
  std::size_t events = history::MaxEvents;
};

enum class ErrorCode {
  InvalidLimits,
  InvalidKey,
  SizeLimit,
  InvalidJson,
  InvalidHeader,
  InvalidBase64,
  WrongIdentity,
  AuthenticationFailed,
  InvalidPayload,
  ReadFailed
};
class Error final : public std::runtime_error {
public:
  Error(ErrorCode code, const char *message)
      : std::runtime_error(message), code_(code) {}
  ErrorCode code() const noexcept { return code_; }

private:
  ErrorCode code_;
};

struct Event {
  history::Revision revision;
  // Opaque base64-encoded CopyQ items; NOT yet approved for import into CopyQ.
  // Transport authentication is distinct from semantic MIME validation.
  std::vector<std::string> items;
  std::size_t plaintextBytes = 0;
};
inline crypto::Bytes fingerprint(const Event &event) {
    // Domain separated, length framed semantic data. JSON whitespace, member
    // order, nonce and compression are deliberately not event identity.
    crypto::Bytes input;
    struct Wipe {crypto::Bytes &b;~Wipe(){crypto::wipe(b);}} wipe{input};
    auto number=[&](std::uint64_t n){for(int shift=56;shift>=0;shift-=8)input.push_back(std::uint8_t(n>>shift));};
    auto field=[&](const std::string &v){number(v.size());input.insert(input.end(),v.begin(),v.end());};
    field("CopyQ-Secure-Sync-observed-event-v1");field(event.revision.id);
    field(event.revision.device);number(event.revision.sequence);
    number(event.revision.parents.size());for(const auto &p:event.revision.parents)field(p);
    number(event.items.size());for(const auto &item:event.items)field(item);
    return crypto::sha256(input);
}
struct Envelope {
  // Must come from the independently checked file identity, not its JSON
  // header.
  std::string expectedId;
  std::string_view bytes;
};

Event decode(const crypto::Bytes &key, const Envelope &envelope,
             Limits limits = {});
// Read only an already-open, finite binary stream. No path opening or directory
// traversal here. The filesystem adapter must forbid symlinks/reparse points,
// special files and concurrent mutation; it must also enforce a scan budget.
Event read(const crypto::Bytes &key, const std::string &expectedId,
           std::istream &input, Limits limits = {});

// Does not return a partial graph on any error. All envelopes must authenticate
// before history validation may report MissingParent, Cycle or multiple tips.
// No writes, callbacks, state updates, key storage or CopyQ operations occur.
class AuthenticatedHistory final {
public:
  AuthenticatedHistory(const crypto::Bytes &key,
                       const std::vector<Envelope> &input, Limits limits = {});
  std::size_t wireBytes() const noexcept { return wireBytes_; }
  const history::Graph &graph() const noexcept { return graph_; }
  const std::map<std::string,crypto::Bytes> &fingerprints() const noexcept { return fingerprints_; }
  const std::vector<Event> &events() const noexcept { return events_; }

private:
  std::vector<Event> events_;
  history::Graph graph_;
  std::size_t wireBytes_=0;
  std::map<std::string,crypto::Bytes> fingerprints_;
};

} // namespace cqs::events
