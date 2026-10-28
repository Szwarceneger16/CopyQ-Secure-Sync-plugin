// SPDX-License-Identifier: GPL-3.0-or-later
#include "events.h"

#include <algorithm>
#include <array>
#include <utility>

namespace cqs::events {
namespace {
using crypto::Bytes;
[[noreturn]] void fail(ErrorCode code, const char *message) {
  throw Error(code, message);
}
void checkLimits(const Limits &v) {
  const Limits ceiling;
  if (!v.eventBytes || !v.plaintextBytes || !v.historyBytes ||
      !v.historyPlaintextBytes || v.eventBytes > ceiling.eventBytes ||
      v.plaintextBytes > ceiling.plaintextBytes || v.items > ceiling.items ||
      v.events > ceiling.events || v.historyBytes > ceiling.historyBytes ||
      v.historyPlaintextBytes > ceiling.historyPlaintextBytes)
    fail(ErrorCode::InvalidLimits, "Invalid event reader limits");
}
void checkKey(const Bytes &key) {
  if (key.size() != 32)
    fail(ErrorCode::InvalidKey, "K-SYNC must contain 32 bytes");
}
void account(std::size_t &total, std::size_t amount, std::size_t limit) {
  if (amount > limit - total)
    fail(ErrorCode::SizeLimit, "Event reader size limit exceeded");
  total += amount;
}

// A schema-directed JSON reader, not a general-purpose JSON DOM. v1 fields
// contain only ASCII identifiers, base64 and unsigned integers. No arbitrary
// nested values, floating point, duplicate members or Unicode names are valid.
// JSON escapes for ASCII (including escaped member names) are decoded before
// validation, so escape spelling cannot conceal duplicate members.
class Json final {
public:
  explicit Json(std::string_view text) : text_(text) {}
  template <class F> void object(F field) {
    expect('{');
    if (take('}'))
      return;
    for (;;) {
      const auto name = string(32);
      expect(':');
      field(name);
      if (take('}'))
        return;
      expect(',');
    }
  }
  std::string string(std::size_t limit) {
    expect('"');
    std::string out;
    while (pos_ < text_.size()) {
      unsigned char c = byte();
      if (c == '"')
        return out;
      if (c < 0x20 || c > 0x7e)
        invalid();
      if (c == '\\') {
        switch (byte()) {
        case '"':
          c = '"';
          break;
        case '\\':
          c = '\\';
          break;
        case '/':
          c = '/';
          break;
        case 'b':
          c = '\b';
          break;
        case 'f':
          c = '\f';
          break;
        case 'n':
          c = '\n';
          break;
        case 'r':
          c = '\r';
          break;
        case 't':
          c = '\t';
          break;
        case 'u': {
          unsigned value = 0;
          for (int i = 0; i < 4; ++i) {
            const auto h = byte();
            const int digit = h >= '0' && h <= '9'   ? h - '0'
                              : h >= 'a' && h <= 'f' ? h - 'a' + 10
                              : h >= 'A' && h <= 'F' ? h - 'A' + 10
                                                     : -1;
            if (digit < 0)
              invalid();
            value = value * 16 + static_cast<unsigned>(digit);
          }
          if (value > 0x7f)
            invalid();
          c = static_cast<unsigned char>(value);
          break;
        }
        default:
          invalid();
        }
      }
      if (out.size() == limit)
        fail(ErrorCode::SizeLimit, "JSON string exceeds limit");
      out.push_back(static_cast<char>(c));
    }
    invalid();
  }
  std::uint64_t number(std::uint64_t maximum) {
    space();
    if (pos_ == text_.size() || text_[pos_] < '0' || text_[pos_] > '9')
      invalid();
    const auto first = pos_;
    std::uint64_t result = 0;
    while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
      const auto digit = static_cast<unsigned>(text_[pos_++] - '0');
      if (pos_ > first + 1 && text_[first] == '0')
        invalid();
      if (digit > maximum || result > (maximum - digit) / 10)
        invalid();
      result = result * 10 + digit;
    }
    // The following field/array delimiter rejects decimals, exponents, etc.
    return result;
  }
  std::vector<std::string> strings(std::size_t count, std::size_t length,
                                   std::size_t budget) {
    std::vector<std::string> out;
    std::size_t total = 0;
    expect('[');
    if (take(']'))
      return out;
    for (;;) {
      if (out.size() == count)
        fail(ErrorCode::SizeLimit, "JSON array exceeds limit");
      auto value = string(std::min(length, budget - total));
      account(total, value.size(), budget);
      out.push_back(std::move(value));
      if (take(']'))
        return out;
      expect(',');
    }
  }
  void end() {
    space();
    if (pos_ != text_.size())
      invalid();
  }

private:
  [[noreturn]] static void invalid() {
    fail(ErrorCode::InvalidJson, "Invalid v1 JSON structure");
  }
  unsigned char byte() {
    if (pos_ == text_.size())
      invalid();
    return text_[pos_++];
  }
  void space() {
    while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\t' ||
                                   text_[pos_] == '\r' || text_[pos_] == '\n'))
      ++pos_;
  }
  bool take(char c) {
    space();
    if (pos_ < text_.size() && text_[pos_] == c) {
      ++pos_;
      return true;
    }
    return false;
  }
  void expect(char c) {
    if (!take(c))
      invalid();
  }
  std::string_view text_;
  std::size_t pos_ = 0;
};
void member(unsigned &seen, unsigned bit) {
  if (seen & bit)
    fail(ErrorCode::InvalidJson, "Duplicate JSON member");
  seen |= bit;
}
int sextet(unsigned char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}
std::size_t base64Size(std::string_view value) {
  const auto n = value.size();
  auto invalid = [] {
    fail(ErrorCode::InvalidBase64, "Invalid canonical base64");
  };
  if (n % 4)
    invalid();
  if (!n)
    return 0;
  const std::size_t pad =
      value[n - 1] == '=' ? (value[n - 2] == '=' ? 2 : 1) : 0;
  for (std::size_t i = 0; i < n - pad; ++i)
    if (sextet(value[i]) < 0)
      invalid();
  if ((pad == 2 && (sextet(value[n - 3]) & 15)) ||
      (pad == 1 && (sextet(value[n - 2]) & 3)))
    invalid();
  return n / 4 * 3 - pad;
}
Bytes unbase64(std::string_view value) {
  const auto size = base64Size(value);
  Bytes out;
  out.reserve(size);
  for (std::size_t i = 0; i < value.size(); i += 4) {
    const auto a = static_cast<unsigned>(sextet(value[i]));
    const auto b = static_cast<unsigned>(sextet(value[i + 1]));
    const auto c =
        value[i + 2] == '=' ? 0U : static_cast<unsigned>(sextet(value[i + 2]));
    const auto d =
        value[i + 3] == '=' ? 0U : static_cast<unsigned>(sextet(value[i + 3]));
    out.push_back(static_cast<std::uint8_t>((a << 2) | (b >> 4)));
    if (out.size() < size)
      out.push_back(static_cast<std::uint8_t>((b << 4) | (c >> 2)));
    if (out.size() < size)
      out.push_back(static_cast<std::uint8_t>((c << 6) | d));
  }
  return out;
}
history::Revision header(Json &json) {
  history::Revision out;
  std::string protocol;
  unsigned seen = 0;
  json.object([&](const std::string &name) {
    if (name == "protocol") {
      member(seen, 1);
      protocol = json.string(32);
    } else if (name == "device") {
      member(seen, 2);
      out.device = json.string(32);
    } else if (name == "seq") {
      member(seen, 4);
      out.sequence = json.number(history::MaxSequence);
    } else if (name == "parents") {
      member(seen, 8);
      out.parents = json.strings(2, 45, 90);
    } else
      fail(ErrorCode::InvalidHeader, "Unknown v1 header field");
  });
  if (seen != 15 || protocol != "copyq-secure-sync-v1")
    fail(ErrorCode::InvalidHeader, "Unsupported event header");
  try {
    out.id = history::makeId(out.device, out.sequence);
    history::validateRevision(out);
  } catch (const history::Error &) {
    fail(ErrorCode::InvalidHeader, "Invalid event revision metadata");
  }
  return out;
}
Bytes aad(const history::Revision &r) {
  // All strings have already passed the portable-ID grammar (no JSON escaping
  // needed). Key ordering matches Python json.dumps(sort_keys=True).
  std::string text = "{\"device\":\"" + r.device + "\",\"parents\":[";
  for (std::size_t i = 0; i < r.parents.size(); ++i) {
    if (i)
      text += ',';
    text += '"' + r.parents[i] + '"';
  }
  text += "],\"protocol\":\"copyq-secure-sync-v1\",\"seq\":" +
          std::to_string(r.sequence) + '}';
  constexpr char prefix[] = "CopyQ-Secure-Sync-event-v1";
  Bytes out(prefix,
            prefix + sizeof(prefix)); // include the NUL domain separator
  out.insert(out.end(), text.begin(), text.end());
  return out;
}
std::vector<std::string> payload(std::string_view text, const Limits &limits) {
  Json json(text);
  unsigned seen = 0;
  std::vector<std::string> items;
  json.object([&](const std::string &name) {
    if (name == "v") {
      member(seen, 1);
      if (json.number(1) != 1)
        fail(ErrorCode::InvalidPayload, "Unsupported payload version");
    } else if (name == "tab") {
      member(seen, 2);
      if (json.string(32) != "synced_tray")
        fail(ErrorCode::InvalidPayload, "Wrong v1 payload tab");
    } else if (name == "items") {
      member(seen, 4);
      items = json.strings(limits.items, limits.plaintextBytes,
                           limits.plaintextBytes);
    } else
      fail(ErrorCode::InvalidPayload, "Unknown payload field");
  });
  json.end();
  if (seen != 7)
    fail(ErrorCode::InvalidPayload, "Missing payload field");
  for (const auto &item : items)
    (void)base64Size(item);
  return items;
}
struct WipedBytes {
  Bytes bytes;
  ~WipedBytes() { crypto::wipe(bytes); }
};
std::vector<Event>
decodeAll(const Bytes &key, const std::vector<Envelope> &input, Limits limits) {
  checkLimits(limits);
  checkKey(key);
  if (input.size() > limits.events)
    fail(ErrorCode::SizeLimit, "Too many event envelopes");
  std::size_t wire = 0, plain = 0;
  // Check aggregate input size before any decryption/allocation of item data.
  for (const auto &e : input) {
    if (e.bytes.size() > limits.eventBytes)
      fail(ErrorCode::SizeLimit, "Event envelope exceeds limit");
    account(wire, e.bytes.size(), limits.historyBytes);
  }
  std::vector<Event> out;
  out.reserve(input.size());
  for (const auto &e : input) {
    auto perEvent = limits;
    const auto remaining = limits.historyPlaintextBytes - plain;
    if (!remaining)
      fail(ErrorCode::SizeLimit, "Decrypted history exceeds limit");
    perEvent.plaintextBytes = std::min(perEvent.plaintextBytes, remaining);
    auto decoded = decode(key, e, perEvent);
    account(plain, decoded.plaintextBytes, limits.historyPlaintextBytes);
    out.push_back(std::move(decoded));
  }
  return out;
}
std::vector<history::Revision> revisions(const std::vector<Event> &input) {
  std::vector<history::Revision> out;
  out.reserve(input.size());
  for (const auto &e : input)
    out.push_back(e.revision);
  return out;
}
} // namespace

Event decode(const Bytes &key, const Envelope &envelope, Limits limits) {
  checkLimits(limits);
  checkKey(key);
  if (envelope.bytes.size() > limits.eventBytes)
    fail(ErrorCode::SizeLimit, "Event envelope exceeds limit");
  Json json(envelope.bytes);
  history::Revision revision;
  std::string nonceText, cipherText;
  unsigned seen = 0;
  json.object([&](const std::string &name) {
    if (name == "header") {
      member(seen, 1);
      revision = header(json);
    } else if (name == "nonce") {
      member(seen, 2);
      nonceText = json.string(16);
    } else if (name == "ciphertext") {
      member(seen, 4);
      cipherText = json.string(limits.eventBytes);
    } else
      fail(ErrorCode::InvalidJson, "Unknown event envelope field");
  });
  json.end();
  if (seen != 7)
    fail(ErrorCode::InvalidJson, "Missing event envelope field");
  if (revision.id != envelope.expectedId)
    fail(ErrorCode::WrongIdentity, "Event file identity disagrees with header");
  const auto nonce = unbase64(nonceText);
  const auto cipher = unbase64(cipherText);
  if (nonce.size() != 12 || cipher.size() < 16)
    fail(ErrorCode::InvalidBase64,
         "Invalid nonce or authentication tag length");
  WipedBytes compressed;
  try {
    compressed.bytes =
        crypto::aes256GcmDecrypt(key, nonce, cipher, aad(revision));
  } catch (const crypto::Error &) {
    fail(ErrorCode::AuthenticationFailed, "Event authentication failed");
  }
  WipedBytes plain;
  try {
    plain.bytes =
        crypto::zlibDecompressBounded(compressed.bytes, limits.plaintextBytes);
  } catch (const crypto::Error &) {
    fail(ErrorCode::InvalidPayload, "Invalid or oversized compressed payload");
  }
  const std::string_view text(
      plain.bytes.empty() ? ""
                          : reinterpret_cast<const char *>(plain.bytes.data()),
      plain.bytes.size());
  auto items = payload(text, limits);
  return {std::move(revision), std::move(items), plain.bytes.size()};
}

Event read(const Bytes &key, const std::string &expectedId, std::istream &input,
           Limits limits) {
  checkLimits(limits);
  checkKey(key);
  std::string bytes;
  std::array<char, 16384> chunk{};
  try {
    for (;;) {
      const auto count =
          std::min(chunk.size(), limits.eventBytes - bytes.size() + 1);
      // An EOF exception after a short read is normal, including for
      // streams configured with failbit/eofbit exceptions. Process gcount
      // and the flags below; do not swallow non-EOF I/O failures.
      try {
        input.read(chunk.data(), static_cast<std::streamsize>(count));
      } catch (const std::ios_base::failure &) {
        if (input.bad() || !input.eof())
          throw;
      }
      const auto got = static_cast<std::size_t>(input.gcount());
      if (got > limits.eventBytes - bytes.size())
        fail(ErrorCode::SizeLimit, "Event stream exceeds limit");
      bytes.append(chunk.data(), got);
      if (input.bad() || (input.fail() && !input.eof()))
        fail(ErrorCode::ReadFailed, "Event stream read failed");
      if (input.eof())
        break;
    }
  } catch (const std::ios_base::failure &) {
    fail(ErrorCode::ReadFailed, "Event stream read failed");
  }
  return decode(key, {expectedId, bytes}, limits);
}

AuthenticatedHistory::AuthenticatedHistory(const Bytes &key,
                                           const std::vector<Envelope> &input,
                                           Limits limits)
    : events_(decodeAll(key, input, limits)), graph_(revisions(events_)) {
    for(const auto &envelope:input)wireBytes_+=envelope.bytes.size();
    for(const auto &event:events_)fingerprints_.emplace(event.revision.id,fingerprint(event));
}
} // namespace cqs::events
