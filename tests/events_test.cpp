// SPDX-License-Identifier: GPL-3.0-or-later
#include "events.h"
#include "test_check.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <random>
#include <sstream>
#include <string>

namespace ev = cqs::events;
namespace hist = cqs::history;
using cqs::crypto::Bytes;
namespace {
int cases = 0;
Bytes bytes(const std::string &s) { return Bytes(s.begin(), s.end()); }
std::string b64(const Bytes &b) {
  constexpr char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string s;
  for (std::size_t i = 0; i < b.size(); i += 3) {
    const unsigned a = b[i], c = i + 1 < b.size() ? b[i + 1] : 0,
                   d = i + 2 < b.size() ? b[i + 2] : 0;
    s += table[a >> 2];
    s += table[((a & 3) << 4) | (c >> 4)];
    s += i + 1 < b.size() ? table[((c & 15) << 2) | (d >> 6)] : '=';
    s += i + 2 < b.size() ? table[d & 63] : '=';
  }
  return s;
}
Bytes key() {
  Bytes k(32);
  for (std::size_t i = 0; i < k.size(); ++i)
    k[i] = static_cast<std::uint8_t>(i);
  return k;
}
Bytes nonce() {
  Bytes n(12);
  for (std::size_t i = 0; i < n.size(); ++i)
    n[i] = static_cast<std::uint8_t>(i);
  return n;
}
std::string header(const std::string &device = "mint-lab",
                   std::uint64_t seq = 1,
                   const std::vector<std::string> &parents = {}) {
  std::string s = "{\"device\":\"" + device + "\",\"parents\":[";
  for (std::size_t i = 0; i < parents.size(); ++i) {
    if (i)
      s += ',';
    s += '"' + parents[i] + '"';
  }
  return s + "],\"protocol\":\"copyq-secure-sync-v1\",\"seq\":" +
         std::to_string(seq) + '}';
}
const std::string body =
    "{\"items\":[\"U1lOQ19URVNUXzAwMQ==\"],\"tab\":\"synced_tray\",\"v\":1}";
std::string sealCompressed(const Bytes &compressed,
                           const std::string &h = header()) {
  auto aad = bytes("CopyQ-Secure-Sync-event-v1");
  aad.push_back(0);
  aad.insert(aad.end(), h.begin(), h.end());
  const auto ciphertext =
      cqs::crypto::aes256GcmEncrypt(key(), nonce(), compressed, aad);
  return "{\"ciphertext\":\"" + b64(ciphertext) + "\",\"header\":" + h +
         ",\"nonce\":\"" + b64(nonce()) + "\"}";
}
// Fixed key/nonce ONLY in deterministic tests; no production writer is
// provided.
std::string seal(const std::string &p = body, const std::string &h = header()) {
  return sealCompressed(cqs::crypto::zlibCompress(bytes(p)), h);
}
std::string replace(std::string s, const std::string &old,
                    const std::string &value) {
  const auto p = s.find(old);
  CHECK(p != std::string::npos);
  s.replace(p, old.size(), value);
  return s;
}
void test(const char *name, const std::function<void()> &f) {
  f();
  ++cases;
  std::cout << "PASS " << name << '\n';
}
void rejected(const std::function<void()> &f) {
  bool threw = false;
  try {
    f();
  } catch (const ev::Error &e) {
    threw = true;
    CHECK(std::string(e.what()).find("SECRET_SENTINEL") == std::string::npos);
  }
  CHECK(threw);
}
void code(ev::ErrorCode c, const std::function<void()> &f) {
  bool threw = false;
  try {
    f();
  } catch (const ev::Error &e) {
    threw = true;
    CHECK(e.code() == c);
  }
  CHECK(threw);
}
void graphError(hist::ErrorCode c, const std::function<void()> &f) {
  bool threw = false;
  try {
    f();
  } catch (const hist::Error &e) {
    threw = true;
    CHECK(e.code() == c);
  }
  CHECK(threw);
}
std::string load(const std::string &root, const char *name) {
  std::ifstream in(root + '/' + name, std::ios::binary);
  CHECK(in.good());
  return std::string(std::istreambuf_iterator<char>(in), {});
}
} // namespace
int main(int argc, char **argv) {
  CHECK(argc == 2);
  const auto frozen = load(argv[1], "mint-lab-000000000001.cqs");
  const auto empty = load(argv[1], "win-lab-000000000001.cqs");
  const auto binary = load(argv[1], "binary-pc-000000000001.cqs");
  const std::string id = "mint-lab/000000000001",
                    child = "win-lab/000000000001";
  const auto good = seal();
  auto decode = [&](const std::string &s) {
    return ev::decode(key(), {id, s});
  };
  test("frozen Python 0.1.1 root", [&] {
    auto e = decode(frozen);
    CHECK(e.revision.id == id);
    CHECK(e.items == std::vector<std::string>{"U1lOQ19URVNUXzAwMQ=="});
    CHECK(e.plaintextBytes == body.size());
  });
  test("frozen Python empty snapshot", [&] {
    auto e = ev::decode(key(), {child, empty});
    CHECK(e.items.empty());
    CHECK(e.revision.parents == std::vector<std::string>{id});
  });
  test("opaque binary, UTF-8 and zero-byte item preserved", [&] {
    auto e = ev::decode(key(), {"binary-pc/000000000001", binary});
    CHECK(e.items.size() == 3);
    Bytes all(256);
    for (std::size_t i = 0; i < all.size(); ++i)
      all[i] = static_cast<std::uint8_t>(i);
    CHECK(e.items[0] == b64(all));
    CHECK(e.items[1] == "WmHFvMOzxYLEhyBnxJnFm2zEhSBqYcW6xYQNCvCfmYIA");
    CHECK(e.items[2].empty());
  });
  test("C++ fixture encryption matches Python",
       [&] { CHECK(frozen == good + '\n'); });
  test("JSON whitespace and field order", [&] {
    const auto reordered =
        " \r\n { \"nonce\" : \"AAECAwQFBgcICQoL\", \"header\" : "
        "{\"seq\":1,\"protocol\":\"copyq-secure-sync-v1\",\"parents\":[],"
        "\"device\":\"mint-lab\"},\"ciphertext\":" +
        good.substr(good.find(':') + 1,
                    good.find(",\"header\"") - good.find(':') - 1) +
        " } \t";
    CHECK(decode(reordered).items == decode(good).items);
  });
  test("ASCII JSON escapes canonicalized for AAD", [&] {
    CHECK(decode(replace(good, "mint-lab", "m\\u0069nt-lab")).items ==
          decode(good).items);
    CHECK(decode(replace(good, "header", "he\\u0061der")).items ==
          decode(good).items);
  });
  test("invalid key sizes", [&] {
    for (auto n : {0, 1, 31, 33})
      code(ev::ErrorCode::InvalidKey,
           [&] { ev::decode(Bytes(n), {id, good}); });
  });
  test("wrong key authentication", [&] {
    auto k = key();
    k[0] ^= 1;
    code(ev::ErrorCode::AuthenticationFailed,
         [&] { ev::decode(k, {id, good}); });
  });
  test("header AAD modification", [&] {
    auto altered = replace(good, "mint-lab", "other-pc");
    code(ev::ErrorCode::AuthenticationFailed,
         [&] { ev::decode(key(), {"other-pc/000000000001", altered}); });
  });
  test("sequence AAD modification", [&] {
    auto altered = replace(good, "\"seq\":1", "\"seq\":2");
    code(ev::ErrorCode::AuthenticationFailed,
         [&] { ev::decode(key(), {"mint-lab/000000000002", altered}); });
  });
  test("parent AAD modification", [&] {
    code(ev::ErrorCode::AuthenticationFailed, [&] {
      decode(replace(good, "\"parents\":[]",
                     "\"parents\":[\"other-pc/000000000001\"]"));
    });
  });
  test("ciphertext and tag modification", [&] {
    for (auto offset : {std::size_t{0}, std::size_t{100}}) {
      auto a = good;
      auto p = a.find(':') + 2 + offset;
      a[p] = a[p] == 'A' ? 'B' : 'A';
      code(ev::ErrorCode::AuthenticationFailed, [&] { decode(a); });
    }
  });
  test("nonce modification", [&] {
    code(ev::ErrorCode::AuthenticationFailed, [&] {
      decode(replace(good, "AAECAwQFBgcICQoL", "BAECAwQFBgcICQoL"));
    });
  });
  test("expected file identity bound to header", [&] {
    for (const auto &bad :
         {child, std::string("../mint/000000000001"), std::string()})
      code(ev::ErrorCode::WrongIdentity,
           [&] { ev::decode(key(), {bad, good}); });
  });
  test("truncated envelope at every offset", [&] {
    for (std::size_t i = 0; i < good.size(); ++i)
      rejected([&] { decode(good.substr(0, i)); });
  });
  test("trailing input rejected", [&] {
    for (auto suffix : {"{}", "true", ",", "/", "\f"})
      rejected([&] { decode(good + suffix); });
    rejected([&] { decode(good + std::string(1, '\0')); });
  });
  test("unknown envelope fields", [&] {
    rejected([&] { decode(replace(good, "{", "{\"SECRET_SENTINEL\":0,")); });
  });
  test("duplicate envelope fields including escapes", [&] {
    rejected([&] {
      decode(replace(good, "{", "{\"nonce\":\"AAECAwQFBgcICQoL\","));
    });
    rejected([&] {
      decode(replace(good, "{", "{\"no\\u006ece\":\"AAECAwQFBgcICQoL\","));
    });
  });
  test("missing fields and wrong top-level types", [&] {
    for (auto s : {"{}", "[]", "null", "0", "\"x\"", "{\"header\":null}"})
      rejected([&] { decode(s); });
  });
  test("duplicate and unknown header fields", [&] {
    for (auto insert : {"\"device\":\"mint-lab\",",
                        "\"de\\u0076ice\":\"mint-lab\",", "\"extra\":0,"})
      rejected([&] {
        decode(replace(good, "\"header\":{",
                       std::string("\"header\":{") + insert));
      });
  });
  test("unsupported protocol", [&] {
    rejected([&] {
      decode(replace(good, "copyq-secure-sync-v1", "copyq-secure-sync-v2"));
    });
  });
  test("strict integer sequence grammar", [&] {
    for (auto n : {"0", "-1", "01", "1.0", "1e0", "true", "null", "\"1\"",
                   "1000000000000", "999999999999999999999999"})
      rejected([&] {
        decode(replace(good, "\"seq\":1", std::string("\"seq\":") + n));
      });
  });
  test("strict portable device grammar", [&] {
    for (auto dev : {"ab", "Aaa", "a_b", "../x", "ab\\u0000", "ab\\n",
                     "\\u00e9aa", "\\ud800"})
      rejected([&] { decode(replace(good, "mint-lab", dev)); });
  });
  test("strict parent schema", [&] {
    for (auto p : {"[\"mint-lab/000000000001\"]", "[\"mint-lab/000000000002\"]",
                   "[\"other-pc/000000000001\",\"other-pc/000000000001\"]",
                   "[\"zzz-pc/000000000001\",\"aaa-pc/000000000001\"]",
                   "[\"a/1\"]", "[1]", "null", "[] []"})
      rejected([&] {
        decode(
            replace(good, "\"parents\":[]", std::string("\"parents\":") + p));
      });
  });
  test("nonce encoding and length", [&] {
    for (auto n : {"", "====", "AAECAwQFBgcICQo=", "AAECAwQFBgcICQoL=",
                   "AAECAwQFBgcICQ-L", "AAECAwQFBgcICQ L"})
      rejected([&] { decode(replace(good, "AAECAwQFBgcICQoL", n)); });
  });
  test("invalid ciphertext base64 and short tag", [&] {
    const auto start = good.find(":") + 2;
    const auto end = good.find(",\"header\"") - 1;
    for (auto val : {"", "AA==", "AB==", "AAF=", "====", "AAA", "AA=A", "AAA_",
                     "AAAA=", "AAA\\n"}) {
      auto a = good;
      a.replace(start, end - start, val);
      code(ev::ErrorCode::InvalidBase64, [&] { decode(a); });
    }
  });
  test("authenticated malformed compression", [&] {
    rejected([&] { decode(sealCompressed({1, 2, 3})); });
    auto compressed = cqs::crypto::zlibCompress(bytes(body));
    compressed.pop_back();
    rejected([&] { decode(sealCompressed(compressed)); });
  });
  test("authenticated concatenated streams and trailing data", [&] {
    auto c = cqs::crypto::zlibCompress(bytes(body));
    auto second = c;
    second.insert(second.end(), c.begin(), c.end());
    rejected([&] { decode(sealCompressed(second)); });
    c.push_back(0);
    rejected([&] { decode(sealCompressed(c)); });
  });
  test("decompression size ceiling", [&] {
    ev::Limits l;
    l.plaintextBytes = body.size() - 1;
    rejected([&] { ev::decode(key(), {id, good}, l); });
    l.plaintextBytes = body.size();
    CHECK(ev::decode(key(), {id, good}, l).items.size() == 1);
  });
  test("high compression ratio cannot exceed budget", [&] {
    const auto bomb = seal(std::string(1024 * 1024, ' '));
    ev::Limits l;
    l.plaintextBytes = 100;
    rejected([&] { ev::decode(key(), {id, bomb}, l); });
  });
  test("authenticated payload schema", [&] {
    for (auto p :
         {"{}", "[]", "null", "{\"items\":[],\"tab\":\"other\",\"v\":1}",
          "{\"items\":[],\"tab\":\"synced_tray\",\"v\":true}",
          "{\"items\":[],\"tab\":\"synced_tray\",\"v\":2}",
          "{\"items\":null,\"tab\":\"synced_tray\",\"v\":1}"})
      rejected([&] { decode(seal(p)); });
  });
  test("authenticated duplicate payload members", [&] {
    rejected([&] { decode(seal(replace(body, "{", "{\"v\":1,"))); });
    rejected([&] { decode(seal(replace(body, "{", "{\"\\u0076\":1,"))); });
  });
  test("authenticated unknown payload field", [&] {
    rejected(
        [&] { decode(seal(replace(body, "{", "{\"SECRET_SENTINEL\":0,"))); });
  });
  test("authenticated invalid base64 items", [&] {
    for (auto item : {"AB==", "AAF=", "a", "====", "AA-A", "AA A", "AAA\\n"})
      rejected(
          [&] { decode(seal(replace(body, "U1lOQ19URVNUXzAwMQ==", item))); });
  });
  test("authenticated unsupported item types", [&] {
    for (auto item : {"null", "1", "true", "[]", "{}"})
      rejected([&] {
        decode(seal(replace(body, "\"U1lOQ19URVNUXzAwMQ==\"", item)));
      });
  });
  test("deep nesting, BOM and malformed escape rejected", [&] {
    for (auto p : {"{\"items\":[[[[[[]]]]]],\"tab\":\"synced_tray\",\"v\":1}",
                   "{\"items\":[\"\\x41\"],\"tab\":\"synced_tray\",\"v\":1}"})
      rejected([&] { decode(seal(p)); });
    rejected([&] { decode(std::string("\xef\xbb\xbf") + good); });
  });
  test("item count limit including zero", [&] {
    ev::Limits l;
    l.items = 0;
    rejected([&] { ev::decode(key(), {id, good}, l); });
    CHECK(ev::decode(key(), {child, empty}, l).items.empty());
  });
  test("envelope ceiling exact boundary", [&] {
    ev::Limits l;
    l.eventBytes = good.size();
    CHECK(ev::decode(key(), {id, good}, l).items.size() == 1);
    --l.eventBytes;
    code(ev::ErrorCode::SizeLimit, [&] { ev::decode(key(), {id, good}, l); });
  });
  test("limits cannot be raised or disabled", [&] {
    ev::Limits l;
    l.eventBytes = 0;
    code(ev::ErrorCode::InvalidLimits,
         [&] { ev::decode(key(), {id, good}, l); });
    l = {};
    ++l.plaintextBytes;
    code(ev::ErrorCode::InvalidLimits,
         [&] { ev::decode(key(), {id, good}, l); });
    l = {};
    ++l.events;
    code(ev::ErrorCode::InvalidLimits,
         [&] { ev::decode(key(), {id, good}, l); });
  });
  test("bounded binary stream", [&] {
    std::istringstream in(frozen);
    CHECK(ev::read(key(), id, in).items == decode(frozen).items);
  });
  test("bounded stream rejects oversize and failures", [&] {
    ev::Limits l;
    l.eventBytes = good.size();
    std::istringstream in(good + ' ');
    code(ev::ErrorCode::SizeLimit, [&] { ev::read(key(), id, in, l); });
    std::istringstream bad(good);
    bad.setstate(std::ios::badbit);
    code(ev::ErrorCode::ReadFailed, [&] { ev::read(key(), id, bad); });
  });
  test("finite file stream and exception-enabled EOF", [&] {
    std::ifstream in(std::string(argv[1]) + "/mint-lab-000000000001.cqs",
                     std::ios::binary);
    CHECK(in.good());
    in.exceptions(std::ios::badbit | std::ios::failbit);
    CHECK(ev::read(key(), id, in).items == decode(frozen).items);
  });
  test("multiple stream chunks and exact boundary", [&] {
    auto longWire = good + std::string(32768, ' ');
    ev::Limits l;
    l.eventBytes = longWire.size();
    std::istringstream in(longWire);
    CHECK(ev::read(key(), id, in, l).items.size() == 1);
    std::istringstream tooLong(longWire + ' ');
    code(ev::ErrorCode::SizeLimit, [&] { ev::read(key(), id, tooLong, l); });
  });
  test("production item-count boundary", [&] {
    std::string list = "[";
    for (int i = 0; i < 10000; ++i) {
      if (i)
        list += ',';
      list += "\"AA==\"";
    }
    list += ']';
    const auto full = replace(body, "[\"U1lOQ19URVNUXzAwMQ==\"]", list);
    CHECK(decode(seal(full)).items.size() == 10000);
    list.insert(1, "\"AA==\",");
    rejected([&] {
      decode(seal(replace(body, "[\"U1lOQ19URVNUXzAwMQ==\"]", list)));
    });
  });
  test("history authenticates before constructing DAG", [&] {
    ev::AuthenticatedHistory h(key(), {{child, empty}, {id, frozen}});
    CHECK(h.graph().size() == 2);
    CHECK(h.graph().isAncestor(id, child));
    CHECK(h.graph().tips() == std::vector<std::string>{child});
    CHECK(h.events()[0].items.empty());
  });
  test("empty authenticated history", [&] {
    ev::AuthenticatedHistory h(key(), {});
    CHECK(h.graph().size() == 0);
    CHECK(h.events().empty());
  });
  test("missing authenticated parent deferred", [&] {
    graphError(hist::ErrorCode::MissingParent,
               [&] { ev::AuthenticatedHistory h(key(), {{child, empty}}); });
  });
  test("bad authentication never becomes MissingParent", [&] {
    auto corrupt = replace(empty, "AAECAwQFBgcICQoL", "BAECAwQFBgcICQoL");
    code(ev::ErrorCode::AuthenticationFailed,
         [&] { ev::AuthenticatedHistory h(key(), {{child, corrupt}}); });
  });
  test("duplicate authenticated identities rejected", [&] {
    graphError(hist::ErrorCode::DuplicateRevision, [&] {
      ev::AuthenticatedHistory h(key(), {{id, good}, {id, good}});
    });
  });
  test("authenticated branches preserved and merge recognized", [&] {
    const std::string forkId = "mint-lab/000000000002",
                      mergeId = "win-lab/000000000002";
    const auto fork = seal(body, header("mint-lab", 2, {id}));
    const auto merge = seal(body, header("win-lab", 2, {forkId, child}));
    ev::AuthenticatedHistory h(key(),
                               {{id, good}, {child, empty}, {forkId, fork}});
    CHECK(h.graph().hasConflict());
    ev::AuthenticatedHistory merged(
        key(), {{mergeId, merge}, {id, good}, {forkId, fork}, {child, empty}});
    CHECK(!merged.graph().hasConflict());
    CHECK(merged.graph().tips() == std::vector<std::string>{mergeId});
  });
  test("authenticated cross-device cycle rejected", [&] {
    auto a = seal(body, header("mint-lab", 1, {child}));
    graphError(hist::ErrorCode::Cycle, [&] {
      ev::AuthenticatedHistory h(key(), {{id, a}, {child, empty}});
    });
  });
  test("encrypted history byte budget", [&] {
    ev::Limits l;
    l.historyBytes = good.size() + empty.size() - 1;
    code(ev::ErrorCode::SizeLimit, [&] {
      ev::AuthenticatedHistory h(key(), {{id, good}, {child, empty}}, l);
    });
    ++l.historyBytes;
    CHECK(ev::AuthenticatedHistory(key(), {{id, good}, {child, empty}}, l)
              .graph()
              .size() == 2);
  });
  test("decrypted history budget enforced before next allocation", [&] {
    ev::Limits l;
    l.historyPlaintextBytes = decode(good).plaintextBytes +
                              ev::decode(key(), {child, empty}).plaintextBytes;
    CHECK(ev::AuthenticatedHistory(key(), {{id, good}, {child, empty}}, l)
              .events()
              .size() == 2);
    --l.historyPlaintextBytes;
    rejected([&] {
      ev::AuthenticatedHistory h(key(), {{id, good}, {child, empty}}, l);
    });
  });
  test("history event-count ceiling", [&] {
    ev::Limits l;
    l.events = 0;
    code(ev::ErrorCode::SizeLimit,
         [&] { ev::AuthenticatedHistory h(key(), {{id, good}}, l); });
    CHECK(ev::AuthenticatedHistory(key(), {}, l).events().empty());
  });
  test("10000 deterministic malformed-input samples", [&] {
    std::mt19937 rng(0x43515332);
    for (int i = 0; i < 10000; ++i) {
      std::string s(rng() % 1024, ' ');
      for (auto &c : s)
        c = static_cast<char>(rng() % 256);
      rejected([&] { decode(s); });
    }
  });
  test("10000 envelope mutations never expose unauthenticated items", [&] {
    std::mt19937 rng(0x43515333);
    for (int i = 0; i < 10000; ++i) {
      auto s = good;
      s[rng() % s.size()] = static_cast<char>(rng() % 128);
      try {
        auto e = decode(s);
        CHECK(e.revision.id == id);
        CHECK(e.items == decode(good).items);
      } catch (const ev::Error &) {
      }
    }
  });
  std::cout << cases << " event test cases passed\n";
}
