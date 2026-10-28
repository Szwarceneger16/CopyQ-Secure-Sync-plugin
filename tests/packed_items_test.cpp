// SPDX-License-Identifier: GPL-3.0-or-later
#include "packed_items.h"
#include "test_check.h"
#include <functional>
#include <iostream>
#include <tuple>

using cqs::crypto::Bytes;
using cqs::packed::decode;
using cqs::transaction::Limits;
namespace {
int passed = 0;
void u32(Bytes &out, std::uint32_t n) { for (int i = 24; i >= 0; i -= 8) out.push_back(static_cast<std::uint8_t>(n >> i)); }
void string(Bytes &out, const std::string &s) { u32(out, static_cast<std::uint32_t>(s.size() * 2)); for (auto c : s) { out.push_back(0); out.push_back(c); } }
void value(Bytes &out, const Bytes &v) { u32(out, static_cast<std::uint32_t>(v.size())); out.insert(out.end(), v.begin(), v.end()); }
Bytes compressed(const Bytes &data) { Bytes out; u32(out, static_cast<std::uint32_t>(data.size())); const auto z = cqs::crypto::zlibCompress(data); out.insert(out.end(), z.begin(), z.end()); return out; }
std::string b64(const Bytes &data) {
    constexpr char abc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < data.size(); i += 3) {
        const unsigned a = data[i], b = i + 1 < data.size() ? data[i + 1] : 0, c = i + 2 < data.size() ? data[i + 2] : 0;
        out += abc[a >> 2]; out += abc[((a & 3) << 4) | (b >> 4)];
        out += i + 1 < data.size() ? abc[((b & 15) << 2) | (c >> 6)] : '=';
        out += i + 2 < data.size() ? abc[c & 63] : '=';
    }
    return out;
}
using Field = std::tuple<std::string, Bytes, bool>;
Bytes wire(const std::vector<Field> &fields, bool legacy = false) {
    Bytes out; if (!legacy) u32(out, 0xfffffffeU); u32(out, static_cast<std::uint32_t>(fields.size()));
    for (const auto &f : fields) { string(out, std::get<0>(f)); if (!legacy) out.push_back(std::get<2>(f) ? 1 : 0); value(out, std::get<1>(f)); }
    return out;
}
void reject(const std::function<void()> &body) { bool caught = false; try { body(); } catch (const cqs::packed::Error &) { caught = true; } CHECK(caught); }
void rejects(const Bytes &bytes, Limits limits = {}) { reject([&] { decode({b64(bytes)}, limits); }); }
void test(const char *name, const std::function<void()> &body) { std::cout << "RUN " << name << std::endl; body(); ++passed; std::cout << "PASS " << name << std::endl; }
}
int main() {
    test("empty tab differs from one empty item", [] { CHECK(decode({}).empty()); CHECK(decode({b64(wire({}))}).size() == 1); });
    test("alternate MIME prefixes have equal effective data", [] {
        const auto a = decode({b64(wire({{"4", {1, 0, 255}, false}}))});
        CHECK(a == decode({b64(wire({{"8plain", {1, 0, 255}, false}}))}));
        CHECK(a == decode({b64(wire({{"0text/plain", {1, 0, 255}, false}}))}));
    });
    test("every pinned MIME prefix expands", [] {
        const std::vector<std::string> names{"custom/mime", "application/x-copyq-owner-window-title", "application/x-copyq-item-notes",
            "application/x-copyq-custom", "text/plain", "text/html", "text/uri-list", "image/png", "text/custom", "application/pdf", "audio/wav", "video/mp4"};
        const std::vector<std::string> shortNames{"0custom/mime", "1", "2", "3custom", "4", "5", "6", "7png", "8custom", "9pdf", "awav", "Bmp4"};
        for (std::size_t i = 0; i < names.size(); ++i) CHECK(decode({b64(wire({{shortNames[i], {}, false}}))})[0].count(names[i]) == 1);
    });
    test("binary NUL CRLF and UTF-8 payload are preserved", [] { Bytes bytes{0, 255, 13, 10, 0xc5, 0xbc}; CHECK(decode({b64(wire({{"4", bytes, false}}))})[0].at("text/plain") == bytes); });
    test("item order and MIME presence are significant", [] {
        const auto a = b64(wire({{"4", {1}, false}})), b = b64(wire({{"4", {}, false}}));
        CHECK(decode({a,b}) != decode({b,a})); CHECK(decode({b}) != decode({b64(wire({}))}));
    });
    test("null byte array is effective empty data", [] { auto bytes = wire({{"4", {}, false}}); for (std::size_t i = bytes.size() - 4; i < bytes.size(); ++i) bytes[i] = 255; CHECK(decode({b64(bytes)})[0].at("text/plain").empty()); });
    test("legacy compressed and empty fields", [] { const Bytes v{0, 13, 255}; CHECK(decode({b64(wire({{"text/plain", compressed(v), false}}, true))})[0].at("text/plain") == v); CHECK(decode({b64(wire({{"text/plain", {}, false}}, true))})[0].at("text/plain").empty()); });
    test("v2 compressed values", [] { const Bytes v(2048, 65); CHECK(decode({b64(wire({{"4", compressed(v), true}}))})[0].at("text/plain") == v); });
    test("duplicate effective MIME names rejected", [] { rejects(wire({{"4", {}, false}, {"8plain", {}, false}})); rejects(wire({{"text/plain", {}, false}, {"text/plain", {}, false}}, true)); });
    test("FILE references rejected in both formats", [] { rejects(wire({{"0FILE:text/plain", {'x'}, false}})); rejects(wire({{"FILE:text/plain", {}, false}}, true)); });
    test("odd and NULL QString lengths rejected", [] { auto bytes = wire({{"4", {}, false}}); bytes[11] = 1; rejects(bytes); for (int i=8;i<12;++i) bytes[i]=255; rejects(bytes); });
    test("non-ASCII and control MIME names rejected", [] { auto bytes = wire({{"4", {}, false}}); bytes[12] = 1; rejects(bytes); rejects(wire({{"0text/ bad", {}, false}})); });
    test("unknown prefix IDs rejected", [] { for (auto id : {"c", "f", "z", "-"}) rejects(wire({{id, {}, false}})); });
    test("encrypted and unknown stream versions rejected", [] { for (auto version : {0xfffffffdU, 0xffffffffU, 0xfffffffcU}) { Bytes b; u32(b,version); u32(b,0); rejects(b); } });
    test("non-boolean compression flags rejected", [] { auto b=wire({{"4", {}, false}}); b[14]=2; rejects(b); });
    test("all truncations rejected", [] { const auto full=wire({{"4", {0,1,2,255}, false}}); for(std::size_t i=0;i<full.size();++i) rejects(Bytes(full.begin(),full.begin()+i)); });
    test("trailing stream data rejected", [] { auto b=wire({}); b.push_back(0); rejects(b); });
    test("strict canonical Base64", [] { for(const auto *s:{"", "A", "AAAA=", "====", "AA==\n", "AB==", "AAB=", "_AAA"}) reject([&]{decode({s});}); });
    test("format and item limits enforced", [] { Limits l; l.formatsPerItem=1; rejects(wire({{"4",{},false},{"5",{},false}}),l); l.items=0; rejects(wire({}),l); CHECK(decode({},l).empty()); });
    test("aggregate snapshot budget includes names", [] { Limits l; l.snapshotBytes=10; rejects(wire({{"4",{1},false}}),l); CHECK(decode({b64(wire({{"4",{},false}}))},l).size()==1); reject([&]{decode({b64(wire({{"4",{},false}})),b64(wire({{"5",{},false}}))},l);}); });
    test("compression expansion budget enforced", [] { Limits l; l.snapshotBytes=100; rejects(wire({{"4",compressed(Bytes(101,1)),true}}),l); });
    test("compressed framing size and trailing bytes rejected", [] { auto z=compressed({1,2}); z[3]=3; rejects(wire({{"4",z,true}})); z=compressed({1,2}); z.push_back(0); rejects(wire({{"4",z,true}})); z.resize(5); rejects(wire({{"4",z,true}})); });
    test("oversized count and declared allocations rejected", [] { Bytes b; u32(b,0xfffffffeU); u32(b,0x7fffffff); rejects(b); auto good=wire({{"4",{},false}}); for(int i=15;i<19;++i)good[i]=0xfe; rejects(good); });
    test("invalid limits and dangerous local snapshots rejected", [] { Limits l; l.snapshotBytes=0; reject([&]{decode({},l);}); l={}; l.formatsPerItem=257; reject([&]{decode({},l);}); reject([]{cqs::packed::validateSnapshot({{{"FILE:text/plain",{}}}},{});}); });
    test("10000 deterministic input mutations stay bounded", [] {
        const auto seed=wire({{"4",{0,1,2,255},false},{"5",{'<','b','>'},false}}); std::uint32_t random=0x41514141;
        for(unsigned i=0;i<10000;++i) { auto b=seed; random=random*1664525U+1013904223U; b[random%b.size()]^=static_cast<std::uint8_t>(random>>24);
            try { cqs::packed::validateSnapshot(decode({b64(b)}),{}); } catch(const cqs::packed::Error&){} }
    });
    std::cout << passed << " packed-item scenarios passed\n";
}
