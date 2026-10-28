// SPDX-License-Identifier: GPL-3.0-or-later
// Portable codec tests: no Qt, filesystem adapter or real user profile.
#include "state_record.h"
#include "test_check.h"
#include "fixtures/state_record_vectors.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <numeric>
#include <set>
#include <string_view>

using cqs::crypto::Bytes;
using cqs::state::Error;
using cqs::state::ErrorCode;
using cqs::transaction::Head;
using cqs::transaction::Pending;
using cqs::transaction::Phase;
using cqs::transaction::Record;
using cqs::transaction::Snapshot;
namespace {
const std::string binding = "public-state-vector-v1";
int cases = 0;
Bytes key() { Bytes k(32); std::iota(k.begin(), k.end(), 0); return k; }
Bytes bytes(std::string_view s) { return {s.begin(), s.end()}; }
Bytes hex(std::string_view text) {
    CHECK(text.size() % 2 == 0);
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        CHECK(c >= 'a' && c <= 'f'); return static_cast<unsigned>(c - 'a' + 10);
    };
    Bytes result;
    for (std::size_t i = 0; i < text.size(); i += 2)
        result.push_back(static_cast<std::uint8_t>((digit(text[i]) << 4) | digit(text[i+1])));
    return result;
}
void test(const std::string &name, const std::function<void()> &body) {
    body(); ++cases; std::cout << "PASS " << name << '\n';
}
void rejects(ErrorCode code, const std::function<void()> &body) {
    bool rejected = false;
    try { body(); }
    catch (const Error &e) { CHECK(e.code() == code); rejected = true; }
    CHECK(rejected);
}
void equalHead(const Head &a, const Head &b) {
    CHECK(a.event.revision.id == b.event.revision.id);
    CHECK(a.event.revision.device == b.event.revision.device);
    CHECK(a.event.revision.sequence == b.event.revision.sequence);
    CHECK(a.event.revision.parents == b.event.revision.parents);
    CHECK(a.event.items == b.event.items);
    CHECK(a.event.plaintextBytes == b.event.plaintextBytes);
    CHECK(a.snapshot == b.snapshot);
}
void equalRecord(const Record &a, const Record &b) {
    // Field-by-field assertions are independent of serialize()/parse().
    CHECK(a.witnessed==b.witnessed);CHECK(a.schema == b.schema); CHECK(a.binding == b.binding);
    CHECK(a.generation == b.generation);
    CHECK(a.local == b.local);CHECK(a.keyIdentity == b.keyIdentity);
    CHECK(a.archives==b.archives);CHECK(a.resolution.has_value()==b.resolution.has_value());
    if(a.resolution)CHECK(a.resolution->tips==b.resolution->tips);
    CHECK(a.allocatedSequence==b.allocatedSequence);CHECK(a.preserved==b.preserved);
    CHECK(a.publication.has_value()==b.publication.has_value());
    if(a.publication){equalHead(a.publication->target,b.publication->target);CHECK(a.publication->wire==b.publication->wire);}
    CHECK(a.head.has_value() == b.head.has_value());
    CHECK(a.pending.has_value() == b.pending.has_value());
    if (a.head) equalHead(*a.head, *b.head);
    if (a.pending) {
        equalHead(a.pending->target, b.pending->target);
        CHECK(a.pending->phase == b.pending->phase);
        CHECK(a.pending->original == b.pending->original);
    }
}
Snapshot snapshot() {
    // Explicit UTF-8 bytes avoid reliance on the Windows compiler code page.
    return {
        {{"application/octet-stream", {0, 127, 128, 255, 13, 10}},
         {"text/plain", hex("5a61c5bcc3b3c582c4872067c499c59b6cc485206a61c5bac5840d0af09f998200")}},
        {{"application/x-empty", {}}},
    };
}
Head original() {
    return {{{"mint-lab/000000000001", "mint-lab", 1, {}}, {"AAE=", ""}, 128}, snapshot()};
}
Head deletion() {
    return {{{"mint-lab/000000000002", "mint-lab", 2, {"mint-lab/000000000001"}}, {}, 40}, {}};
}
Record empty() { return {1, binding, 0, {}, {}}; }
Record join() { return {1, binding, 1, {}, Pending{original(), {}, Phase::Import}}; }
Record restore() {
    return {1, binding, (std::uint64_t{1} << 63) + 5, original(),
            Pending{deletion(), snapshot(), Phase::Restore}};
}
Record checkpoint() {
    return {1, binding, std::numeric_limits<std::uint64_t>::max(), original(), {}};
}
struct Vector { const char *name; const char *plain; const char *wire; Record expected; };
Bytes referenceAad() {
    auto result = bytes("CopyQ-Secure-Sync-private-state-v1");
    result.push_back(0);
    const auto suffix = bytes("CQSREC01" + binding);
    result.insert(result.end(), suffix.begin(), suffix.end()); return result;
}
} // namespace
int main(int argc, char **argv) {
    // Optional external verification: emits only this fixed PUBLIC synthetic
    // checkpoint. Never reads arguments as a key, profile or record path.
    if (argc == 2 && std::string_view(argv[1]) == "--emit-public-checkpoint") {
        const auto wire = cqs::state::seal(key(), binding, checkpoint());
        constexpr char digits[] = "0123456789abcdef";
        for (auto c : wire) std::cout << digits[c >> 4] << digits[c & 15];
        std::cout << '\n'; return 0;
    }
    CHECK(argc == 1);
    using namespace state_vectors;
    const std::vector<Vector> vectors{
        {"empty", empty_plain, empty_wire, empty()},
        {"pending join", pending_join_plain, pending_join_wire, join()},
        {"pending restore", pending_restore_plain, pending_restore_wire, restore()},
        {"checkpoint", checkpoint_plain, checkpoint_wire, checkpoint()},
        {"unified pending", unified_pending_plain, unified_pending_wire, []{
            auto r=restore();r.schema=2;r.generation=7;r.pending->phase=Phase::Import;r.local=Snapshot{};
            r.keyIdentity="4312dec9a216ecf94478adf20482f373fb34d2df376860efb545b2402cbad1f4";return r;
        }()},
        {"Seed pending", seed_pending_plain, seed_pending_wire, []{
            auto r=empty();r.schema=3;r.generation=8;r.local=snapshot();r.preserved=snapshot();r.allocatedSequence=1;
            r.keyIdentity="4312dec9a216ecf94478adf20482f373fb34d2df376860efb545b2402cbad1f4";
            r.publication=cqs::transaction::Publication{original(),"public-codec-only-ciphertext"};return r;
        }()},
        {"publication pending", publication_pending_plain, publication_pending_wire, []{
            auto r=empty();r.schema=4;r.generation=9;r.head=original();r.local=Snapshot{};r.preserved=snapshot();r.allocatedSequence=2;
            r.keyIdentity="4312dec9a216ecf94478adf20482f373fb34d2df376860efb545b2402cbad1f4";
            r.publication=cqs::transaction::Publication{deletion(),"public-update-codec-only-ciphertext"};return r;
        }()},
        {"resolution pending", resolution_pending_plain, resolution_pending_wire, []{
            auto r=empty();r.schema=5;r.generation=10;r.head=original();r.local=snapshot();r.allocatedSequence=2;
            r.keyIdentity="4312dec9a216ecf94478adf20482f373fb34d2df376860efb545b2402cbad1f4";
            auto target=deletion();target.event.revision.parents={"mint-lab/000000000001","remote-pc/000000000001"};
            r.publication=cqs::transaction::Publication{target,"public-resolution-codec-only-ciphertext"};r.archives={snapshot()};
            r.resolution=cqs::transaction::Resolution{{"mint-lab/000000000001","remote-pc/000000000001"}};return r;
        }()},
        {"witnessed pending", witnessed_pending_plain, witnessed_pending_wire, []{
            auto r=empty();r.schema=6;r.generation=10;r.head=original();r.local=snapshot();r.allocatedSequence=2;
            r.keyIdentity="4312dec9a216ecf94478adf20482f373fb34d2df376860efb545b2402cbad1f4";
            auto target=deletion();target.event.revision.parents={"mint-lab/000000000001","remote-pc/000000000001"};
            r.publication=cqs::transaction::Publication{target,"public-resolution-codec-only-ciphertext"};r.archives={snapshot()};
            r.resolution=cqs::transaction::Resolution{{"mint-lab/000000000001","remote-pc/000000000001"}};
            r.witnessed={{"mint-lab/000000000001",Bytes(32,0x42)},{"remote-pc/000000000001",Bytes(32,0x43)}};return r;
        }()},
    };
    for (const auto &v : vectors) {
        const auto plain = hex(v.plain), wire = hex(v.wire);
        test(std::string(v.name) + ": independent binary decode", [&] {
            equalRecord(cqs::state::parse(plain), v.expected);
        });
        test(std::string(v.name) + ": canonical bytes match independent encoder", [&] {
            CHECK(cqs::state::serialize(v.expected) == plain);
        });
        test(std::string(v.name) + ": independent AES-GCM fixture", [&] {
            equalRecord(cqs::state::unseal(key(), binding, wire), v.expected);
        });
        test(std::string(v.name) + ": fresh encryption and exact byte budget", [&] {
            cqs::state::Limits l; l.recordBytes = plain.size();
            auto sealed = cqs::state::seal(key(), binding, v.expected, l);
            CHECK(sealed.size() == plain.size() + cqs::state::EnvelopeOverhead);
            equalRecord(cqs::state::unseal(key(), binding, sealed, l), v.expected);
            --l.recordBytes;
            rejects(ErrorCode::SizeLimit, [&] { cqs::state::unseal(key(), binding, sealed, l); });
            rejects(ErrorCode::SizeLimit, [&] { cqs::state::seal(key(), binding, v.expected, l); });
        });
        test(std::string(v.name) + ": every changed wire byte fails closed", [&] {
            for (std::size_t i = 0; i < wire.size(); ++i) {
                auto damaged = wire; damaged[i] ^= 1;
                rejects(i < 8 ? ErrorCode::InvalidRecord : ErrorCode::AuthenticationFailed,
                        [&] { cqs::state::unseal(key(), binding, damaged); });
            }
        });
        test(std::string(v.name) + ": every truncation fails closed", [&] {
            for (std::size_t n = 0; n < wire.size(); ++n) {
                const Bytes truncated(wire.begin(), wire.begin() + n);
                rejects(n < 36 ? ErrorCode::InvalidRecord : ErrorCode::AuthenticationFailed,
                        [&] { cqs::state::unseal(key(), binding, truncated); });
            }
        });
    }
    test("Seed fields require schema 3, unique pending kind and matching bounded sequence",[&]{
        auto r=vectors[5].expected;
        r.schema=2;rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[5].expected;r.allocatedSequence=2;rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[5].expected;r.pending=Pending{deletion(),snapshot(),Phase::Import};rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[5].expected;r.head=original();rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[5].expected;r.publication->wire.clear();rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[5].expected;r.allocatedSequence=cqs::history::MaxSequence+1;rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
    });
    test("schema 4 publication retains exactly one matching prior head",[&]{
        auto r=vectors[6].expected;r.schema=3;rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[6].expected;r.publication->target.event.revision.parents={"other-pc/000000000001"};
        rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[6].expected;r.head.reset();rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[6].expected;r.schema=7;rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
    });
    test("schema 6 witness codec is bounded, canonical and preserves old schemas",[&]{
        auto r=vectors[4].expected;r.schema=6;
        r.witnessed.emplace("mint-lab/000000000001",Bytes(32,0x42));
        equalRecord(cqs::state::parse(cqs::state::serialize(r)),r);
        equalRecord(cqs::state::unseal(key(),binding,cqs::state::seal(key(),binding,r)),r);
        auto bad=r;bad.schema=5;rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(bad);});
        bad=r;bad.witnessed.begin()->second.pop_back();rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(bad);});
        bad=r;bad.witnessed.emplace("../bad",Bytes(32));rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(bad);});
        auto bytes=cqs::state::serialize(r);bytes.pop_back();rejects(ErrorCode::InvalidRecord,[&]{cqs::state::parse(bytes);});
        bad=r;for(unsigned i=1;i<=1001;++i)bad.witnessed.emplace(cqs::history::makeId("peer-pc",i),Bytes(32));
        rejects(ErrorCode::SizeLimit,[&]{cqs::state::serialize(bad);});
    });
    const auto wire = hex(pending_restore_wire);
    test("resolution rejects incomplete parent joins and inconsistent projection",[&]{
        auto r=vectors[7].expected;r.publication->target.event.revision.parents.resize(1);
        rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r=vectors[7].expected;r.publication.reset();r.pending=cqs::transaction::Pending{*r.head,r.archives.back(),cqs::transaction::Phase::Import};
        rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
        r.resolution->tips={r.head->event.revision.id};cqs::state::serialize(r);
        r.pending->target.snapshot={};rejects(ErrorCode::InvalidRecord,[&]{cqs::state::serialize(r);});
    });
    test("different key and profile binding rejected", [&] {
        auto changed = key(); changed[0] ^= 1;
        rejects(ErrorCode::AuthenticationFailed, [&] { cqs::state::unseal(changed, binding, wire); });
        rejects(ErrorCode::AuthenticationFailed, [&] { cqs::state::unseal(key(), "other-profile", wire); });
        rejects(ErrorCode::InvalidKey, [&] { cqs::state::unseal({}, binding, wire); });
    });
    test("event-domain AAD cannot authenticate a private record", [&] {
        const Bytes nonce(wire.begin()+8, wire.begin()+20);
        auto aad = bytes("CopyQ-Secure-Sync-event-v1"); aad.push_back(0);
        auto cipher = cqs::crypto::aes256GcmEncrypt(key(), nonce, hex(pending_restore_plain), aad);
        Bytes wrongDomain(wire.begin(), wire.begin()+20);
        wrongDomain.insert(wrongDomain.end(), cipher.begin(), cipher.end());
        rejects(ErrorCode::AuthenticationFailed, [&] { cqs::state::unseal(key(), binding, wrongDomain); });
    });
    test("correct AEAD does not excuse inner binding mismatch", [&] {
        auto record = checkpoint(); record.binding = "other-profile";
        const auto plain = cqs::state::serialize(record);
        const Bytes nonce(wire.begin()+8, wire.begin()+20);
        auto cipher = cqs::crypto::aes256GcmEncrypt(key(), nonce, plain, referenceAad());
        Bytes forged(wire.begin(), wire.begin()+20); forged.insert(forged.end(), cipher.begin(), cipher.end());
        rejects(ErrorCode::WrongBinding, [&] { cqs::state::unseal(key(), binding, forged); });
    });
    test("schema and all length bytes use fixed big-endian layout", [&] {
        const auto plain = hex(empty_plain);
        CHECK(plain.size() == 26 + binding.size());
        CHECK(Bytes(plain.begin(), plain.begin()+8) == hex("0000000000000001"));
        CHECK(Bytes(plain.begin()+8, plain.begin()+16) == hex("0000000000000016"));
        const auto high = cqs::state::parse(hex(pending_restore_plain));
        CHECK(high.generation == (std::uint64_t{1} << 63) + 5);
        CHECK(cqs::state::parse(hex(checkpoint_plain)).generation == std::numeric_limits<std::uint64_t>::max());
    });
    test("repeated same-generation seal uses independent nonces", [&] {
        std::set<Bytes> nonces;
        for (int i = 0; i < 128; ++i) {
            const auto sealed = cqs::state::seal(key(), binding, empty());
            CHECK(nonces.emplace(sealed.begin()+8, sealed.begin()+20).second);
            equalRecord(cqs::state::unseal(key(), binding, sealed), empty());
        }
        // A smoke check, NOT a proof of RNG quality or impossibility of collision.
    });
    std::cout << cases << " portable state codec scenarios passed\n";
}
