// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_identity.h"
#include "test_check.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <string>
#include <type_traits>

using namespace cqs::trust;
using cqs::crypto::Bytes;
namespace {
unsigned cases = 0;
void test(const char *name, const std::function<void()> &body) {
    body(); ++cases; std::cout << "PASS " << name << '\n';
}
Bytes unhex(const std::string &s) {
    CHECK(s.size() % 2 == 0); Bytes out;
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        throw std::runtime_error("Invalid test hex");
    };
    for (std::size_t i = 0; i < s.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>((digit(s[i]) << 4) | digit(s[i + 1])));
    return out;
}
template<std::size_t N> std::array<std::uint8_t, N> fixed(const std::string &s) {
    const auto b = unhex(s); CHECK(b.size() == N);
    std::array<std::uint8_t, N> out{}; std::copy(b.begin(), b.end(), out.begin()); return out;
}
Token token(unsigned value) { Token out{}; out.fill(static_cast<std::uint8_t>(value)); return out; }
void refuses(const std::function<void()> &body) {
    bool failed = false; try { body(); } catch (const cqs::crypto::Error &) { failed = true; } CHECK(failed);
}
void refusesTrust(ErrorCode expected, const std::function<void()> &body) {
    bool failed = false;
    try { body(); } catch (const Error &e) { failed = true; CHECK(e.code() == expected); }
    CHECK(failed);
}
Bytes privateFixture(const std::string &seed) {
    // PUBLIC RFC8032 test seeds, never user data. The private wire record is
    // deliberately constructed independently of exportPrivate() for vectors.
    constexpr char domain[] = "CopyQ-Secure-Sync-device-identity-private-lab-v1";
    Bytes out(domain, domain + sizeof(domain));
    const auto id = token(1), x = token(2), s = fixed<32>(seed);
    out.insert(out.end(), id.begin(), id.end()); out.insert(out.end(), s.begin(), s.end());
    out.insert(out.end(), x.begin(), x.end()); return out;
}
Approval vote(const Proposal &p, const Identity &i) {
    return {i.member().id, i.sign(approvalBytes(p, i.member()))};
}
}

int main() {
    static_assert(!std::is_copy_constructible<Identity>::value && !std::is_move_constructible<Identity>::value,
                  "Identity secrets must not acquire implicit copies");
    const SodiumVerifier verifier;
    test("RFC8032 independent public Ed25519 vectors, not Ed25519ph", [&] {
        struct Vector { const char *seed, *key, *message, *signature; };
        const Vector vectors[] = {
            {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
             "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
             "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
            {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
             "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
             "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
            {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
             "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
             "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"}
        };
        for (const auto &v : vectors) {
            auto privateBytes = privateFixture(v.seed); auto i = Identity::restore(privateBytes);
            cqs::crypto::wipe(privateBytes);
            const auto message = unhex(v.message); const auto signature = fixed<64>(v.signature);
            CHECK(i->member().signingKey == fixed<32>(v.key));
            CHECK(i->sign(message) == signature);
            CHECK(verifier.verify(i->member().signingKey, message, signature));
            auto changed = message; changed.push_back(0);
            CHECK(!verifier.verify(i->member().signingKey, changed, signature));
        }
    });
    test("generated identities separate roles, restore exactly and sign deterministically", [&] {
        const auto a = Identity::generate(), b = Identity::generate();
        CHECK(SodiumVerifier::validMember(a->member())); CHECK(SodiumVerifier::validMember(b->member()));
        CHECK(a->member().id != b->member().id); CHECK(a->member().signingKey != b->member().signingKey);
        CHECK(a->member().encryptionKey != b->member().encryptionKey);
        CHECK(a->member().signingKey != a->member().encryptionKey);
        auto privateBytes = a->exportPrivate(); const auto restored = Identity::restore(privateBytes);
        CHECK(restored->member() == a->member()); cqs::crypto::wipe(privateBytes); CHECK(privateBytes.empty());
        const Bytes m{'b','i','n',0,'a','r','y'};
        CHECK(restored->sign(m) == a->sign(m)); CHECK(a->sign(m) == a->sign(m));
        CHECK(verifier.verify(a->member().signingKey, m, a->sign(m)));
        CHECK(!verifier.verify(b->member().signingKey, m, a->sign(m)));
    });
    test("signature every-bit tampering, scalar malleability and malformed R rejected", [&] {
        const auto a = Identity::generate(); const Bytes m{'m'}; const auto signature = a->sign(m);
        for (std::size_t bit = 0; bit < signature.size() * 8; ++bit) {
            auto bad = signature; bad[bit / 8] ^= static_cast<std::uint8_t>(1U << (bit % 8));
            CHECK(!verifier.verify(a->member().signingKey, m, bad));
        }
        const auto order = fixed<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        auto malleable = signature; unsigned carry = 0;
        for (std::size_t n = 0; n < order.size(); ++n) {
            carry += static_cast<unsigned>(malleable[32 + n]) + order[n];
            malleable[32 + n] = static_cast<std::uint8_t>(carry); carry >>= 8;
        }
        CHECK(!verifier.verify(a->member().signingKey, m, malleable));
        auto bad = signature; std::fill_n(bad.begin(), 32, 0); bad[0] = 1;
        CHECK(!verifier.verify(a->member().signingKey, m, bad));
        bad.fill(0); CHECK(!verifier.verify(a->member().signingKey, m, bad));
    });
    test("strict Ed25519 validation rejects noncanonical small and mixed-order points", [] {
        CHECK(SodiumVerifier::validSigningKey(fixed<32>("5866666666666666666666666666666666666666666666666666666666666666")));
        const Token zero{}; CHECK(!SodiumVerifier::validSigningKey(zero));
        auto one = zero; one[0] = 1; CHECK(!SodiumVerifier::validSigningKey(one));
        auto p = token(255); p[0] = 0xed; p[31] = 0x7f; CHECK(!SodiumVerifier::validSigningKey(p));
        // B + (0,-1), calculated from y -> p-y and x -> -x. This has mixed
        // order, not a small order; older libsodium validation accepted it.
        CHECK(!SodiumVerifier::validSigningKey(fixed<32>("9599999999999999999999999999999999999999999999999999999999999999")));
    });
    test("X25519 canonical public encoding and low-order blacklist", [] {
        const char *bad[] = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        };
        for (const auto *encoding : bad) {
            auto key = fixed<32>(encoding); CHECK(!SodiumVerifier::validEncryptionKey(key));
            key[31] |= 0x80; CHECK(!SodiumVerifier::validEncryptionKey(key));
        }
        const auto a = Identity::generate(); auto alias = a->member().encryptionKey; alias[31] |= 0x80;
        CHECK(!SodiumVerifier::validEncryptionKey(alias));
        Member badMember = a->member(); badMember.id.fill(0); CHECK(!SodiumVerifier::validMember(badMember));
        badMember = a->member(); badMember.signingKey = badMember.encryptionKey;
        CHECK(!SodiumVerifier::validMember(badMember));
    });
    test("private import rejects all truncations domains trailers and zero identity", [] {
        const auto a = Identity::generate(); auto record = a->exportPrivate();
        for (std::size_t n = 0; n < record.size(); ++n)
            refuses([&] { Identity::restore(Bytes(record.begin(), record.begin() + static_cast<std::ptrdiff_t>(n))); });
        auto bad = record; bad.push_back(0); refuses([&] { Identity::restore(bad); });
        bad = record; bad[0] ^= 1; refuses([&] { Identity::restore(bad); });
        constexpr auto offset = sizeof("CopyQ-Secure-Sync-device-identity-private-lab-v1");
        bad = record; std::fill_n(bad.begin() + static_cast<std::ptrdiff_t>(offset), 32, 0);
        refuses([&] { Identity::restore(bad); });
        cqs::crypto::wipe(record); cqs::crypto::wipe(bad);
    });
    test("signature message resource bound enforced before cryptographic work", [&] {
        const auto a = Identity::generate(); const Bytes limit(SodiumVerifier::MaxMessage, 0x42);
        const auto signature = a->sign(limit); CHECK(verifier.verify(a->member().signingKey, limit, signature));
        const Bytes large(SodiumVerifier::MaxMessage + 1, 0x42);
        refuses([&] { a->sign(large); }); CHECK(!verifier.verify(a->member().signingKey, large, signature));
    });
    test("real approval signatures bind exact proposal and approver, enforce quorum", [&] {
        const auto a = Identity::generate(), b = Identity::generate(), c = Identity::generate();
        Membership group(token(1), a->member(), token(2), token(3));
        const auto p = group.propose(Operation::Add, b->member(), token(4), token(5), 100, 200);
        Certificate bootstrap{p, {vote(p, *a)}};
        CHECK(group.observe(bootstrap, 100, verifier) == ObserveResult::Applied);
        const auto next = group.propose(Operation::Add, c->member(), token(6), token(7), 100, 200);
        Certificate admission{next, {vote(next, *a)}};
        refusesTrust(ErrorCode::NoQuorum, [&] { group.observe(admission, 100, verifier); });
        admission.approvals.push_back(vote(next, *b));
        auto changed = admission; changed.proposal.nonce[0] ^= 1;
        refusesTrust(ErrorCode::BadSignature, [&] { group.observe(changed, 100, verifier); });
        changed = admission; changed.approvals[1].signature = a->sign(approvalBytes(next, b->member()));
        refusesTrust(ErrorCode::BadSignature, [&] { group.observe(changed, 100, verifier); });
        CHECK(group.observe(admission, 100, verifier) == ObserveResult::Applied);
        CHECK(group.current().members.size() == 3);
    });
    std::cout << cases << " device identity adapter test cases passed\n";
}
