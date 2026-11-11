// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_key_receipt.h"
#include "test_check.h"
#include <sodium.h>
#include <algorithm>
#include <iostream>
#include <iterator>
#include <string_view>

using namespace cqs::trust;
using cqs::crypto::Bytes;

namespace {
// Public RFC 8032 section 7.1 and RFC 7748 section 6.1 test keys.
constexpr std::string_view SenderSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
constexpr std::string_view RecipientSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
constexpr std::string_view SenderScalar = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
constexpr std::string_view RecipientScalar = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
constexpr char IdentityDomain[] = "CopyQ-Secure-Sync-device-identity-private-lab-v1";
constexpr char ReceiptDomain[] = "CopyQ-Secure-Sync-key-storage-receipt-lab-v1";
constexpr char EnvelopeDomain[] = "CopyQ-Secure-Sync-key-envelope-lab-v1";
constexpr std::size_t SignedSize = 378;
constexpr std::size_t WireSize = 442;

unsigned cases = 0;

template<class Action> void test(const char *name, const Action &action)
{
    action();
    ++cases;
    std::cout << "PASS " << name << '\n';
}

template<class Action> void refuses(ReceiptCode expected, const Action &action)
{
    try {
        action();
    } catch (const ReceiptError &error) {
        CHECK(error.code() == expected);
        return;
    }
    CHECK(false);
}

Bytes hexBytes(std::string_view value)
{
    const auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        CHECK(c >= 'a' && c <= 'f');
        return static_cast<unsigned>(c - 'a' + 10);
    };
    CHECK(value.size() % 2 == 0);
    Bytes bytes;
    bytes.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2)
        bytes.push_back(static_cast<std::uint8_t>((digit(value[i]) << 4) | digit(value[i + 1])));
    return bytes;
}

Token token(std::uint8_t value)
{
    Token result{};
    result.fill(value);
    return result;
}

template<class Range> void append(Bytes &out, const Range &part)
{
    out.insert(out.end(), std::begin(part), std::end(part));
}

std::unique_ptr<Identity> fixtureIdentity(std::string_view seed, std::string_view scalar)
{
    Bytes bytes;
    bytes.reserve(sizeof(IdentityDomain) + 96);
    append(bytes, IdentityDomain);
    append(bytes, token(0xb2));
    append(bytes, hexBytes(seed));
    append(bytes, hexBytes(scalar));
    auto identity = Identity::restore(bytes);
    cqs::crypto::wipe(bytes);
    return identity;
}

Bytes prefix(const ReceiptContext &context)
{
    Bytes wire;
    wire.reserve(WireSize);
    append(wire, ReceiptDomain);
    append(wire, std::array<std::uint8_t, 4>{0, 0, 0, 1});
    append(wire, context.group);
    append(wire, context.root);
    append(wire, context.successor);
    append(wire, context.proposal);
    append(wire, context.sender);
    append(wire, context.recipient.id);
    append(wire, context.recipient.signingKey);
    append(wire, context.recipient.encryptionKey);
    for (int shift = 56; shift >= 0; shift -= 8)
        wire.push_back(static_cast<std::uint8_t>(context.generation >> shift));
    append(wire, context.commitment);
    append(wire, context.envelopeDigest);
    wire.push_back(static_cast<std::uint8_t>(context.scope));
    CHECK(wire.size() == SignedSize);
    return wire;
}

void signRaw(Bytes &wire, std::string_view seedHex = RecipientSeed)
{
    const auto seed = hexBytes(seedHex);
    Token publicKey{};
    std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES> secret{};
    CHECK(crypto_sign_seed_keypair(publicKey.data(), secret.data(), seed.data()) == 0);
    CHECK(wire.size() >= SignedSize);
    wire.resize(WireSize);
    CHECK(crypto_sign_detached(wire.data() + SignedSize, nullptr, wire.data(), SignedSize, secret.data()) == 0);
    sodium_memzero(secret.data(), secret.size());
}
} // namespace

int main()
{
    CHECK(sodium_init() >= 0);
    const auto recipient = fixtureIdentity(RecipientSeed, RecipientScalar);
    const auto other = Identity::generate();
    ReceiptContext context{token(0x11), token(0x22), token(0x33), token(0x44), token(0xa1), recipient->member(),
                           0x0102030405060708ULL, {}, token(0x66), KeyScope::CurrentGeneration};
    const auto commitment = hexBytes("d7353fe7cf0d2888dba12cc532ed5e8875130c1d01f5d2338b3223a96ab4dff4");
    std::copy(commitment.begin(), commitment.end(), context.commitment.begin());
    const auto wire = KeyReceiptCodec::sign(context, *recipient);

    test("independent canonical vector and raw Ed25519 interoperability", [&] {
        // Python struct/hashlib fixed the preimage. OpenSSL 3 pkeyutl -sign
        // -rawin independently signed it with the public RFC test seed.
        const auto expectedSignature = hexBytes(
            "397306ce5c476055a5eb5a7d1d3987854311023cc63708a1a4c309c806e6f017e"
            "b92533c329449b5cb4ab7a724d89cd9d0d516b4cb58ac3cb7480de74b44030f");
        CHECK(wire.size() == WireSize);
        CHECK(cqs::crypto::sha256(Bytes(wire.begin(), wire.begin() + SignedSize)) ==
              hexBytes("71fea851158de6c062ac1db2be9a1d51e714e9adf0577622666088014699953b"));
        CHECK(Bytes(wire.begin() + SignedSize, wire.end()) == expectedSignature);
        CHECK(crypto_sign_verify_detached(wire.data() + SignedSize, wire.data(), SignedSize,
                                          recipient->member().signingKey.data()) == 0);
        auto fromSodium = prefix(context);
        signRaw(fromSodium);
        CHECK(fromSodium == wire);
        KeyReceiptCodec::verify(fromSodium, context);
        CHECK(prefix(KeyReceiptCodec::inspect(wire)) == prefix(context));
    });

    test("every truncation, trailer and malformed signed format rejected", [&] {
        const auto refuseMalformed = [&](const Bytes &malformed) {
            refuses(ReceiptCode::Invalid, [&] { KeyReceiptCodec::inspect(malformed); });
            refuses(ReceiptCode::Invalid, [&] { KeyReceiptCodec::verify(malformed, context); });
        };
        for (std::size_t size = 0; size < wire.size(); ++size)
            refuseMalformed(Bytes(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(size)));
        auto changed = wire;
        changed.push_back(0);
        refuseMalformed(changed);
        for (const auto offset : {std::size_t{0}, sizeof(ReceiptDomain) - 1, sizeof(ReceiptDomain) + 3, SignedSize - 1}) {
            changed = wire;
            changed[offset] ^= 2;
            signRaw(changed);
            refuseMalformed(changed);
        }
    });

    test("verification binds every independently pinned field", [&] {
        for (auto field : {&ReceiptContext::group, &ReceiptContext::root, &ReceiptContext::successor,
                           &ReceiptContext::proposal, &ReceiptContext::sender, &ReceiptContext::commitment,
                           &ReceiptContext::envelopeDigest}) {
            auto changed = context;
            (changed.*field)[0] ^= 1;
            refuses(ReceiptCode::ContextMismatch, [&] { KeyReceiptCodec::verify(wire, changed); });
        }
        for (auto field : {&Member::id, &Member::signingKey, &Member::encryptionKey}) {
            auto changed = context;
            changed.recipient.*field = other->member().*field;
            refuses(ReceiptCode::ContextMismatch, [&] { KeyReceiptCodec::verify(wire, changed); });
        }
        auto changed = context;
        ++changed.generation;
        refuses(ReceiptCode::ContextMismatch, [&] { KeyReceiptCodec::verify(wire, changed); });
        changed = context;
        changed.scope = KeyScope::CatchUp;
        refuses(ReceiptCode::ContextMismatch, [&] { KeyReceiptCodec::verify(wire, changed); });
    });

    test("another exact envelope digest cannot replay a receipt for the same operation", [&] {
        auto resealed = context;
        resealed.envelopeDigest = token(0x77);
        const auto otherReceipt = KeyReceiptCodec::sign(resealed, *recipient);
        KeyReceiptCodec::verify(otherReceipt, resealed);
        refuses(ReceiptCode::ContextMismatch, [&] { KeyReceiptCodec::verify(wire, resealed); });
        refuses(ReceiptCode::ContextMismatch, [&] { KeyReceiptCodec::verify(otherReceipt, context); });

        // Matching the expected digest by editing the wire still needs a new signature.
        auto forged = wire;
        std::copy(resealed.envelopeDigest.begin(), resealed.envelopeDigest.end(), forged.begin() + SignedSize - 33);
        CHECK(KeyReceiptCodec::inspect(forged).envelopeDigest == resealed.envelopeDigest);
        refuses(ReceiptCode::BadSignature, [&] { KeyReceiptCodec::verify(forged, resealed); });
    });

    test("the recipient identity and signing purpose are required", [&] {
        const auto wrongSigningKey = fixtureIdentity(SenderSeed, RecipientScalar);
        const auto wrongEncryptionKey = fixtureIdentity(RecipientSeed, SenderScalar);
        for (const auto *wrong : {other.get(), wrongSigningKey.get(), wrongEncryptionKey.get()})
            refuses(ReceiptCode::ContextMismatch, [&] { KeyReceiptCodec::sign(context, *wrong); });

        auto forged = wire;
        signRaw(forged, SenderSeed);
        refuses(ReceiptCode::BadSignature, [&] { KeyReceiptCodec::verify(forged, context); });

        Bytes anotherPurpose;
        anotherPurpose.reserve(SignedSize);
        append(anotherPurpose, EnvelopeDomain);
        anotherPurpose.insert(anotherPurpose.end(), wire.begin() + sizeof(ReceiptDomain), wire.begin() + SignedSize);
        const auto crossSignature = recipient->sign(anotherPurpose);
        std::copy(crossSignature.begin(), crossSignature.end(), forged.begin() + SignedSize);
        refuses(ReceiptCode::BadSignature, [&] { KeyReceiptCodec::verify(forged, context); });

        forged = wire;
        forged.back() ^= 1;
        CHECK(prefix(KeyReceiptCodec::inspect(forged)) == prefix(context));
        refuses(ReceiptCode::BadSignature, [&] { KeyReceiptCodec::verify(forged, context); });
    });

    test("zero pins, sender alias, malformed member keys and unsupported scope rejected", [&] {
        const auto refuseInvalidContext = [&](const ReceiptContext &invalid) {
            refuses(ReceiptCode::Invalid, [&] { KeyReceiptCodec::sign(invalid, *recipient); });
            auto invalidWire = prefix(invalid);
            signRaw(invalidWire);
            refuses(ReceiptCode::Invalid, [&] { KeyReceiptCodec::inspect(invalidWire); });
            refuses(ReceiptCode::Invalid, [&] { KeyReceiptCodec::verify(invalidWire, invalid); });
        };
        for (auto field : {&ReceiptContext::group, &ReceiptContext::root, &ReceiptContext::successor,
                           &ReceiptContext::proposal, &ReceiptContext::sender, &ReceiptContext::commitment,
                           &ReceiptContext::envelopeDigest}) {
            auto invalid = context;
            (invalid.*field).fill(0);
            refuseInvalidContext(invalid);
        }
        for (auto field : {&Member::id, &Member::signingKey, &Member::encryptionKey}) {
            auto invalid = context;
            (invalid.recipient.*field).fill(0);
            refuseInvalidContext(invalid);
        }
        auto invalid = context;
        invalid.sender = invalid.recipient.id;
        refuseInvalidContext(invalid);
        invalid = context;
        invalid.recipient.encryptionKey.back() |= 0x80;
        refuseInvalidContext(invalid);
        invalid = context;
        invalid.scope = static_cast<KeyScope>(0);
        refuseInvalidContext(invalid);
    });

    test("generation zero and catch-up scope round trip with distinct signatures", [&] {
        auto initial = context;
        initial.generation = 0;
        const auto initialWire = KeyReceiptCodec::sign(initial, *recipient);
        KeyReceiptCodec::verify(initialWire, initial);
        CHECK(KeyReceiptCodec::inspect(initialWire).generation == 0);
        auto catchUp = initial;
        catchUp.scope = KeyScope::CatchUp;
        const auto catchUpWire = KeyReceiptCodec::sign(catchUp, *recipient);
        KeyReceiptCodec::verify(catchUpWire, catchUp);
        CHECK(KeyReceiptCodec::inspect(catchUpWire).scope == KeyScope::CatchUp);
        CHECK(!std::equal(initialWire.begin() + SignedSize, initialWire.end(), catchUpWire.begin() + SignedSize));
        refuses(ReceiptCode::ContextMismatch, [&] { KeyReceiptCodec::verify(catchUpWire, initial); });
    });

    std::cout << cases << " device key storage receipt test cases passed\n";
}
