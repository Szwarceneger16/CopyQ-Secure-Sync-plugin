// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_key_envelope.h"
#include "test_check.h"
#include <sodium.h>
#include <algorithm>
#include <iostream>
#include <iterator>
#include <string_view>
#include <type_traits>
#include <utility>

using namespace cqs::trust;
using cqs::crypto::Bytes;

namespace {
// Public RFC 8032 section 7.1 and RFC 7748 section 6.1 fixtures. These keys
// and the fixed data key are deliberately public and must never protect data.
constexpr std::string_view SenderSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
constexpr std::string_view RecipientSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
constexpr std::string_view SenderScalar = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
constexpr std::string_view RecipientScalar = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
constexpr char IdentityDomain[] = "CopyQ-Secure-Sync-device-identity-private-lab-v1";
constexpr char EnvelopeDomain[] = "CopyQ-Secure-Sync-key-envelope-lab-v1";
constexpr char PlaintextDomain[] = "CopyQ-Secure-Sync-key-envelope-plaintext-lab-v1";
constexpr std::size_t HeaderSize = sizeof(EnvelopeDomain) + 301;
constexpr std::size_t PlaintextSize = sizeof(PlaintextDomain) + 301 + 32;
constexpr std::size_t SealedSize = PlaintextSize + crypto_box_SEALBYTES;
constexpr std::size_t SignedSize = HeaderSize + SealedSize;
constexpr std::size_t WireSize = SignedSize + 64;

unsigned cases = 0;

template<class Action> void test(const char *name, const Action &action)
{
    action();
    ++cases;
    std::cout << "PASS " << name << '\n';
}

template<class Action> void refuses(EnvelopeCode expected, const Action &action)
{
    try {
        action();
    } catch (const EnvelopeError &error) {
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

std::unique_ptr<Identity> fixtureIdentity(std::uint8_t id, std::string_view seed, std::string_view scalar)
{
    Bytes bytes;
    bytes.reserve(sizeof(IdentityDomain) + 96);
    append(bytes, IdentityDomain);
    append(bytes, token(id));
    append(bytes, hexBytes(seed));
    append(bytes, hexBytes(scalar));
    auto identity = Identity::restore(bytes);
    cqs::crypto::wipe(bytes);
    return identity;
}

void appendContext(Bytes &out, const KeyEnvelopeContext &context)
{
    append(out, std::array<std::uint8_t, 4>{0, 0, 0, 1});
    append(out, context.group);
    append(out, context.root);
    append(out, context.successor);
    append(out, context.proposal);
    append(out, context.recipient.id);
    append(out, context.recipient.signingKey);
    append(out, context.recipient.encryptionKey);
    append(out, context.sender);
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>(context.generation >> shift));
    append(out, context.commitment);
    out.push_back(static_cast<std::uint8_t>(context.scope));
}

Bytes header(const KeyEnvelopeContext &context)
{
    Bytes out;
    out.reserve(WireSize);
    append(out, EnvelopeDomain);
    appendContext(out, context);
    CHECK(out.size() == HeaderSize);
    return out;
}

Bytes plaintext(const KeyEnvelopeContext &context, const Bytes &key)
{
    Bytes out;
    out.reserve(PlaintextSize);
    append(out, PlaintextDomain);
    appendContext(out, context);
    append(out, key);
    CHECK(out.size() == PlaintextSize);
    return out;
}

void signAsSender(Bytes &wire)
{
    // Independent test-only signer for deliberately contradictory envelopes.
    const auto seed = hexBytes(SenderSeed);
    Token publicKey{};
    std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES> secret{};
    CHECK(crypto_sign_seed_keypair(publicKey.data(), secret.data(), seed.data()) == 0);
    CHECK(wire.size() >= SignedSize);
    wire.resize(WireSize);
    CHECK(crypto_sign_detached(wire.data() + SignedSize, nullptr, wire.data(), SignedSize, secret.data()) == 0);
    sodium_memzero(secret.data(), secret.size());
}

Bytes signedEnvelope(const KeyEnvelopeContext &outer, Bytes inner, const Token &encryptionKey)
{
    auto wire = header(outer);
    wire.resize(SignedSize);
    CHECK(crypto_box_seal(wire.data() + HeaderSize, inner.data(), inner.size(), encryptionKey.data()) == 0);
    cqs::crypto::wipe(inner);
    signAsSender(wire);
    return wire;
}
} // namespace

int main()
{
    static_assert(!std::is_copy_constructible_v<SyncKey> && !std::is_move_constructible_v<SyncKey>);
    CHECK(sodium_init() >= 0);
    const auto sender = fixtureIdentity(0xa1, SenderSeed, SenderScalar);
    const auto recipient = fixtureIdentity(0xb2, RecipientSeed, RecipientScalar);
    const auto other = Identity::generate();
    const auto publicKeyFixture = hexBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const auto key = SyncKey::import(publicKeyFixture);
    const auto group = token(0x11);
    constexpr std::uint64_t generation = 0x0102030405060708ULL;
    const auto commitment = key->commitment(group, generation);
    const KeyEnvelopeContext context{group, token(0x22), token(0x33), token(0x44), recipient->member(),
                                     sender->member().id, generation, commitment, KeyScope::CurrentGeneration};
    const auto wire = KeyEnvelopeCodec::seal(context, *sender, *key);
    const auto open = [&](const Bytes &candidate) {
        return KeyEnvelopeCodec::open(candidate, context, sender->member(), *recipient);
    };

    test("independent commitment, header and sealed plaintext vectors", [&] {
        // Python struct.pack('>I', 1), struct.pack('>Q', generation) and hashlib
        // generated these fixed hashes from the public RFC fixture keys.
        CHECK(Bytes(commitment.begin(), commitment.end()) ==
              hexBytes("d7353fe7cf0d2888dba12cc532ed5e8875130c1d01f5d2338b3223a96ab4dff4"));
        CHECK(wire.size() == WireSize && WireSize == 832);
        CHECK(cqs::crypto::sha256(Bytes(wire.begin(), wire.begin() + HeaderSize)) ==
              hexBytes("62b35027ca87419b2c33409ce89f76faa2d9c4d7398a35cc3e6dfcb0e226e84b"));
        CHECK(crypto_sign_verify_detached(wire.data() + SignedSize, wire.data(), SignedSize,
                                          sender->member().signingKey.data()) == 0);
        Bytes decrypted(PlaintextSize);
        const auto scalar = hexBytes(RecipientScalar);
        CHECK(crypto_box_seal_open(decrypted.data(), wire.data() + HeaderSize, SealedSize,
                                   recipient->member().encryptionKey.data(), scalar.data()) == 0);
        CHECK(cqs::crypto::sha256(decrypted) ==
              hexBytes("0170e318fe4eb09304cf8f8d0b1ebb9eab6869d40212b2b24a9a59ae05dd3f8f"));
        cqs::crypto::wipe(decrypted);
        CHECK(header(KeyEnvelopeCodec::inspect(wire)) == header(context));
        KeyEnvelopeCodec::verify(wire, context, sender->member());
        CHECK(open(wire)->sameKey(*key));
        CHECK(open(signedEnvelope(context, plaintext(context, publicKeyFixture), context.recipient.encryptionKey))
              ->sameKey(*key));
    });

    test("key commitment binds group and generation, generation zero is supported", [&] {
        CHECK(key->commitment(group, generation + 1) != commitment);
        CHECK(key->commitment(token(0x12), generation) != commitment);
        auto initial = context;
        initial.generation = 0;
        initial.commitment = key->commitment(group, 0);
        const auto initialWire = KeyEnvelopeCodec::seal(initial, *sender, *key);
        CHECK(KeyEnvelopeCodec::open(initialWire, initial, sender->member(), *recipient)->sameKey(*key));
        auto exported = key->exportPrivate();
        CHECK(exported == publicKeyFixture);
        cqs::crypto::wipe(exported);
        CHECK(!SyncKey::generate()->sameKey(*key));
    });

    test("malformed key imports and mismatched seal inputs fail closed", [&] {
        refuses(EnvelopeCode::Invalid, [] { SyncKey::import(Bytes(31, 1)); });
        refuses(EnvelopeCode::Invalid, [] { SyncKey::import(Bytes(33, 1)); });
        refuses(EnvelopeCode::KeyMismatch, [] { SyncKey::import(Bytes(32, 0)); });
        refuses(EnvelopeCode::ContextMismatch, [&] { KeyEnvelopeCodec::seal(context, *other, *key); });
        auto changed = context;
        changed.commitment[0] ^= 1;
        refuses(EnvelopeCode::KeyMismatch, [&] { KeyEnvelopeCodec::seal(changed, *sender, *key); });
    });

    test("every truncation, trailing bytes and malformed signed headers rejected", [&] {
        for (std::size_t size = 0; size < wire.size(); ++size) {
            const Bytes truncated(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(size));
            refuses(EnvelopeCode::Invalid, [&] { KeyEnvelopeCodec::inspect(truncated); });
            refuses(EnvelopeCode::Invalid, [&] { open(truncated); });
        }
        auto changed = wire;
        changed.push_back(0);
        refuses(EnvelopeCode::Invalid, [&] { KeyEnvelopeCodec::inspect(changed); });
        refuses(EnvelopeCode::Invalid, [&] { open(changed); });
        for (const auto offset : {std::size_t{0}, sizeof(EnvelopeDomain) + 3, HeaderSize - 1}) {
            changed = wire;
            changed[offset] ^= 2;
            signAsSender(changed);
            refuses(EnvelopeCode::Invalid, [&] { KeyEnvelopeCodec::inspect(changed); });
            refuses(EnvelopeCode::Invalid, [&] { open(changed); });
        }
    });

    test("every public field and both identities bind to independently pinned values", [&] {
        const auto refuseContext = [&](const KeyEnvelopeContext &changed) {
            refuses(EnvelopeCode::ContextMismatch, [&] { KeyEnvelopeCodec::verify(wire, changed, sender->member()); });
            refuses(EnvelopeCode::ContextMismatch, [&] {
                KeyEnvelopeCodec::open(wire, changed, sender->member(), *recipient);
            });
        };
        for (auto field : {&KeyEnvelopeContext::group, &KeyEnvelopeContext::root, &KeyEnvelopeContext::successor,
                           &KeyEnvelopeContext::proposal, &KeyEnvelopeContext::sender, &KeyEnvelopeContext::commitment}) {
            auto changed = context;
            (changed.*field)[0] ^= 1;
            refuseContext(changed);
        }
        for (auto field : {&Member::id, &Member::signingKey, &Member::encryptionKey}) {
            auto changed = context;
            changed.recipient.*field = other->member().*field;
            refuseContext(changed);
        }
        auto changed = context;
        ++changed.generation;
        refuseContext(changed);
        refuses(EnvelopeCode::ContextMismatch, [&] {
            KeyEnvelopeCodec::open(wire, context, sender->member(), *other);
        });
        auto wrongSender = sender->member();
        wrongSender.id = other->member().id;
        refuses(EnvelopeCode::ContextMismatch, [&] { KeyEnvelopeCodec::verify(wire, context, wrongSender); });
        wrongSender.id = sender->member().id;
        wrongSender.signingKey = other->member().signingKey;
        refuses(EnvelopeCode::BadSignature, [&] { KeyEnvelopeCodec::verify(wire, context, wrongSender); });
        wrongSender.encryptionKey.fill(0);
        refuses(EnvelopeCode::Invalid, [&] { KeyEnvelopeCodec::verify(wire, context, wrongSender); });

        auto invalidRecipient = context;
        invalidRecipient.recipient.encryptionKey.back() |= 0x80;
        const auto signedAlias = signedEnvelope(invalidRecipient, plaintext(invalidRecipient, publicKeyFixture),
                                                context.recipient.encryptionKey);
        refuses(EnvelopeCode::Invalid, [&] { KeyEnvelopeCodec::inspect(signedAlias); });
        refuses(EnvelopeCode::Invalid, [&] { open(signedAlias); });
    });

    test("unsigned tampering is rejected before handling sealed ciphertext", [&] {
        auto changed = wire;
        changed[HeaderSize + crypto_box_PUBLICKEYBYTES] ^= 1;
        refuses(EnvelopeCode::BadSignature, [&] { open(changed); });
        changed = wire;
        changed.back() ^= 1;
        refuses(EnvelopeCode::BadSignature, [&] { open(changed); });
        changed = wire;
        std::fill_n(changed.begin() + HeaderSize, crypto_box_PUBLICKEYBYTES, 0);
        refuses(EnvelopeCode::BadSignature, [&] { open(changed); });
        signAsSender(changed);
        refuses(EnvelopeCode::Invalid, [&] { KeyEnvelopeCodec::verify(changed, context, sender->member()); });
        refuses(EnvelopeCode::Invalid, [&] { open(changed); });
        changed = wire;
        changed[HeaderSize + crypto_box_PUBLICKEYBYTES - 1] |= 0x80;
        signAsSender(changed);
        refuses(EnvelopeCode::Invalid, [&] { open(changed); });
    });

    test("authenticated ciphertext to the wrong recipient cannot be opened", [&] {
        const auto wrong = signedEnvelope(context, plaintext(context, publicKeyFixture), other->member().encryptionKey);
        KeyEnvelopeCodec::verify(wrong, context, sender->member());
        refuses(EnvelopeCode::DecryptionFailed, [&] { open(wrong); });
    });

    test("authenticated plaintext must reproduce the exact context and approved key", [&] {
        auto changed = context;
        changed.group[0] ^= 1;
        auto signedWrong = signedEnvelope(context, plaintext(changed, publicKeyFixture), context.recipient.encryptionKey);
        KeyEnvelopeCodec::verify(signedWrong, context, sender->member());
        refuses(EnvelopeCode::ContextMismatch, [&] { open(signedWrong); });
        auto wrongPlaintext = plaintext(context, publicKeyFixture);
        wrongPlaintext[0] ^= 1;
        signedWrong = signedEnvelope(context, std::move(wrongPlaintext), context.recipient.encryptionKey);
        refuses(EnvelopeCode::ContextMismatch, [&] { open(signedWrong); });
        auto wrongKey = publicKeyFixture;
        wrongKey[0] ^= 1;
        signedWrong = signedEnvelope(context, plaintext(context, wrongKey), context.recipient.encryptionKey);
        KeyEnvelopeCodec::verify(signedWrong, context, sender->member());
        refuses(EnvelopeCode::KeyMismatch, [&] { open(signedWrong); });
        // Even an independently committed all-zero key is rejected.
        auto zeroContext = context;
        const auto zeroCommitment = hexBytes("4e9dbf547c2769368a8377714efe115f43c7b3820c170660d6ead2c7d8e62fcd");
        std::copy(zeroCommitment.begin(), zeroCommitment.end(), zeroContext.commitment.begin());
        signedWrong = signedEnvelope(zeroContext, plaintext(zeroContext, Bytes(32, 0)), context.recipient.encryptionKey);
        KeyEnvelopeCodec::verify(signedWrong, zeroContext, sender->member());
        refuses(EnvelopeCode::KeyMismatch, [&] {
            KeyEnvelopeCodec::open(signedWrong, zeroContext, sender->member(), *recipient);
        });
    });

    std::cout << cases << " device key envelope test cases passed\n";
}
