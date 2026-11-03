// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_signed_event.h"
#include "test_check.h"
#include <sodium.h>
#include <algorithm>
#include <iostream>

using namespace cqs::trust;
using cqs::crypto::Bytes;
using EventErrorCode = cqs::events::ErrorCode;
using cqs::events::Limits;

namespace {
// Public RFC 8032 section 7.1 and RFC 7748 section 6.1 test keys.
constexpr char Seed[] = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
constexpr char Scalar[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
constexpr char IdentityDomain[] = "CopyQ-Secure-Sync-device-identity-private-lab-v1";
constexpr char WireDomain[] = "CopyQ-Secure-Sync-signed-event-lab-v1";
constexpr char PayloadDomain[] = "CopyQ-Secure-Sync-signed-event-payload-lab-v1";
constexpr char SignatureDomain[] = "CopyQ-Secure-Sync-signed-event-signature-lab-v1";
constexpr char KdfDomain[] = "CopyQ-Secure-Sync-signed-event-aes-gcm-key-lab-v1";
constexpr std::string_view Device = "d6fg7zb23dltvpbarf55jhkl2enugpjs";
constexpr std::string_view OtherDevice = "dkl7gbfduhp6u7g7egiozrloh4i6bvnr";
constexpr std::uint64_t Generation = 0x0102030405060708ULL;
constexpr std::size_t IdSize = 45;
constexpr std::size_t IdOffset = sizeof(WireDomain) + 4 + 5 * 32 + 2 * 8;
constexpr std::size_t ParentCountOffset = IdOffset + IdSize;
constexpr std::size_t ParentBytes = IdSize + 32;
constexpr std::size_t HeaderSize = ParentCountOffset + 1 + 2 * ParentBytes + 12 + 4;
constexpr std::size_t NonceOffset = HeaderSize - 16;
constexpr std::size_t SignatureSize = 64;

// Python struct, hashlib, hmac and cryptography's AESGCM/Ed25519 produced
// this full independent packet, with a fixed public key and nonce for testing.
constexpr char WireHex[] =
    "436f7079512d5365637572652d53796e632d7369676e65642d6576656e742d6c61622d76310000000001111111111111"
    "111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222"
    "222222222222222222223333333333333333333333333333333333333333333333333333333333333333d7353fe7cf0d"
    "2888dba12cc532ed5e8875130c1d01f5d2338b3223a96ab4dff4b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
    "b2b2b2b2b2b2b2b2b2b20102030405060708000000000000000364366667377a623233646c7476706261726635356a68"
    "6b6c32656e7567706a732f3030303030303030303030330264366667377a623233646c7476706261726635356a686b6c"
    "32656e7567706a732f303030303030303030303032777777777777777777777777777777777777777777777777777777"
    "7777777777646b6c376762666475687036753767376567696f7a726c6f6834693662766e722f30303030303030303030"
    "30378888888888888888888888888888888888888888888888888888888888888888000102030405060708090a0b0000"
    "0072592035dfc4c22ebeef622629edd88901524eaa5f3b189157ee8b1e6bc1c4363faad4b15dacef61bfa63cf0493a9b"
    "5aebaa648785c41031cad03980a5805b7861aa61b65e5192b2d605c8a61acab53a19a71c1f407017192d8f52086ab80f"
    "de1e430e1f3146d173f6756bafa1502dda5328301a41d833e8f66e2a71880d7f5016588250a9dab92ae7e5c1aa940a06"
    "d3564d3fbdfb4a3172e5a06c729f67c6e7539f6472bfbb06500bc04e6b802a793e869d06";

unsigned cases = 0;

template<class Action> void test(const char *name, const Action &action)
{
    action();
    ++cases;
    std::cout << "PASS " << name << '\n';
}

template<class Action> void refuses(const Action &action)
{
    try {
        action();
    } catch (const cqs::events::Error &) {
        return;
    }
    CHECK(false);
}

template<class Action> void refuses(EventErrorCode code, const Action &action)
{
    try {
        action();
    } catch (const cqs::events::Error &error) {
        if (error.code() != code) std::cerr << "Unexpected event error: " << error.what() << '\n';
        CHECK(error.code() == code);
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

Token token(std::uint8_t byte)
{
    Token result{};
    result.fill(byte);
    return result;
}

std::string_view view(const Bytes &bytes)
{
    return {bytes.empty() ? "" : reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

void u32(Bytes &bytes, std::uint32_t value)
{
    for (int shift = 24; shift >= 0; shift -= 8)
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}

Bytes payload(const std::vector<std::string> &items)
{
    Bytes bytes(PayloadDomain, PayloadDomain + sizeof(PayloadDomain));
    u32(bytes, static_cast<std::uint32_t>(items.size()));
    for (const auto &item : items) {
        u32(bytes, static_cast<std::uint32_t>(item.size()));
        bytes.insert(bytes.end(), item.begin(), item.end());
    }
    return bytes;
}

std::unique_ptr<Identity> fixtureIdentity()
{
    const auto id = token(0xb2);
    const auto seed = hexBytes(Seed), scalar = hexBytes(Scalar);
    Bytes bytes;
    bytes.reserve(sizeof(IdentityDomain) + 96);
    bytes.insert(bytes.end(), IdentityDomain, IdentityDomain + sizeof(IdentityDomain));
    bytes.insert(bytes.end(), id.begin(), id.end());
    bytes.insert(bytes.end(), seed.begin(), seed.end());
    bytes.insert(bytes.end(), scalar.begin(), scalar.end());
    auto identity = Identity::restore(bytes);
    cqs::crypto::wipe(bytes);
    return identity;
}

void signRaw(Bytes &wire)
{
    const auto hash = cqs::crypto::sha256(wire);
    Bytes message(SignatureDomain, SignatureDomain + sizeof(SignatureDomain));
    message.insert(message.end(), hash.begin(), hash.end());
    const auto seed = hexBytes(Seed);
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> publicKey{};
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret{};
    CHECK(crypto_sign_seed_keypair(publicKey.data(), secret.data(), seed.data()) == 0);
    const auto signedSize = wire.size();
    wire.resize(signedSize + SignatureSize);
    CHECK(crypto_sign_detached(wire.data() + signedSize, nullptr, message.data(), message.size(), secret.data()) == 0);
    sodium_memzero(secret.data(), secret.size());
}

Bytes repack(const Bytes &wire, const Bytes &plain, const Bytes &aesKey)
{
    const Bytes nonce(wire.begin() + NonceOffset, wire.begin() + NonceOffset + 12);
    Bytes header(wire.begin(), wire.begin() + HeaderSize - 4);
    u32(header, static_cast<std::uint32_t>(plain.size() + 16));
    const auto cipher = cqs::crypto::aes256GcmEncrypt(aesKey, nonce, plain, header);
    header.insert(header.end(), cipher.begin(), cipher.end());
    signRaw(header);
    return header;
}
} // namespace

int main()
{
    CHECK(sodium_init() >= 0);
    const auto author = fixtureIdentity();
    const auto other = Identity::generate();
    const auto rawKey = hexBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const auto derived = hexBytes("12ce75cf0cc376ef20a30afb69f7ce11c3174d624e06a1256e7fa08db2900e3f");
    const auto key = SyncKey::import(rawKey);
    const SignedEventContext context{token(0x11), token(0x22), token(0x33), key->commitment(token(0x11), Generation),
                                     author->member().id, Generation};
    const auto id = std::string(Device) + "/000000000003";
    const std::vector<SignedEventParent> parents{
        {std::string(Device) + "/000000000002", token(0x77)},
        {std::string(OtherDevice) + "/000000000007", token(0x88)}};
    const std::vector<std::string> items{"AAAAAA==", "/////gAAAAEAAAACADQAAAAAA0FCQw=="};
    const auto plain = payload(items);
    const auto wire = hexBytes(WireHex);
    const auto open = [&](const Bytes &packet, Limits limits = {}) {
        return SignedEventCodec::open({id, view(packet)}, context, author->member(), *key, limits);
    };

    test("independent binary wire, alias, KDF and signature vectors", [&] {
        CHECK(HeaderSize == 434 && plain.size() == 98 && wire.size() == 612);
        CHECK(SignedEventCodec::deviceName(context.author) == Device);
        CHECK(SignedEventCodec::deviceName(token(0xa1)) == OtherDevice);
        auto changedAuthor = context.author;
        changedAuthor.back() ^= 1;
        CHECK(SignedEventCodec::deviceName(changedAuthor) != Device);
        CHECK(Bytes(context.commitment.begin(), context.commitment.end()) ==
              hexBytes("d7353fe7cf0d2888dba12cc532ed5e8875130c1d01f5d2338b3223a96ab4dff4"));
        const auto digest = SignedEventCodec::digest(view(wire));
        CHECK(Bytes(digest.begin(), digest.end()) ==
              hexBytes("3a28057801e4c7f0ff6f5f8f42ac122ae58b89f3e577df38ae86c32e3b0b5eef"));
        Bytes info(KdfDomain, KdfDomain + sizeof(KdfDomain));
        info.insert(info.end(), context.group.begin(), context.group.end());
        info.insert(info.end(), context.root.begin(), context.root.end());
        for (int shift = 56; shift >= 0; shift -= 8) info.push_back(static_cast<std::uint8_t>(Generation >> shift));
        Bytes rawHmac(32);
        CHECK(crypto_auth_hmacsha256(rawHmac.data(), info.data(), info.size(), rawKey.data()) == 0);
        CHECK(rawHmac == derived);
        CHECK(repack(wire, plain, derived) == wire);
        const auto header = SignedEventCodec::inspect(view(wire));
        CHECK(header.revision.id == id && header.revision.device == Device && header.revision.sequence == 3);
        CHECK(header.context.generation == Generation && header.context.author == context.author);
        CHECK(header.parents.size() == parents.size());
        for (std::size_t i = 0; i < parents.size(); ++i) {
            CHECK(header.parents[i].id == parents[i].id && header.parents[i].digest == parents[i].digest);
            CHECK(header.revision.parents[i] == parents[i].id);
        }
        const auto decoded = open(wire);
        CHECK(decoded.revision.id == id && decoded.items == items && decoded.plaintextBytes == plain.size());
        const auto created = SignedEventCodec::seal(context, *author, *key, 3, parents, items);
        CHECK(created.size() == wire.size());
        CHECK(std::equal(wire.begin(), wire.begin() + NonceOffset, created.begin()));
        CHECK(repack(created, plain, derived) == created);
        CHECK(open(created).items == items);
        CHECK(SignedEventCodec::seal(context, *author, *key, 3, parents, items) != created);
    });

    test("all truncations, invalid framing and authenticated legacy input refused", [&] {
        const auto malformed = [&](const Bytes &input) {
            refuses([&] { SignedEventCodec::inspect(view(input)); });
            refuses([&] { open(input); });
        };
        for (std::size_t size = 0; size < wire.size(); ++size)
            malformed(Bytes(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(size)));
        auto changed = wire;
        changed.push_back(0);
        malformed(changed);
        for (const auto offset : {std::size_t{0}, sizeof(WireDomain) - 1, sizeof(WireDomain) + 3,
                                 IdOffset + IdSize - 1, ParentCountOffset, HeaderSize - 4}) {
            changed = wire;
            changed[offset] ^= 0x80;
            malformed(changed);
        }
        const std::string legacy =
            "{\"header\":{\"device\":\"" + std::string(Device) +
            "\",\"parents\":[],\"protocol\":\"copyq-secure-sync-v1\",\"seq\":3},"
            "\"nonce\":\"AAECAwQFBgcICQoL\",\"ciphertext\":\""
            "i9zUf98KM2brIuvmfiT5oq/cA5FpAkV65XnoH1q2yNZJxP9TSOlxbuFusW8YJYtY67nTT1FOATv+jqdGBexBbF3JC7Q=\"}";
        CHECK(cqs::events::decode(rawKey, {id, legacy}).items == std::vector<std::string>{items.front()});
        refuses(EventErrorCode::InvalidHeader, [&] { SignedEventCodec::open({id, legacy}, context, author->member(), *key); });
    });

    test("file identity, membership context and author verification bind independently", [&] {
        for (const auto field : {&SignedEventContext::group, &SignedEventContext::root, &SignedEventContext::head,
                                 &SignedEventContext::commitment, &SignedEventContext::author}) {
            auto changed = context;
            (changed.*field).back() ^= 1;
            refuses(EventErrorCode::WrongIdentity, [&] {
                SignedEventCodec::open({id, view(wire)}, changed, author->member(), *key);
            });
        }
        auto changed = context;
        ++changed.generation;
        refuses(EventErrorCode::WrongIdentity, [&] { SignedEventCodec::open({id, view(wire)}, changed, author->member(), *key); });
        refuses(EventErrorCode::WrongIdentity, [&] {
            SignedEventCodec::open({parents[0].id, view(wire)}, context, author->member(), *key);
        });
        refuses(EventErrorCode::WrongIdentity, [&] { SignedEventCodec::open({id, view(wire)}, context, other->member(), *key); });
        auto substituted = author->member();
        substituted.signingKey = other->member().signingKey;
        refuses(EventErrorCode::AuthenticationFailed, [&] { SignedEventCodec::open({id, view(wire)}, context, substituted, *key); });
        refuses(EventErrorCode::WrongIdentity, [&] { SignedEventCodec::seal(context, *other, *key, 3, parents, items); });
        const auto wrongKey = SyncKey::generate();
        refuses(EventErrorCode::InvalidKey, [&] { SignedEventCodec::open({id, view(wire)}, context, author->member(), *wrongKey); });
        refuses(EventErrorCode::InvalidKey, [&] { SignedEventCodec::seal(context, *author, *wrongKey, 3, parents, items); });
    });

    test("signature protects exact parent digest, nonce and ciphertext before payload parsing", [&] {
        for (const auto offset : {ParentCountOffset + 1 + IdSize, NonceOffset, HeaderSize,
                                 wire.size() - SignatureSize - 1, wire.size() - 1}) {
            auto changed = wire;
            changed[offset] ^= 1;
            CHECK(SignedEventCodec::inspect(view(changed)).revision.id == id);
            refuses(EventErrorCode::AuthenticationFailed, [&] { open(changed); });
        }
        auto badPayload = repack(wire, payload({"AB=="}), derived);
        refuses(EventErrorCode::InvalidBase64, [&] { open(badPayload); });
        badPayload.back() ^= 1;
        refuses(EventErrorCode::AuthenticationFailed, [&] { open(badPayload); });

        auto invalidCipher = wire;
        invalidCipher.resize(invalidCipher.size() - SignatureSize);
        invalidCipher.back() ^= 1;
        signRaw(invalidCipher);
        refuses(EventErrorCode::AuthenticationFailed, [&] { open(invalidCipher); });
        refuses(EventErrorCode::AuthenticationFailed, [&] { open(repack(wire, plain, rawKey)); });
    });

    test("authorized malformed plaintext is refused and packed items use canonical Base64", [&] {
        for (const auto &value : {"AB==", "AAB=", "AA=A", "====", "_AAA", "A A=", "AAA=\n"}) {
            refuses(EventErrorCode::InvalidBase64, [&] { open(repack(wire, payload({value}), derived)); });
            refuses(EventErrorCode::InvalidBase64, [&] { SignedEventCodec::seal(context, *author, *key, 3, parents, {value}); });
        }
        auto bad = plain;
        bad[0] ^= 1;
        refuses(EventErrorCode::InvalidPayload, [&] { open(repack(wire, bad, derived)); });
        bad = plain;
        bad.push_back(0);
        refuses(EventErrorCode::InvalidPayload, [&] { open(repack(wire, bad, derived)); });
        bad = plain;
        bad.pop_back();
        refuses(EventErrorCode::InvalidPayload, [&] { open(repack(wire, bad, derived)); });
        bad = plain;
        std::fill_n(bad.begin() + sizeof(PayloadDomain), 4, 0xff);
        refuses([&] { open(repack(wire, bad, derived)); });
        refuses([&] { open(repack(wire, payload({""}), derived)); });
    });

    test("parent identifiers are unique, sorted, strictly signed and monotonic", [&] {
        auto invalid = parents;
        std::reverse(invalid.begin(), invalid.end());
        refuses(EventErrorCode::InvalidHeader, [&] { SignedEventCodec::seal(context, *author, *key, 3, invalid, items); });
        auto reordered = wire;
        const auto first = reordered.begin() + ParentCountOffset + 1;
        std::swap_ranges(first, first + ParentBytes, first + ParentBytes);
        reordered.resize(reordered.size() - SignatureSize);
        signRaw(reordered);
        refuses(EventErrorCode::InvalidHeader, [&] { SignedEventCodec::inspect(view(reordered)); });
        refuses(EventErrorCode::InvalidHeader, [&] { open(reordered); });

        invalid = {parents.front(), parents.front()};
        refuses(EventErrorCode::InvalidHeader, [&] { SignedEventCodec::seal(context, *author, *key, 3, invalid, items); });
        for (const auto &parentId : {id, std::string(Device) + "/000000000004", std::string("legacy/000000000001")}) {
            invalid = {{parentId, token(0x55)}};
            refuses(EventErrorCode::InvalidHeader, [&] { SignedEventCodec::seal(context, *author, *key, 3, invalid, items); });
        }
        invalid = {{parents.front().id, {}}};
        refuses(EventErrorCode::InvalidHeader, [&] { SignedEventCodec::seal(context, *author, *key, 3, invalid, items); });
        invalid = parents;
        invalid.front().digest.back() ^= 1;
        const auto changed = SignedEventCodec::seal(context, *author, *key, 3, invalid, items);
        CHECK(SignedEventCodec::inspect(view(changed)).parents.front().digest == invalid.front().digest);
        CHECK(SignedEventCodec::digest(view(changed)) != SignedEventCodec::digest(view(wire)));
        CHECK(open(changed).items == items);
    });

    test("wire, plaintext, item and event ceilings enforce exact bounds", [&] {
        for (const auto field : {&Limits::eventBytes, &Limits::historyBytes, &Limits::plaintextBytes,
                                 &Limits::historyPlaintextBytes, &Limits::items, &Limits::events}) {
            Limits invalid;
            ++(invalid.*field);
            refuses(EventErrorCode::InvalidLimits, [&] { SignedEventCodec::validateLimits(invalid); });
        }
        Limits exact{wire.size(), plain.size(), items.size(), wire.size(), plain.size(), 1};
        CHECK(open(wire, exact).items == items);
        CHECK(SignedEventCodec::seal(context, *author, *key, 3, parents, items, exact).size() == wire.size());
        for (const auto field : {&Limits::eventBytes, &Limits::historyBytes, &Limits::plaintextBytes,
                                 &Limits::historyPlaintextBytes, &Limits::items, &Limits::events}) {
            auto lower = exact;
            --(lower.*field);
            refuses(EventErrorCode::SizeLimit, [&] { open(wire, lower); });
            refuses(EventErrorCode::SizeLimit, [&] { SignedEventCodec::seal(context, *author, *key, 3, parents, items, lower); });
        }
        Limits emptyLimits;
        emptyLimits.items = 0;
        const auto empty = SignedEventCodec::seal(context, *author, *key, 3, {}, {}, emptyLimits);
        CHECK(open(empty, emptyLimits).items.empty());
    });

    std::cout << cases << " signed event codec test cases passed\n";
}
