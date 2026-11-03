// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_signed_event.h"
#include <sodium.h>
#include <algorithm>
#include <utility>

namespace cqs::trust {
namespace {
using crypto::Bytes;
using EventError = events::ErrorCode;

// All domains include NUL. Integers are unsigned big endian. Wire layout:
// domain, u32 version, group/root/head/commitment/author (32 bytes each),
// u64 generation, u64 sequence, id45, u8 parent count, each parent id45 and
// digest32, nonce12, u32 ciphertext length, ciphertext including tag16, sig64.
// AAD is the wire prefix through ciphertext length. Sign the signature domain
// followed by SHA-256 of the exact wire prefix through ciphertext/tag.
constexpr char WireDomain[] = "CopyQ-Secure-Sync-signed-event-lab-v1";
constexpr char SignatureDomain[] = "CopyQ-Secure-Sync-signed-event-signature-lab-v1";
constexpr char KeyDomain[] = "CopyQ-Secure-Sync-signed-event-aes-gcm-key-lab-v1";
constexpr char PayloadDomain[] = "CopyQ-Secure-Sync-signed-event-payload-lab-v1";
constexpr char Base32[] = "abcdefghijklmnopqrstuvwxyz234567";
constexpr std::uint32_t EventVersion = 1;
constexpr std::size_t DeviceSize = 32, IdSize = 45, MaxParents = 2;
constexpr std::size_t NonceSize = 12, TagSize = 16, SignatureSize = Signature{}.size();
constexpr std::size_t PayloadMinimum = sizeof(PayloadDomain) + 4;

static_assert(crypto_auth_hmacsha256_KEYBYTES == SyncKey::Size && crypto_auth_hmacsha256_BYTES == 32,
              "Signed event key derivation sizes changed");
static_assert(crypto_hash_sha256_BYTES == Token{}.size(), "Signed event digest size changed");

[[noreturn]] void fail(EventError code, const char *message) { throw events::Error(code, message); }

bool zero(const Token &token) {
    return std::all_of(token.begin(), token.end(), [](std::uint8_t byte) { return byte == 0; });
}

void validateContext(const SignedEventContext &context) {
    if (zero(context.group) || zero(context.root) || zero(context.head) ||
        zero(context.commitment) || zero(context.author)) {
        fail(EventError::InvalidHeader, "Invalid signed event context");
    }
}

bool sameContext(const SignedEventContext &a, const SignedEventContext &b) {
    return a.group == b.group && a.root == b.root && a.head == b.head && a.commitment == b.commitment &&
           a.author == b.author && a.generation == b.generation;
}

template<class Range> void append(Bytes &out, const Range &bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

template<std::size_t N> void domain(Bytes &out, const char (&value)[N]) {
    out.insert(out.end(), value, value + N);
}

void u32(Bytes &out, std::uint32_t number) {
    for (unsigned shift = 32; shift != 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(number >> (shift - 8)));
}

void u64(Bytes &out, std::uint64_t number) {
    for (unsigned shift = 64; shift != 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(number >> (shift - 8)));
}

std::string_view view(const Bytes &bytes) {
    if (bytes.empty()) return {};
    return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

Bytes copy(std::string_view bytes) { return Bytes(bytes.begin(), bytes.end()); }

Token hash(std::string_view bytes) {
    SodiumVerifier{};
    static const std::uint8_t empty = 0;
    const auto *input = bytes.empty() ? &empty : reinterpret_cast<const std::uint8_t *>(bytes.data());
    Token digest{};
    if (crypto_hash_sha256(digest.data(), input, bytes.size()) != 0) throw crypto::Error("Signed event hashing failed");
    return digest;
}

Bytes signatureMessage(std::string_view signedWire) {
    Bytes message;
    message.reserve(sizeof(SignatureDomain) + Token{}.size());
    domain(message, SignatureDomain);
    append(message, hash(signedWire));
    return message;
}

struct WipedBytes {
    Bytes value;
    WipedBytes() = default;
    explicit WipedBytes(Bytes bytes) : value(std::move(bytes)) {}
    WipedBytes(const WipedBytes &) = delete;
    WipedBytes &operator=(const WipedBytes &) = delete;
    ~WipedBytes() { crypto::wipe(value); }
};

void deriveKey(WipedBytes &derived, const SyncKey &key, const SignedEventContext &context) {
    Bytes input;
    input.reserve(sizeof(KeyDomain) + 2 * Token{}.size() + 8);
    domain(input, KeyDomain);
    append(input, context.group);
    append(input, context.root);
    u64(input, context.generation);
    const WipedBytes raw(key.exportPrivate());
    derived.value.resize(crypto_auth_hmacsha256_BYTES);
    if (crypto_auth_hmacsha256(derived.value.data(), input.data(), input.size(), raw.value.data()) != 0)
        throw crypto::Error("Signed event key derivation failed");
}

void checkKey(const SyncKey &key, const SignedEventContext &context) {
    if (key.commitment(context.group, context.generation) != context.commitment)
        fail(EventError::InvalidKey, "Signed event key commitment differs");
}

bool signedId(std::string_view id) {
    constexpr std::string_view alphabet(Base32, sizeof(Base32) - 1);
    if (id.size() != IdSize || id[0] != 'd' || id[DeviceSize] != '/') return false;
    return id.substr(1, DeviceSize - 1).find_first_not_of(alphabet) == std::string_view::npos;
}

history::Revision revision(const Token &author, std::uint64_t sequence, const std::vector<SignedEventParent> &parents) {
    if (parents.size() > MaxParents) fail(EventError::InvalidHeader, "Too many signed event parents");
    history::Revision value;
    value.device = SignedEventCodec::deviceName(author);
    value.sequence = sequence;
    for (const auto &parent : parents) {
        if (!signedId(parent.id) || zero(parent.digest)) fail(EventError::InvalidHeader, "Invalid signed event parent");
        value.parents.push_back(parent.id);
    }
    try {
        value.id = history::makeId(value.device, sequence);
        history::validateRevision(value);
    } catch (const history::Error &) {
        fail(EventError::InvalidHeader, "Invalid signed event revision");
    }
    return value;
}

class Reader final {
public:
    Reader(std::string_view bytes, EventError malformed) : bytes_(bytes), malformed_(malformed) {}
    std::size_t remaining() const noexcept { return bytes_.size(); }
    std::string_view take(std::size_t size) {
        if (size > bytes_.size()) invalid();
        const auto value = bytes_.substr(0, size);
        bytes_.remove_prefix(size);
        return value;
    }
    template<std::size_t N> void expect(const char (&value)[N]) {
        if (take(N) != std::string_view(value, N)) invalid();
    }
    std::uint8_t byte() { return static_cast<std::uint8_t>(take(1)[0]); }
    std::uint32_t number32() {
        std::uint32_t number = 0;
        for (unsigned i = 0; i < 4; ++i) number = (number << 8) | byte();
        return number;
    }
    std::uint64_t number64() {
        std::uint64_t number = 0;
        for (unsigned i = 0; i < 8; ++i) number = (number << 8) | byte();
        return number;
    }
    Token token() {
        Token result{};
        const auto value = take(result.size());
        std::copy(value.begin(), value.end(), result.begin());
        return result;
    }
private:
    [[noreturn]] void invalid() const { fail(malformed_, "Invalid signed event framing"); }
    std::string_view bytes_;
    EventError malformed_;
};

std::size_t wireLimit(const events::Limits &limits) { return std::min(limits.eventBytes, limits.historyBytes); }
std::size_t plainLimit(const events::Limits &limits) { return std::min(limits.plaintextBytes, limits.historyPlaintextBytes); }

struct Parsed {
    SignedEventHeader header;
    std::string_view aad, nonce, cipher;
    Signature signature{};
};

Parsed parse(std::string_view wire, events::Limits limits) {
    SignedEventCodec::validateLimits(limits);
    if (!limits.events || wire.size() > wireLimit(limits)) fail(EventError::SizeLimit, "Signed event exceeds wire budget");

    Reader reader(wire, EventError::InvalidHeader);
    reader.expect(WireDomain);
    if (reader.number32() != EventVersion) fail(EventError::InvalidHeader, "Unsupported signed event version");
    Parsed value;
    auto &header = value.header;
    auto &context = header.context;
    context.group = reader.token();
    context.root = reader.token();
    context.head = reader.token();
    context.commitment = reader.token();
    context.author = reader.token();
    context.generation = reader.number64();
    validateContext(context);

    const auto sequence = reader.number64();
    const auto id = reader.take(IdSize);
    const auto count = reader.byte();
    if (count > MaxParents) fail(EventError::InvalidHeader, "Too many signed event parents");
    for (unsigned i = 0; i < count; ++i) header.parents.push_back({std::string(reader.take(IdSize)), reader.token()});
    header.revision = revision(context.author, sequence, header.parents);
    if (id != header.revision.id) fail(EventError::InvalidHeader, "Signed event ID differs from its author or sequence");

    value.nonce = reader.take(NonceSize);
    const auto cipherSize = reader.number32();
    if (reader.remaining() < SignatureSize || cipherSize != reader.remaining() - SignatureSize ||
        cipherSize < TagSize + PayloadMinimum) {
        fail(EventError::InvalidHeader, "Invalid signed event ciphertext length");
    }
    if (cipherSize - TagSize > plainLimit(limits)) fail(EventError::SizeLimit, "Signed event exceeds plaintext budget");
    value.aad = wire.substr(0, wire.size() - reader.remaining());
    value.cipher = reader.take(cipherSize);
    const auto signature = reader.take(SignatureSize);
    std::copy(signature.begin(), signature.end(), value.signature.begin());
    return value;
}

Parsed authenticate(const events::Envelope &envelope, const SignedEventContext &expected,
                    const Member &author, events::Limits limits) {
    auto parsed = parse(envelope.bytes, limits);
    if (parsed.header.revision.id != envelope.expectedId || !sameContext(parsed.header.context, expected) ||
        author.id != expected.author) {
        fail(EventError::WrongIdentity, "Signed event does not match pinned context or file identity");
    }
    const SodiumVerifier verifier;
    const auto signedWire = envelope.bytes.substr(0, envelope.bytes.size() - SignatureSize);
    if (!SodiumVerifier::validMember(author) ||
        !verifier.verify(author.signingKey, signatureMessage(signedWire), parsed.signature)) {
        fail(EventError::AuthenticationFailed, "Signed event author signature failed");
    }
    return parsed;
}

int sextet(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
}

void checkPacked(std::string_view item) {
    if (item.empty() || item.size() % 4 != 0) fail(EventError::InvalidBase64, "Invalid signed event packed item");
    const auto size = item.size();
    const std::size_t padding = item[size - 1] == '=' ? (item[size - 2] == '=' ? 2 : 1) : 0;
    for (std::size_t i = 0; i < size - padding; ++i) {
        if (sextet(item[i]) < 0) fail(EventError::InvalidBase64, "Invalid signed event packed item");
    }
    if ((padding == 2 && (sextet(item[size - 3]) & 15)) ||
        (padding == 1 && (sextet(item[size - 2]) & 3))) {
        fail(EventError::InvalidBase64, "Noncanonical signed event packed item");
    }
}

// Uncompressed payload: domain, u32 count, then u32 length and canonical
// base64 bytes for each item. The transaction layer validates MIME semantics.
void encodePayload(WipedBytes &plain, const std::vector<std::string> &items, std::size_t sizeLimit, std::size_t itemLimit) {
    if (items.size() > itemLimit || sizeLimit < PayloadMinimum) fail(EventError::SizeLimit, "Signed event exceeds payload budget");
    std::size_t size = PayloadMinimum;
    for (const auto &item : items) {
        if (sizeLimit - size < 4 || item.size() > sizeLimit - size - 4)
            fail(EventError::SizeLimit, "Signed event exceeds payload budget");
        checkPacked(item);
        size += 4 + item.size();
    }

    plain.value.reserve(size);
    domain(plain.value, PayloadDomain);
    u32(plain.value, static_cast<std::uint32_t>(items.size()));
    for (const auto &item : items) {
        u32(plain.value, static_cast<std::uint32_t>(item.size()));
        append(plain.value, item);
    }
}

std::vector<std::string> decodePayload(std::string_view plain, std::size_t itemLimit) {
    Reader reader(plain, EventError::InvalidPayload);
    reader.expect(PayloadDomain);
    const auto count = reader.number32();
    if (count > itemLimit) fail(EventError::SizeLimit, "Signed event exceeds item budget");
    if (count > reader.remaining() / 8) fail(EventError::InvalidPayload, "Invalid signed event item count");
    std::vector<std::string> items;
    struct WipeItems {
        std::vector<std::string> &value;
        ~WipeItems() {
            for (auto &item : value) if (!item.empty()) sodium_memzero(item.data(), item.size());
        }
    } wipe{items};
    items.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto size = reader.number32();
        const auto item = reader.take(size);
        checkPacked(item);
        items.emplace_back(item);
    }
    if (reader.remaining() != 0) fail(EventError::InvalidPayload, "Unexpected signed event payload data");
    // Move the vector out of the scope with the wipe guard. If an exception
    // occurs during parsing, the guard clears every already copied item.
    return std::vector<std::string>(std::move(items));
}
} // namespace

void SignedEventCodec::validateLimits(events::Limits limits) {
    const events::Limits ceiling;
    if (!limits.eventBytes || !limits.plaintextBytes || !limits.historyBytes || !limits.historyPlaintextBytes ||
        limits.eventBytes > ceiling.eventBytes || limits.plaintextBytes > ceiling.plaintextBytes ||
        limits.items > ceiling.items || limits.events > ceiling.events || limits.historyBytes > ceiling.historyBytes ||
        limits.historyPlaintextBytes > ceiling.historyPlaintextBytes) {
        fail(EventError::InvalidLimits, "Invalid signed event limits");
    }
}

std::string SignedEventCodec::deviceName(const Token &author) {
    if (zero(author)) fail(EventError::InvalidHeader, "Invalid signed event author");
    const auto hashed = hash({reinterpret_cast<const char *>(author.data()), author.size()});
    std::string device("d");
    device.reserve(DeviceSize);
    for (std::size_t i = 0; i < DeviceSize - 1; ++i) {
        unsigned digit = 0;
        for (std::size_t j = 0; j < 5; ++j) {
            const auto bit = 5 * i + j;
            digit = (digit << 1) | ((hashed[bit / 8] >> (7 - bit % 8)) & 1U);
        }
        device.push_back(Base32[digit]);
    }
    return device;
}

Token SignedEventCodec::digest(std::string_view wire) {
    if (wire.size() > events::Limits{}.eventBytes) fail(EventError::SizeLimit, "Signed event exceeds digest budget");
    return hash(wire);
}

SignedEventHeader SignedEventCodec::inspect(std::string_view wire, events::Limits limits) {
    return parse(wire, limits).header;
}

Bytes SignedEventCodec::seal(const SignedEventContext &context, const Identity &author, const SyncKey &key,
                             std::uint64_t sequence, const std::vector<SignedEventParent> &parents,
                             const std::vector<std::string> &packedItems, events::Limits limits) {
    validateLimits(limits);
    validateContext(context);
    if (author.member().id != context.author) fail(EventError::WrongIdentity, "Signed event author differs");
    const auto identity = revision(context.author, sequence, parents);
    checkKey(key, context);

    Bytes wire;
    domain(wire, WireDomain);
    u32(wire, EventVersion);
    append(wire, context.group);
    append(wire, context.root);
    append(wire, context.head);
    append(wire, context.commitment);
    append(wire, context.author);
    u64(wire, context.generation);
    u64(wire, sequence);
    append(wire, identity.id);
    wire.push_back(static_cast<std::uint8_t>(parents.size()));
    for (const auto &parent : parents) {
        append(wire, parent.id);
        append(wire, parent.digest);
    }

    const auto overhead = wire.size() + NonceSize + 4 + TagSize + SignatureSize;
    const auto limit = wireLimit(limits);
    if (!limits.events || overhead > limit) fail(EventError::SizeLimit, "Signed event exceeds wire budget");
    Bytes cipher;
    {
        WipedBytes plain;
        encodePayload(plain, packedItems, std::min(plainLimit(limits), limit - overhead), limits.items);
        const auto nonce = crypto::random(NonceSize);
        append(wire, nonce);
        u32(wire, static_cast<std::uint32_t>(plain.value.size() + TagSize));
        WipedBytes derived;
        deriveKey(derived, key, context);
        cipher = crypto::aes256GcmEncrypt(derived.value, nonce, plain.value, wire);
    }
    wire.reserve(wire.size() + cipher.size() + SignatureSize);
    append(wire, cipher);
    const auto signature = author.sign(signatureMessage(view(wire)));
    append(wire, signature);
    return wire;
}

void SignedEventCodec::verify(const events::Envelope &envelope, const SignedEventContext &expected,
                              const Member &author, events::Limits limits) {
    (void)authenticate(envelope, expected, author, limits);
}

events::Event SignedEventCodec::open(const events::Envelope &envelope, const SignedEventContext &expected,
                                    const Member &author, const SyncKey &key, events::Limits limits) {
    auto parsed = authenticate(envelope, expected, author, limits);
    checkKey(key, expected);

    WipedBytes plain;
    {
        WipedBytes derived;
        deriveKey(derived, key, expected);
        try {
            plain.value = crypto::aes256GcmDecrypt(derived.value, copy(parsed.nonce), copy(parsed.cipher), copy(parsed.aad));
        } catch (const crypto::Error &) {
            fail(EventError::AuthenticationFailed, "Signed event ciphertext authentication failed");
        }
    }
    auto items = decodePayload(view(plain.value), limits.items);
    return {std::move(parsed.header.revision), std::move(items), plain.value.size()};
}
} // namespace cqs::trust
