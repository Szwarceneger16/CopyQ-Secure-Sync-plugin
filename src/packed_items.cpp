// SPDX-License-Identifier: GPL-3.0-or-later
#include "packed_items.h"
#include <algorithm>
#include <array>
#include <string_view>

namespace cqs::packed {
namespace {
using crypto::Bytes;
[[noreturn]] void fail() { throw Error(); }
void account(std::size_t size, std::size_t &total, std::size_t limit) {
    if (total > limit || size > limit - total) fail();
    total += size;
}
void mimeName(std::string_view name, transaction::Limits limits) {
    if (name.empty() || name.size() > limits.mimeNameBytes || name.substr(0, 5) == "FILE:" ||
        !std::all_of(name.begin(), name.end(), [](unsigned char c) { return c >= 0x21 && c <= 0x7e; })) fail();
}
int sextet(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
}
Bytes base64(std::string_view text) {
    if (text.empty() || text.size() % 4) fail();
    const auto n = text.size();
    const std::size_t padding = text[n - 1] == '=' ? (text[n - 2] == '=' ? 2 : 1) : 0;
    for (std::size_t i = 0; i < n - padding; ++i) if (sextet(text[i]) < 0) fail();
    if ((padding == 2 && (sextet(text[n - 3]) & 15)) || (padding == 1 && (sextet(text[n - 2]) & 3))) fail();
    const auto size = n / 4 * 3 - padding;
    Bytes out; out.reserve(size);
    for (std::size_t i = 0; i < n; i += 4) {
        const auto a = static_cast<unsigned>(sextet(text[i])), b = static_cast<unsigned>(sextet(text[i + 1]));
        const auto c = text[i + 2] == '=' ? 0U : static_cast<unsigned>(sextet(text[i + 2]));
        const auto d = text[i + 3] == '=' ? 0U : static_cast<unsigned>(sextet(text[i + 3]));
        out.push_back(static_cast<std::uint8_t>((a << 2) | (b >> 4)));
        if (out.size() < size) out.push_back(static_cast<std::uint8_t>((b << 4) | (c >> 2)));
        if (out.size() < size) out.push_back(static_cast<std::uint8_t>((c << 6) | d));
    }
    return out;
}
class Stream {
public:
    explicit Stream(const Bytes &bytes) : bytes_(bytes) {}
    std::uint32_t u32() {
        std::uint32_t n = 0;
        for (unsigned i = 0; i < 4; ++i) n = (n << 8) | byte();
        return n;
    }
    unsigned byte() { if (pos_ == bytes_.size()) fail(); return bytes_[pos_++]; }
    std::string name(transaction::Limits limits) {
        const auto size = u32();
        // QString uses a byte count, then UTF-16BE. Accepted effective MIME
        // names are ASCII; reject non-ASCII instead of lossy conversion.
        if (size % 2 || size / 2 > limits.mimeNameBytes + 1 || size > bytes_.size() - pos_) fail();
        std::string name; name.reserve(size / 2);
        for (unsigned i = 0; i < size; i += 2) {
            if (byte() != 0) fail();
            const auto c = byte(); if (c < 0x21 || c > 0x7e) fail();
            name += static_cast<char>(c);
        }
        return name;
    }
    Bytes value(std::size_t budget, bool compressed) {
        auto size = u32();
        if (size == 0xffffffffU) size = 0; // Qt null QByteArray is effective empty data.
        if (size > bytes_.size() - pos_) fail();
        if (!compressed && size > budget) fail();
        if (compressed) {
            if (size < 5) fail();
            const auto advertised = u32();
            if (!advertised || advertised > budget) fail();
            size -= 4;
            Bytes wire(bytes_.begin() + pos_, bytes_.begin() + pos_ + size); pos_ += size;
            Bytes value;
            try { value = crypto::zlibDecompressBounded(wire, advertised); }
            catch (const crypto::Error &) { fail(); }
            if (value.size() != advertised) fail();
            return value;
        }
        Bytes value(bytes_.begin() + pos_, bytes_.begin() + pos_ + size); pos_ += size;
        return value;
    }
    bool end() const { return pos_ == bytes_.size(); }
private:
    const Bytes &bytes_;
    std::size_t pos_ = 0;
};
std::string expanded(std::string name) {
    constexpr std::array<std::string_view, 12> prefixes{
        "", "application/x-copyq-owner-window-title", "application/x-copyq-item-notes",
        "application/x-copyq-", "text/plain", "text/html", "text/uri-list",
        "image/", "text/", "application/", "audio/", "video/"};
    if (name.empty()) fail();
    const auto c = name[0];
    const auto id = c >= '0' && c <= '9' ? c - '0' :
        c >= 'a' && c <= 'b' ? c - 'a' + 10 : c >= 'A' && c <= 'B' ? c - 'A' + 10 : -1;
    if (id < 0) fail();
    return std::string(prefixes[static_cast<std::size_t>(id)]) + name.substr(1);
}
} // namespace
void validateLimits(transaction::Limits limits) {
    const transaction::Limits ceiling;
    if (limits.items > ceiling.items || !limits.formatsPerItem || limits.formatsPerItem > ceiling.formatsPerItem ||
        !limits.mimeNameBytes || limits.mimeNameBytes > ceiling.mimeNameBytes ||
        !limits.snapshotBytes || limits.snapshotBytes > ceiling.snapshotBytes) fail();
}
void validateSnapshot(const transaction::Snapshot &snapshot, transaction::Limits limits) {
    validateLimits(limits);
    if (snapshot.size() > limits.items) fail();
    std::size_t total = 0;
    for (const auto &item : snapshot) {
        if (item.size() > limits.formatsPerItem) fail();
        for (const auto &field : item) {
            mimeName(field.first, limits);
            account(field.first.size(), total, limits.snapshotBytes);
            account(field.second.size(), total, limits.snapshotBytes);
        }
    }
}
transaction::Snapshot decode(const std::vector<std::string> &items, transaction::Limits limits) {
    validateLimits(limits);
    if (items.size() > limits.items) fail();
    // Apply the v1 event plaintext ceiling to packed input too. A format count
    // limit alone must not permit unbounded compressed/encoded allocations.
    std::size_t encoded = 0;
    for (const auto &item : items) account(item.size(), encoded, events::Limits{}.plaintextBytes);
    transaction::Snapshot result; result.reserve(items.size());
    std::size_t total = 0;
    for (const auto &text : items) {
        const auto bytes = base64(text); Stream stream(bytes);
        const auto version = stream.u32();
        const bool v2 = version == 0xfffffffeU;
        const auto count = v2 ? stream.u32() : version;
        if (count > limits.formatsPerItem) fail(); // Includes -3/unknown versions.
        transaction::Item item;
        for (std::uint32_t i = 0; i < count; ++i) {
            auto name = stream.name(limits);
            if (v2) name = expanded(std::move(name));
            mimeName(name, limits);
            if (item.count(name)) fail();
            account(name.size(), total, limits.snapshotBytes);
            const auto flag = v2 ? stream.byte() : 1U;
            if (flag > 1) fail();
            // Legacy empty values are uncompressed. All nonempty legacy
            // values and v2 values flagged compressed have qCompress framing.
            if (!v2) {
                auto wire = stream.value(events::Limits{}.plaintextBytes, false);
                Bytes value;
                if (!wire.empty()) {
                    Stream compressed(wire);
                    const auto advertised = compressed.u32();
                    if (!advertised || advertised > limits.snapshotBytes - total || wire.size() < 5) fail();
                    Bytes zlib(wire.begin() + 4, wire.end());
                    try { value = crypto::zlibDecompressBounded(zlib, advertised); }
                    catch (const crypto::Error &) { fail(); }
                    if (value.size() != advertised) fail();
                }
                account(value.size(), total, limits.snapshotBytes); item.emplace(std::move(name), std::move(value));
            } else {
                auto value = stream.value(limits.snapshotBytes - total, flag != 0);
                account(value.size(), total, limits.snapshotBytes); item.emplace(std::move(name), std::move(value));
            }
        }
        if (!stream.end()) fail();
        result.push_back(std::move(item));
    }
    return result;
}
} // namespace cqs::packed
