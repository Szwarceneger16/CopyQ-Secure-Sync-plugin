// SPDX-License-Identifier: GPL-3.0-or-later
#include "crypto.h"
#include <zlib.h>
#include <climits>
namespace cqs::crypto {
Bytes zlibCompress(const Bytes &input) {
    if (input.size() > static_cast<std::size_t>(UINT_MAX)) throw Error("Compress input exceeds bounds");
    uLongf max = compressBound(static_cast<uLong>(input.size()));
    Bytes out(max);
    if (compress2(out.data(), &max, input.data(), static_cast<uLong>(input.size()), 6) != Z_OK)
        throw Error("Compression failed");
    out.resize(max);
    return out;
}
Bytes zlibDecompressBounded(const Bytes &input, const std::size_t limit) {
    if (input.size() > static_cast<std::size_t>(UINT_MAX) || limit > static_cast<std::size_t>(UINT_MAX))
        throw Error("Decompression size exceeds bounds");
    z_stream strm{};
    if (inflateInit(&strm) != Z_OK) throw Error("Cannot initialize decompression");
    struct Finish { z_stream *s; ~Finish() { inflateEnd(s); } } finish{&strm};
    strm.next_in = const_cast<Bytef*>(input.data());
    strm.avail_in = static_cast<uInt>(input.size());
    Bytes out;
    std::uint8_t buffer[16384];
    for (;;) {
        strm.next_out = buffer;
        strm.avail_out = static_cast<uInt>(sizeof(buffer));
        const int ret = inflate(&strm, Z_NO_FLUSH);
        const std::size_t written = sizeof(buffer) - strm.avail_out;
        if (written > limit - out.size()) throw Error("Decompressed payload exceeds limit");
        out.insert(out.end(), buffer, buffer + written);
        if (ret == Z_STREAM_END) {
            if (strm.avail_in != 0) throw Error("Trailing compressed payload data");
            return out;
        }
        if (ret != Z_OK || (strm.avail_in == 0 && written == 0))
            throw Error("Corrupt or truncated compressed payload");
    }
}
}
