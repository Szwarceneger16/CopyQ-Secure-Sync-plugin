// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace cqs::state::windows_detail {
struct LocalPath { std::wstring drive; std::vector<std::wstring> components; };
// Pure syntax validation, NOT authorization or reparse-point validation. The
// Windows backend pins every component and validates its handle separately.
inline LocalPath localPath(std::wstring text) {
    const auto invalid = [] { throw std::invalid_argument("Invalid local Windows state path"); };
    std::replace(text.begin(), text.end(), L'/', L'\\');
    if (text.size() < 4 || text.size() > 32000 ||
        !((text[0] >= L'A' && text[0] <= L'Z') || (text[0] >= L'a' && text[0] <= L'z')) ||
        text[1] != L':' || text[2] != L'\\') invalid();
    LocalPath out{text.substr(0, 3), {}};
    if (text.back() == L'\\') {
        text.pop_back();
        if (text.size() <= 3 || text.back() == L'\\') invalid();
    }
    for (std::size_t pos = 3; pos < text.size();) {
        auto end = text.find(L'\\', pos);
        if (end == std::wstring::npos) end = text.size();
        auto part = text.substr(pos, end - pos);
        if (part.empty() || part.size() > 255 || part == L"." || part == L".." ||
            part.back() == L'.' || part.back() == L' ' || out.components.size() == 256) invalid();
        for (std::size_t i = 0; i < part.size(); ++i) {
            const auto c = static_cast<unsigned>(part[i]);
            if (c < 32 || c == 127 || c > 0xffff || std::wstring(L"<>:\"|?*").find(part[i]) != std::wstring::npos)
                invalid();
            if (c >= 0xd800 && c <= 0xdbff) {
                if (++i == part.size() || part[i] < 0xdc00 || part[i] > 0xdfff) invalid();
            } else if (c >= 0xdc00 && c <= 0xdfff) invalid();
        }
        auto stem = part.substr(0, part.find(L'.'));
        while (!stem.empty() && stem.back() == L' ') stem.pop_back();
        for (auto &c : stem) if (c >= L'a' && c <= L'z') c -= L'a' - L'A';
        if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
            stem == L"CONIN$" || stem == L"CONOUT$") invalid();
        if (stem.size() == 4 && (stem.substr(0, 3) == L"COM" || stem.substr(0, 3) == L"LPT") &&
            ((stem[3] >= L'0' && stem[3] <= L'9') || stem[3] == 0x00b9 || stem[3] == 0x00b2 || stem[3] == 0x00b3)) invalid();
        out.components.push_back(std::move(part));
        pos = end + 1;
    }
    if (out.components.empty()) invalid();
    return out;
}
} // namespace cqs::state::windows_detail
