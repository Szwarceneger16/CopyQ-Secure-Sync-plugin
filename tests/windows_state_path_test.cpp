// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_state_path.h"
#include <functional>
#include <iostream>
#include <stdexcept>
using cqs::state::windows_detail::localPath;
namespace {
int checks = 0;
void check(bool ok) { if (!ok) throw std::runtime_error("Windows path policy regression"); ++checks; }
void rejects(const std::wstring &path) {
    bool rejected = false;
    try { (void)localPath(path); } catch (const std::invalid_argument &) { rejected = true; }
    check(rejected);
}
}
int main() {
    auto p = localPath(L"C:\\Users\\test\\private-state");
    check(p.drive == L"C:\\");
    check(p.components == std::vector<std::wstring>({L"Users", L"test", L"private-state"}));
    check(localPath(L"c:/Users/test/private-state/").components == p.components);
    check(localPath(L"D:\\folder with space\\\u017c\u00f3\u0142\u0107").components.size() == 2);
    std::wstring emoji = L"C:\\"; emoji += wchar_t(0xd83d); emoji += wchar_t(0xde42);
    check(localPath(emoji).components.size() == 1);
    for (const auto &bad : {L"", L"state", L"C:state", L"C:\\", L"\\state", L"\\\\host\\share\\state",
         L"\\\\?\\C:\\state", L"\\\\.\\C:\\state", L"C:\\state\\..\\elsewhere", L"C:\\state\\.",
         L"C:\\a\\\\b", L"C:\\a\\\\", L"C:\\state ", L"C:\\state.", L"C:\\state:stream",
         L"C:\\state\n", L"C:\\state?", L"C:\\state*", L"C:\\a|b", L"C:\\<b", L"C:\\a>b", L"C:\\a\"b"}) rejects(bad);
    for (const auto &name : {L"con", L"CON.txt", L"con .txt", L"PRN", L"aux.foo", L"NUL", L"CONIN$", L"CONOUT$",
         L"COM0", L"COM1", L"com9.txt", L"LPT1", L"LPT9", L"COM\u00b9", L"LPT\u00b2", L"COM\u00b3"}) rejects(L"C:\\" + std::wstring(name));
    rejects(L"C:\\" + std::wstring(256, L'a'));
    check(localPath(L"C:\\" + std::wstring(255, L'a')).components.size() == 1);
    rejects(L"C:\\" + std::wstring(32001, L'a'));
    auto many = std::wstring(L"C:");
    for (int i = 0; i < 256; ++i) many += L"\\a";
    check(localPath(many).components.size() == 256); rejects(many + L"\\a");
    auto nul = std::wstring(L"C:\\safe"); nul += wchar_t(0); nul += L"evil"; rejects(nul);
    rejects(L"C:\\" + std::wstring(1, wchar_t(0xd800)));
    rejects(L"C:\\" + std::wstring(1, wchar_t(0xdc00)));
    rejects(L"C:\\" + std::wstring(1, wchar_t(0xd800)) + L"a");
    std::cout << checks << " Windows path policy checks passed (pure syntax, not Win32 I/O)\n";
}
