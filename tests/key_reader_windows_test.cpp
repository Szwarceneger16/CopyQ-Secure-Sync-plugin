// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _WIN32
#error These tests require real Windows/NTFS, not a POSIX simulation
#endif
#include "key_reader.h"
#include "key_reader_hooks.h"
#include "test_check.h"
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <functional>
#include <iostream>
#include <numeric>

namespace cqs::native::testing { std::function<void(Point)> hook; }
namespace fs = std::filesystem;
using cqs::native::readKeyStrict;
using cqs::native::testing::Point;
namespace {
int passed = 0;
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) { CHECK(h && h != INVALID_HANDLE_VALUE); }
    ~Handle() { CloseHandle(value); }
    Handle(const Handle &) = delete;
};
struct SD {
    PSECURITY_DESCRIPTOR data = nullptr;
    SECURITY_ATTRIBUTES sa{};
    explicit SD(const std::wstring &extra = L"", bool protectedAcl = true, bool readOnly = false) {
        HANDLE raw = nullptr; CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw));
        Handle token(raw);
        DWORD size = 0; GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
        CHECK(size > 0); std::vector<unsigned char> buffer(size);
        CHECK(GetTokenInformation(token.value, TokenUser, buffer.data(), size, &size));
        LPWSTR user = nullptr;
        CHECK(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &user));
        const auto sddl = L"O:" + std::wstring(user) + (protectedAcl ? L"D:P" : L"D:") +
            (readOnly ? L"(A;;FR;;;" : L"(A;OICI;FA;;;") + user + L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + extra;
        LocalFree(user);
        CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &data, nullptr));
        sa = {sizeof(sa), data, FALSE};
    }
    ~SD() { if (data) LocalFree(data); }
    SD(const SD &) = delete;
};
void dacl(const fs::path &path, SD &sd, bool protectedAcl = true) {
    BOOL present = FALSE, defaulted = FALSE; PACL acl = nullptr;
    CHECK(GetSecurityDescriptorDacl(sd.data, &present, &acl, &defaulted));
    CHECK(present);
    CHECK(SetNamedSecurityInfoW(const_cast<wchar_t *>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | (protectedAcl ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION),
        nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS);
}
struct Temp {
    fs::path root, key;
    Temp() {
        wchar_t path[32768]{}; const auto n = GetTempPathW(32768, path); CHECK(n && n < 32768);
        std::wstring name = L"cqs-key-win-"; constexpr wchar_t hex[] = L"0123456789abcdef";
        for (auto c : cqs::crypto::random(16)) { name += hex[c >> 4]; name += hex[c & 15]; }
        root = fs::path(path) / name; key = root / L"ksync.key"; SD sd;
        CHECK(CreateDirectoryW(root.c_str(), &sd.sa));
    }
    ~Temp() { std::error_code ec; fs::remove_all(root, ec); }
    void put(std::size_t size = 32) {
        SD sd;
        Handle h(CreateFileW(key.c_str(), GENERIC_WRITE, 0, &sd.sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        std::vector<unsigned char> data(size); std::iota(data.begin(), data.end(), 0);
        DWORD count = 0;
        if (size) CHECK(WriteFile(h.value, data.data(), static_cast<DWORD>(size), &count, nullptr));
        CHECK(count == size);
    }
};
void reject(const std::function<void()> &body) {
    bool rejected = false;
    try { body(); } catch (const cqs::crypto::Error &e) {
        CHECK(std::string(e.what()) == "K-SYNC path, permissions, type, size or stability check failed");
        rejected = true;
    }
    CHECK(rejected);
}
void expectKey(const fs::path &path) {
    auto key = readKeyStrict(path); CHECK(key.size() == 32);
    for (unsigned i = 0; i < 32; ++i) CHECK(key[i] == i);
    cqs::crypto::wipe(key);
}
void test(const char *name, const std::function<void()> &body) {
    cqs::native::testing::hook = {};
    std::cout << "RUN " << name << std::endl;
    body(); ++passed;
    cqs::native::testing::hook = {};
    std::cout << "PASS " << name << std::endl;
}
void on(Point point, std::function<void()> body) {
    cqs::native::testing::hook = [point, body = std::move(body), done = false](Point p) mutable {
        if (!done && point == p) { done = true; body(); }
    };
}
void symlink(const fs::path &target, const fs::path &link, bool directory) {
    // Failure is a failed test, never a silently successful SKIP. Hosted CI
    // enables Developer Mode; local runs need it or the symlink privilege too.
    CHECK(CreateSymbolicLinkW(link.c_str(), target.c_str(), (directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0) | 0x2));
}
std::vector<unsigned char> security(const fs::path &path) {
    DWORD size = 0;
    const auto info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    GetFileSecurityW(path.c_str(), info, nullptr, 0, &size); CHECK(size > 0);
    std::vector<unsigned char> bytes(size); CHECK(GetFileSecurityW(path.c_str(), info, bytes.data(), size, &size));
    return bytes;
}
} // namespace
int main() {
    try {
        test("exact bytes and protected read-only key", [] {
            Temp t; t.put(); expectKey(t.key);
            SD readOnly(L"", true, true); dacl(t.key, readOnly); expectKey(t.key);
        });
        test("Unicode spaces and UTF-16 surrogate pairs", [] {
            Temp t; t.key = t.root / L"klucz \u017c\u00f3\u0142\u0107 \U0001f512.key"; t.put(); expectKey(t.key);
        });
        test("missing file or parent never created", [] {
            Temp t; reject([&] { readKeyStrict(t.key); }); CHECK(!fs::exists(t.key));
            reject([&] { readKeyStrict(t.root / L"missing" / L"key"); }); CHECK(!fs::exists(t.root / L"missing"));
        });
        test("unsupported Windows path forms", [] {
            for (const auto *p : {L"key", L"C:key", L"C:\\", L"\\\\server\\share\\key", L"\\\\?\\C:\\key",
                L"\\\\.\\pipe\\key", L"C:\\dir\\key:stream", L"C:\\dir\\..\\key", L"C:\\dir\\.\\key",
                L"C:\\dir\\NUL", L"C:\\dir\\key.", L"C:\\dir\\key ", L"C:\\dir\\key\\"})
                reject([&] { readKeyStrict(p); });
            reject([] { readKeyStrict(fs::path(std::wstring(L"C:\\key\0suffix", 13))); });
        });
        test("wrong sizes rejected without changes", [] {
            for (auto size : {0U, 1U, 31U, 33U, 4096U}) {
                Temp t; t.put(size); reject([&] { readKeyStrict(t.key); }); CHECK(fs::file_size(t.key) == size);
            }
        });
        test("directory cannot be a key", [] {
            Temp t; SD sd; CHECK(CreateDirectoryW(t.key.c_str(), &sd.sa)); reject([&] { readKeyStrict(t.key); });
        });
        test("hardlinked key is rejected", [] {
            Temp t; t.put(); CHECK(CreateHardLinkW((t.root / L"alias").c_str(), t.key.c_str(), nullptr));
            reject([&] { readKeyStrict(t.key); });
        });
        test("leaf and ancestor symlinks rejected", [] {
            Temp t, alias; t.put(); const auto leaf = alias.root / L"leaf", parent = alias.root / L"parent";
            symlink(t.key, leaf, false); symlink(t.root, parent, true);
            reject([&] { readKeyStrict(leaf); }); reject([&] { readKeyStrict(parent / t.key.filename()); });
        });
        test("key and parent public ACLs rejected unchanged", [] {
            for (bool parent : {false, true}) {
                Temp t; t.put(); const auto path = parent ? t.root : t.key;
                SD publicAcl(L"(A;;FR;;;WD)"); dacl(path, publicAcl); const auto before = security(path);
                reject([&] { readKeyStrict(t.key); }); CHECK(security(path) == before);
            }
        });
        test("unprotected and NULL DACLs rejected", [] {
            for (bool parent : {false, true}) {
                Temp t; t.put(); const auto path = parent ? t.root : t.key;
                SD inherited(L"", false); dacl(path, inherited, false);
                reject([&] { readKeyStrict(t.key); });
                CHECK(SetNamedSecurityInfoW(const_cast<wchar_t *>(path.c_str()), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS);
                reject([&] { readKeyStrict(t.key); });
            }
        });
        test("thread impersonation rejected and normal access restored", [] {
            Temp t; t.put(); CHECK(ImpersonateSelf(SecurityImpersonation));
            struct Revert { ~Revert() { RevertToSelf(); } } guard;
            reject([&] { readKeyStrict(t.key); }); CHECK(RevertToSelf()); expectKey(t.key);
        });
        test("existing writer prevents key read", [] {
            Temp t; t.put();
            { Handle h(CreateFileW(t.key.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, 0, nullptr));
              reject([&] { readKeyStrict(t.key); }); }
            expectKey(t.key);
        });
        test("pinned key denies new writes deletes and ancestor rename", [] {
            Temp t; t.put();
            on(Point::ReadPinned, [&] {
                for (auto access : {GENERIC_WRITE, DELETE}) {
                    const auto h = CreateFileW(t.key.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              nullptr, OPEN_EXISTING, 0, nullptr);
                    const auto error = GetLastError(); if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
                    CHECK(h == INVALID_HANDLE_VALUE && error == ERROR_SHARING_VIOLATION);
                }
                auto moved = t.root; moved += L"-moved";
                CHECK(!MoveFileExW(t.root.c_str(), moved.c_str(), 0));
                // Directory moves may report ACCESS_DENIED rather than
                // SHARING_VIOLATION. Assert the actual namespace guarantee.
                CHECK(fs::is_directory(t.root) && !fs::exists(moved));
            });
            expectKey(t.key);
        });
        test("ACL change after read invalidates the result", [] {
            for (bool parent : {false, true}) {
                Temp t; t.put();
                on(Point::ReadComplete, [&] { SD publicAcl(L"(A;;FR;;;WD)"); dacl(parent ? t.root : t.key, publicAcl); });
                reject([&] { readKeyStrict(t.key); });
            }
        });
        test("late injected failure releases the read handle", [] {
            Temp t; t.put(); on(Point::ReadComplete, [] { throw cqs::crypto::Error("Injected failure after read"); });
            bool rejected = false;
            try { readKeyStrict(t.key); } catch (const cqs::crypto::Error &) { rejected = true; }
            CHECK(rejected); cqs::native::testing::hook = {}; expectKey(t.key);
            CHECK(DeleteFileW(t.key.c_str()));
        });
        test("successful and rejected reads do not leak handles", [] {
            Temp t; t.put(); expectKey(t.key); DWORD before = 0, after = 0;
            CHECK(GetProcessHandleCount(GetCurrentProcess(), &before));
            for (int i = 0; i < 100; ++i) expectKey(t.key);
            CHECK(GetProcessHandleCount(GetCurrentProcess(), &after)); CHECK(before == after);
            SD publicAcl(L"(A;;FR;;;WD)"); dacl(t.key, publicAcl);
            CHECK(GetProcessHandleCount(GetCurrentProcess(), &before));
            for (int i = 0; i < 300; ++i) reject([&] { readKeyStrict(t.key); });
            CHECK(GetProcessHandleCount(GetCurrentProcess(), &after)); CHECK(before == after);
        });
        std::cout << passed << " Windows key-reader scenarios passed\n";
        return 0;
    } catch (const std::exception &e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
