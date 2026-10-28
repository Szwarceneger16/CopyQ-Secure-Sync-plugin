// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#ifndef _WIN32
#error Windows-only fixture helper; not a production ACL provisioning API
#endif
#include "test_check.h"
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <filesystem>
#include <string>
#include <vector>

namespace cqs::testing {
class WindowsAcl final {
public:
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    SECURITY_ATTRIBUTES attributes{};
    explicit WindowsAcl(const std::wstring &extra = L"", bool protect = true) {
        HANDLE token = nullptr; CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));
        DWORD size = 0; GetTokenInformation(token,TokenUser,nullptr,0,&size); CHECK(size > 0);
        std::vector<unsigned char> bytes(size);
        const auto ok = GetTokenInformation(token,TokenUser,bytes.data(),size,&size); CloseHandle(token); CHECK(ok);
        LPWSTR user = nullptr; CHECK(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(bytes.data())->User.Sid,&user));
        const auto text = L"O:"+std::wstring(user)+(protect ? L"D:P" : L"D:")+L"(A;OICI;FA;;;"+user+L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"+extra;
        LocalFree(user);
        CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(),SDDL_REVISION_1,&descriptor,nullptr));
        attributes = {sizeof(attributes),descriptor,FALSE};
    }
    ~WindowsAcl() { if (descriptor) LocalFree(descriptor); }
    WindowsAcl(const WindowsAcl &) = delete;
    void apply(const std::filesystem::path &path, bool protect = true) const {
        BOOL present = FALSE, defaulted = FALSE; PACL acl = nullptr;
        CHECK(GetSecurityDescriptorDacl(descriptor,&present,&acl,&defaulted) && present);
        CHECK(SetNamedSecurityInfoW(const_cast<wchar_t *>(path.c_str()),SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | (protect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION),
            nullptr,nullptr,acl,nullptr) == ERROR_SUCCESS);
    }
};
inline void directory(const std::filesystem::path &path) {
    WindowsAcl acl; CHECK(CreateDirectoryW(path.c_str(),&acl.attributes));
}
inline void write(const std::filesystem::path &path, const std::string &bytes) {
    WindowsAcl acl;
    const auto file = CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&acl.attributes,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    CHECK(file != INVALID_HANDLE_VALUE); DWORD count = 0;
    const auto ok = bytes.empty() || WriteFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr);
    CloseHandle(file); CHECK(ok && count == bytes.size());
}
} // namespace cqs::testing
