// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _WIN32
#error This key reader requires the Windows kernel and local NTFS
#endif
#include "key_reader.h"
#include "windows_state_path.h"
#include <windows.h>
#include <aclapi.h>
#include <utility>
#ifdef CQS_KEY_READER_TESTING
#include "../tests/key_reader_hooks.h"
#define KEY_HOOK(p) do { if (testing::hook) testing::hook(testing::Point::p); } while (false)
#else
#define KEY_HOOK(p) do {} while (false)
#endif

namespace cqs::native {
namespace {
constexpr DWORD inspectFlags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL;
constexpr DWORD shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
[[noreturn]] void fail() {
    // Match Linux: never expose path names, ACL trustees, OS errors or key bytes.
    throw crypto::Error("K-SYNC path, permissions, type, size or stability check failed");
}
class Handle final {
public:
    explicit Handle(HANDLE h) : handle_(h) { if (!h || h == INVALID_HANDLE_VALUE) fail(); }
    ~Handle() { if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    Handle(Handle &&other) noexcept : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    HANDLE get() const { return handle_; }
private:
    HANDLE handle_;
};
struct LocalMemory { void *data = nullptr; ~LocalMemory() { if (data) LocalFree(data); } };
struct Wiped { crypto::Bytes bytes; ~Wiped() { crypto::wipe(bytes); } };
void noImpersonation() {
    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        CloseHandle(token); fail();
    }
    if (GetLastError() != ERROR_NO_TOKEN) fail();
}
struct Identity {
    crypto::Bytes sid;
    Identity() {
        noImpersonation();
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) fail();
        Handle token(raw);
        DWORD size = 0;
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size || size > 65536) fail();
        crypto::Bytes buffer(size);
        if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), size, &size)) fail();
        const auto user = reinterpret_cast<const TOKEN_USER *>(buffer.data())->User.Sid;
        if (!IsValidSid(user)) fail();
        sid.resize(GetLengthSid(user));
        if (!CopySid(static_cast<DWORD>(sid.size()), sid.data(), user)) fail();
    }
    void check(HANDLE file) const {
        PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
        const auto status = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                            &owner, nullptr, &acl, nullptr, &sd);
        LocalMemory memory{sd};
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        auto userSid = const_cast<std::uint8_t *>(sid.data());
        if (status != ERROR_SUCCESS || !owner || !IsValidSid(owner) || !EqualSid(owner, userSid) ||
            !acl || !IsValidAcl(acl) || !GetSecurityDescriptorControl(sd, &control, &revision) ||
            !(control & SE_DACL_PRESENT) || !(control & SE_DACL_PROTECTED)) fail();
        bool userGrant = false;
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void *raw = nullptr;
            if (!GetAce(acl, i, &raw)) fail();
            const auto header = static_cast<const ACE_HEADER *>(raw);
            // Fail closed on object/callback/conditional rules instead of
            // approximating the Windows authorization algorithm.
            if ((header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) ||
                header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8) fail();
            const auto ace = static_cast<const ACCESS_ALLOWED_ACE *>(raw);
            auto trustee = reinterpret_cast<PSID>(const_cast<DWORD *>(&ace->SidStart));
            const auto sidHeader = static_cast<const SID *>(trustee);
            if (GetSidLengthRequired(sidHeader->SubAuthorityCount) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) ||
                !IsValidSid(trustee)) fail();
            if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
            const bool user = EqualSid(trustee, userSid) != FALSE;
            if (!user && !IsWellKnownSid(trustee, WinLocalSystemSid) &&
                !IsWellKnownSid(trustee, WinBuiltinAdministratorsSid)) fail();
            if (user && !(header->AceFlags & INHERIT_ONLY_ACE) && ace->Mask) userGrant = true;
        }
        if (!userGrant) fail();
    }
};
struct Stamp { BY_HANDLE_FILE_INFORMATION id{}; FILE_BASIC_INFO basic{}; FILE_STANDARD_INFO standard{}; };
Stamp stamp(HANDLE file, bool directory) {
    Stamp s;
    if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &s.id) ||
        !GetFileInformationByHandleEx(file, FileBasicInfo, &s.basic, sizeof(s.basic)) ||
        !GetFileInformationByHandleEx(file, FileStandardInfo, &s.standard, sizeof(s.standard))) fail();
    // The literal recall flags are available on supported Windows 10+ NTFS,
    // including SDKs which omit their symbolic definitions.
    constexpr DWORD unsafe = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_DEVICE |
                             0x00040000u | 0x00400000u; // RECALL_ON_OPEN / RECALL_ON_DATA_ACCESS
    if ((s.basic.FileAttributes & unsafe) || !!(s.basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory ||
        s.standard.DeletePending || (!directory && (s.standard.NumberOfLinks != 1 || s.standard.EndOfFile.QuadPart != 32))) fail();
    return s;
}
bool identity(const Stamp &a, const Stamp &b) {
    return a.id.dwVolumeSerialNumber == b.id.dwVolumeSerialNumber &&
        a.id.nFileIndexHigh == b.id.nFileIndexHigh && a.id.nFileIndexLow == b.id.nFileIndexLow &&
        a.basic.CreationTime.QuadPart == b.basic.CreationTime.QuadPart &&
        a.basic.FileAttributes == b.basic.FileAttributes;
}
bool same(const Stamp &a, const Stamp &b) {
    return identity(a, b) && a.basic.LastWriteTime.QuadPart == b.basic.LastWriteTime.QuadPart &&
        a.basic.ChangeTime.QuadPart == b.basic.ChangeTime.QuadPart &&
        a.standard.EndOfFile.QuadPart == b.standard.EndOfFile.QuadPart &&
        a.standard.NumberOfLinks == b.standard.NumberOfLinks;
}
struct Pinned { Handle handle; std::wstring path; Stamp initial; bool directory; };
Pinned open(const std::wstring &path, bool directory, DWORD access, DWORD sharing) {
    Handle h(CreateFileW(path.c_str(), access, sharing, nullptr, OPEN_EXISTING, inspectFlags, nullptr));
    const auto s = stamp(h.get(), directory);
    return {std::move(h), path, s, directory};
}
void verify(const std::vector<Pinned> &chain, const Identity &user) {
    noImpersonation();
    for (const auto &p : chain) {
        const auto named = open(p.path, p.directory, FILE_READ_ATTRIBUTES, shareAll);
        const auto current = stamp(p.handle.get(), p.directory);
        if (!identity(p.initial, named.initial) || !identity(p.initial, current) ||
            (!p.directory && (!same(p.initial, named.initial) || !same(p.initial, current)))) fail();
    }
    user.check(chain[chain.size() - 2].handle.get());
    user.check(chain.back().handle.get());
}
} // namespace

crypto::Bytes readKeyStrict(const std::filesystem::path &file) {
    state::windows_detail::LocalPath parts;
    const auto &text = file.native();
    // A trailing directory separator must not turn a file selection into a
    // different accepted path. UNC, devices, ADS and relative paths fail too.
    if (text.empty() || text.back() == L'\\' || text.back() == L'/') fail();
    try { parts = state::windows_detail::localPath(text); }
    catch (const std::invalid_argument &) { fail(); }
    if (parts.components.size() < 2) fail(); // A key requires an explicit private parent folder.
    Identity user;
    if (GetDriveTypeW(parts.drive.c_str()) != DRIVE_FIXED) fail();
    wchar_t volume[64]{};
    if (!GetVolumeNameForVolumeMountPointW(parts.drive.c_str(), volume, 64)) fail();
    // Open by volume GUID, so mutable DOS drive mappings cannot retarget reads.
    std::wstring current(volume);
    std::vector<Pinned> chain;
    chain.push_back(open(current, true, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE));
    wchar_t filesystem[32]{}; DWORD flags = 0;
    if (!GetVolumeInformationByHandleW(chain.front().handle.get(), nullptr, 0, nullptr, nullptr,
                                      &flags, filesystem, 32) || std::wstring(filesystem) != L"NTFS" ||
        !(flags & FILE_PERSISTENT_ACLS)) fail();
    for (std::size_t i = 0; i < parts.components.size(); ++i) {
        const bool last = i + 1 == parts.components.size();
        if (current.back() != L'\\') current += L'\\';
        current += parts.components[i];
        chain.push_back(open(current, !last,
            last ? GENERIC_READ | READ_CONTROL : FILE_READ_ATTRIBUTES | (i + 2 == parts.components.size() ? READ_CONTROL : 0),
            last ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE));
        if (chain.back().initial.id.dwVolumeSerialNumber != chain.front().initial.id.dwVolumeSerialNumber) fail();
    }
    // All ancestors stay pinned without delete sharing. The leaf denies both
    // writes and deletes, including already-open incompatible writer handles.
    verify(chain, user);
    KEY_HOOK(ReadPinned);
    Wiped output; output.bytes.resize(33);
    std::size_t total = 0;
    while (total < output.bytes.size()) {
        DWORD count = 0;
        const auto remaining = static_cast<DWORD>(output.bytes.size() - total);
        if (!ReadFile(chain.back().handle.get(), output.bytes.data() + total, remaining, &count, nullptr) ||
            count > remaining) fail();
        if (!count) break;
        total += count;
    }
    KEY_HOOK(ReadComplete);
    if (total != 32) fail();
    verify(chain, user);
    output.bytes.resize(32);
    return std::move(output.bytes);
}
} // namespace cqs::native
