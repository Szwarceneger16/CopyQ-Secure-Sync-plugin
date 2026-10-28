// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _WIN32
#error This native blob reader requires the Windows kernel and local NTFS
#endif
#include "native_blob.h"
#include <filesystem>
#include <windows.h>
#include <sddl.h>
#include <QTemporaryDir>
#include "windows_state_path.h"
#include <aclapi.h>
#include <utility>
namespace cqs::native {
namespace {
constexpr DWORD inspectFlags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL;
constexpr DWORD shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
[[noreturn]] void fail() {
    // Match Linux: never expose path names, ACL trustees, OS errors or key bytes.
    throw crypto::Error("Native blob path, permissions, type, size or stability check failed");
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
    void check(HANDLE file,bool privateCipher=false) const {
        PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
        const auto status = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                            &owner, nullptr, &acl, nullptr, &sd);
        LocalMemory memory{sd};
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        auto userSid = const_cast<std::uint8_t *>(sid.data());
        if (status != ERROR_SUCCESS || !owner || !IsValidSid(owner) || (!EqualSid(owner,userSid)&&(privateCipher||(!IsWellKnownSid(owner,WinBuiltinAdministratorsSid)&&!IsWellKnownSid(owner,WinLocalSystemSid)))) ||
            !acl || !IsValidAcl(acl) || !GetSecurityDescriptorControl(sd, &control, &revision) ||
            (!(control & SE_DACL_PRESENT)||(privateCipher&&!(control & SE_DACL_PROTECTED)))) fail();
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
                !IsWellKnownSid(trustee, WinBuiltinAdministratorsSid) && !(header->AceFlags & INHERIT_ONLY_ACE) &&
                (ace->Mask & (FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL))) fail();
            if (user && !(header->AceFlags & INHERIT_ONLY_ACE) && ace->Mask) userGrant = true;
        }
        if (privateCipher&&!userGrant) fail();
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
        s.standard.DeletePending || (!directory && (s.standard.NumberOfLinks != 1 || s.standard.EndOfFile.QuadPart < 0))) fail();
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

QByteArray readNativeBlob(const QString &filename,std::size_t maximum) {
    const std::filesystem::path file(filename.toStdWString());
    state::windows_detail::LocalPath parts;
    const auto &text = file.native();
    // A trailing directory separator must not turn a file selection into a
    // different accepted path. UNC, devices, ADS and relative paths fail too.
    if (text.empty() || text.back() == L'\\' || text.back() == L'/') fail();
    try { parts = state::windows_detail::localPath(text); }
    catch (const std::invalid_argument &) { fail(); }
    if (parts.components.size() < 2) fail(); // A blob requires an explicit parent folder.
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

    if(std::uint64_t(chain.back().initial.standard.EndOfFile.QuadPart)>maximum)fail();
    Wiped output;output.bytes.resize(std::size_t(chain.back().initial.standard.EndOfFile.QuadPart)+1);
    std::size_t total = 0;
    while (total < output.bytes.size()) {
        DWORD count = 0;
        const auto remaining = static_cast<DWORD>(output.bytes.size() - total);
        if (!ReadFile(chain.back().handle.get(), output.bytes.data() + total, remaining, &count, nullptr) ||
            count > remaining) fail();
        if (!count) break;
        total += count;
    }

    if(total!=std::size_t(chain.back().initial.standard.EndOfFile.QuadPart))fail();
    verify(chain, user);
    return QByteArray(reinterpret_cast<const char *>(output.bytes.data()),qsizetype(total));
}
QByteArray withFrozenCiphertext(const QByteArray &bytes,const std::function<QByteArray(const QString &)> &convert) {
    const char *phase="identity";
    try {
    Identity user;LPWSTR sid=nullptr;if(!ConvertSidToStringSidW(user.sid.data(),&sid))fail();LocalMemory sidMemory{sid};
    const auto rule=std::wstring(L"O:")+sid+L"D:P(A;OICI;FA;;;"+sid+L")";
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(rule.c_str(),SDDL_REVISION_1,&descriptor,nullptr))fail();LocalMemory descriptorMemory{descriptor};
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
    phase="temporary directory";
    QTemporaryDir directory;if(!directory.isValid())fail();
    state::windows_detail::LocalPath parts;
    try{parts=state::windows_detail::localPath(directory.path().toStdWString());}catch(...){fail();}
    if(GetDriveTypeW(parts.drive.c_str())!=DRIVE_FIXED)fail();
    wchar_t volume[64]{};if(!GetVolumeNameForVolumeMountPointW(parts.drive.c_str(),volume,64))fail();
    phase="pinned directory chain";
    std::wstring current(volume);std::vector<Pinned> directories;
    directories.push_back(open(current,true,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE));
    wchar_t filesystem[32]{};DWORD flags=0;
    if(!GetVolumeInformationByHandleW(directories.front().handle.get(),nullptr,0,nullptr,nullptr,&flags,filesystem,32)||std::wstring(filesystem)!=L"NTFS"||!(flags&FILE_PERSISTENT_ACLS))fail();
    for(std::size_t i=0;i<parts.components.size();++i){
        if(current.back()!=L'\\')current+=L'\\';current+=parts.components[i];
        const bool last=i+1==parts.components.size();
        directories.push_back(open(current,true,FILE_READ_ATTRIBUTES|READ_CONTROL|(last?(WRITE_DAC|WRITE_OWNER):0),FILE_SHARE_READ|FILE_SHARE_WRITE));
        if(directories.back().initial.id.dwVolumeSerialNumber!=directories.front().initial.id.dwVolumeSerialNumber)fail();
    }
    phase="private directory ACL";
    BOOL present=FALSE,defaulted=FALSE;PACL privateAcl=nullptr;
    if(!GetSecurityDescriptorDacl(descriptor,&present,&privateAcl,&defaulted)||!present||!privateAcl)fail();
    // QTemporaryDir inherits Windows defaults; elevated tokens can create an
    // Administrators-owned directory. Provision the new cipher directory with
    // the exact user owner and protected DACL before creating any contents.
    if(SetSecurityInfo(directories.back().handle.get(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,user.sid.data(),nullptr,privateAcl,nullptr)!=ERROR_SUCCESS)fail();
    user.check(directories.back().handle.get(),true);
    // Pin every ancestor without delete sharing and use the volume GUID for
    // both creation and conversion: neither a rename nor DOS drive remapping
    // can redirect the host's path-based readAll() to a different file.
    const auto name=QString::fromStdWString(current+L"\\ciphertext");
    // Qt 6.10 longFileName() preserves the Win32 device namespace, while
    // rewriting an extended Volume GUID path as an invalid UNC path. Both
    // names address the same pinned volume; neither uses a DOS drive mapping.
    auto qtName=name;qtName[2]=QChar('.');
    struct Cleanup {QString name;~Cleanup(){DeleteFileW(reinterpret_cast<LPCWSTR>(name.utf16()));}} cleanup{name};
    // A protected user-only ACL and a live handle without write/delete sharing
    // make the ciphertext immutable while the host converter opens it for read.
    phase="private file creation";
    Handle file(CreateFileW(reinterpret_cast<LPCWSTR>(name.utf16()),GENERIC_READ|GENERIC_WRITE|READ_CONTROL,FILE_SHARE_READ,&attributes,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY,nullptr));
    phase="private file ACL";
    user.check(file.get(),true);DWORD done=0;
    phase="ciphertext write";
    if(!WriteFile(file.get(),bytes.constData(),DWORD(bytes.size()),&done,nullptr)||done!=DWORD(bytes.size())||!FlushFileBuffers(file.get()))fail();
    phase="conversion";
    return convert(qtName);
    } catch(const crypto::Error &) {
        const auto message=std::string("Frozen native ciphertext verification failed: ")+phase;
        throw crypto::Error(message.c_str());
    }
}
} // namespace cqs::native
