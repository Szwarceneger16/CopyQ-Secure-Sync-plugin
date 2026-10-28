// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _WIN32
#error This transport backend requires Windows and local NTFS
#endif
#include "storage.h"
#include "windows_state_path.h"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <set>
#include <utility>
#ifdef CQS_STORAGE_TESTING
#include "../tests/storage_hooks.h"
#define CQS_HOOK(p) do { if (testing::hook) testing::hook(testing::Point::p); } while (false)
#else
#define CQS_HOOK(p) do {} while (false)
#endif

namespace cqs::storage {
namespace {
constexpr DWORD shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
constexpr DWORD flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL;
constexpr DWORD inspect = FILE_READ_ATTRIBUTES | READ_CONTROL;
[[noreturn]] void fail(ErrorCode code, const char *text) { throw Error(code, text); }
[[noreturn]] void io(DWORD error = GetLastError()) {
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND || error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION)
        fail(ErrorCode::Unavailable, "Transport entry unavailable; retry a complete operation");
    if (error == ERROR_CANT_ACCESS_FILE || error == ERROR_DIRECTORY)
        fail(ErrorCode::UnsafeEntry, "Unsafe transport path component");
    fail(ErrorCode::Io, "Windows transport I/O failed");
}
class Handle final {
public:
    explicit Handle(HANDLE h) : h_(h) { if (!h || h == INVALID_HANDLE_VALUE) io(); }
    ~Handle() { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    Handle(Handle &&other) noexcept : h_(std::exchange(other.h_, INVALID_HANDLE_VALUE)) {}
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    HANDLE get() const { return h_; }
private:
    HANDLE h_;
};
struct LocalMemory { void *p = nullptr; ~LocalMemory() { if (p) LocalFree(p); } };
void noImpersonation() {
    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        CloseHandle(token); fail(ErrorCode::UnsafeEntry, "Transport must not run under impersonation");
    }
    if (GetLastError() != ERROR_NO_TOKEN) io();
}
struct Security {
    crypto::Bytes sid;
    LocalMemory descriptor;
    SECURITY_ATTRIBUTES attributes{};
    Security() {
        noImpersonation(); HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) io();
        Handle token(raw); DWORD size = 0;
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size || size > 65536) io();
        crypto::Bytes data(size);
        if (!GetTokenInformation(token.get(), TokenUser, data.data(), size, &size)) io();
        const auto user = reinterpret_cast<const TOKEN_USER *>(data.data())->User.Sid;
        if (!IsValidSid(user)) fail(ErrorCode::UnsafeEntry, "Invalid transport process identity");
        sid.resize(GetLengthSid(user));
        if (!CopySid(static_cast<DWORD>(sid.size()), sid.data(), user)) io();
        LPWSTR text = nullptr;
        if (!ConvertSidToStringSidW(sid.data(), &text)) io();
        LocalMemory sidText{text};
        const std::wstring sddl = L"O:" + std::wstring(text) + L"D:P(A;OICI;FA;;;" + text + L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) io();
        descriptor.p = sd; attributes = {sizeof(SECURITY_ATTRIBUTES), sd, FALSE};
    }
    void check(HANDLE file, bool privateOnly = false) const {
        PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
        const auto result = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                            &owner, nullptr, &acl, nullptr, &sd);
        LocalMemory memory{sd}; SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        auto userSid = const_cast<std::uint8_t *>(sid.data());
        if (result != ERROR_SUCCESS) io(result);
        if (!owner || !IsValidSid(owner) || !EqualSid(owner, userSid) || !acl || !IsValidAcl(acl) ||
            !GetSecurityDescriptorControl(sd, &control, &revision) || !(control & SE_DACL_PRESENT) ||
            (privateOnly && !(control & SE_DACL_PROTECTED)))
            fail(ErrorCode::UnsafeEntry, "Transport needs a user-owned bounded access policy");
        constexpr DWORD writes = GENERIC_ALL | GENERIC_WRITE | MAXIMUM_ALLOWED | WRITE_DAC | WRITE_OWNER | DELETE |
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD;
        bool userGrant = false;
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void *raw = nullptr; if (!GetAce(acl, i, &raw)) io();
            const auto header = static_cast<const ACE_HEADER *>(raw);
            if ((header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) ||
                header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8)
                fail(ErrorCode::UnsafeEntry, "Unsupported transport access rule");
            const auto ace = static_cast<const ACCESS_ALLOWED_ACE *>(raw);
            auto trustee = reinterpret_cast<PSID>(const_cast<DWORD *>(&ace->SidStart));
            const auto sidHeader = static_cast<const SID *>(trustee);
            if (GetSidLengthRequired(sidHeader->SubAuthorityCount) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) || !IsValidSid(trustee))
                fail(ErrorCode::UnsafeEntry, "Invalid transport access trustee");
            if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
            const bool user = EqualSid(trustee, userSid) != FALSE;
            const bool trusted = user || IsWellKnownSid(trustee, WinLocalSystemSid) || IsWellKnownSid(trustee, WinBuiltinAdministratorsSid);
            // Ciphertext transport may be readable by others, matching Linux.
            // Inherited rules are checked too; no broad-write ACL repair occurs.
            if (!trusted && (privateOnly || (ace->Mask & writes)))
                fail(ErrorCode::UnsafeEntry, "Transport grants unsafe access to another principal");
            if (user && !(header->AceFlags & INHERIT_ONLY_ACE) && ace->Mask) userGrant = true;
        }
        if (privateOnly && !userGrant) fail(ErrorCode::UnsafeEntry, "Private staging lacks a user grant");
    }
};
struct Stamp { BY_HANDLE_FILE_INFORMATION id{}; FILE_BASIC_INFO basic{}; FILE_STANDARD_INFO standard{}; };
Stamp stamp(HANDLE file, bool directory) {
    Stamp out;
    if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &out.id) ||
        !GetFileInformationByHandleEx(file, FileBasicInfo, &out.basic, sizeof(out.basic)) ||
        !GetFileInformationByHandleEx(file, FileStandardInfo, &out.standard, sizeof(out.standard))) io();
    constexpr DWORD unsafe = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_DEVICE | 0x00040000u | 0x00400000u;
    if ((out.basic.FileAttributes & unsafe) || !!(out.basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory ||
        out.standard.DeletePending || out.standard.EndOfFile.QuadPart < 0 || (!directory && out.standard.NumberOfLinks != 1))
        fail(ErrorCode::UnsafeEntry, "Transport rejects reparse, offline, special and hardlinked entries");
    return out;
}
bool identity(const Stamp &a, const Stamp &b) {
    return a.id.dwVolumeSerialNumber == b.id.dwVolumeSerialNumber && a.id.nFileIndexHigh == b.id.nFileIndexHigh &&
        a.id.nFileIndexLow == b.id.nFileIndexLow && a.basic.CreationTime.QuadPart == b.basic.CreationTime.QuadPart &&
        a.basic.FileAttributes == b.basic.FileAttributes;
}
bool same(const Stamp &a, const Stamp &b) {
    return identity(a,b) && a.basic.LastWriteTime.QuadPart == b.basic.LastWriteTime.QuadPart &&
        a.basic.ChangeTime.QuadPart == b.basic.ChangeTime.QuadPart && a.standard.EndOfFile.QuadPart == b.standard.EndOfFile.QuadPart &&
        a.standard.NumberOfLinks == b.standard.NumberOfLinks;
}
struct Pinned { Handle handle; std::wstring path; Stamp initial; bool directory; };
Pinned open(const std::wstring &path, bool directory, DWORD access = inspect, DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE) {
    Handle h(CreateFileW(path.c_str(), access, sharing, nullptr, OPEN_EXISTING, flags, nullptr));
    const auto initial = stamp(h.get(), directory); return {std::move(h), path, initial, directory};
}
void mapped(const Pinned &p, bool content = false) {
    const auto named = open(p.path, p.directory, FILE_READ_ATTRIBUTES, shareAll);
    const auto current = stamp(p.handle.get(), p.directory);
    if (!identity(p.initial, named.initial) || !identity(p.initial, current) ||
        (content && (!same(p.initial, named.initial) || !same(p.initial, current))))
        fail(ErrorCode::Changed, "Transport mapping or content changed");
}
std::wstring child(const Pinned &parent, const std::wstring &name) { return parent.path + (parent.path.back() == L'\\' ? L"" : L"\\") + name; }
struct Root {
    std::vector<Pinned> chain;
    std::wstring volume;
    Root(const std::filesystem::path &path, const Security &security, bool privateOnly,DWORD extraAccess=0) {
        state::windows_detail::LocalPath parts;
        try { parts = state::windows_detail::localPath(path.native()); }
        catch (const std::invalid_argument &) { fail(ErrorCode::InvalidPath, "Explicit local transport drive path required"); }
        if (GetDriveTypeW(parts.drive.c_str()) != DRIVE_FIXED)
            fail(ErrorCode::UnsupportedFilesystem, "Transport requires a fixed local NTFS volume");
        wchar_t guid[64]{};
        if (!GetVolumeNameForVolumeMountPointW(parts.drive.c_str(), guid, 64))
            fail(ErrorCode::UnsupportedFilesystem, "Substituted or unmapped transport drives are unsupported");
        volume = guid; std::wstring current = volume;
        chain.push_back(open(current, true, FILE_READ_ATTRIBUTES));
        wchar_t filesystem[32]{}; DWORD capabilities = 0;
        if (!GetVolumeInformationByHandleW(chain.front().handle.get(), nullptr, 0, nullptr, nullptr, &capabilities, filesystem, 32)) io();
        if (std::wstring(filesystem) != L"NTFS" || !(capabilities & FILE_PERSISTENT_ACLS))
            fail(ErrorCode::UnsupportedFilesystem, "Only local NTFS transport is supported");
        for (std::size_t i = 0; i < parts.components.size(); ++i) {
            if (current.back() != L'\\') current += L'\\';
            current += parts.components[i];
            const bool last = i + 1 == parts.components.size();
            chain.push_back(open(current, true, last ? inspect | FILE_LIST_DIRECTORY | extraAccess : FILE_READ_ATTRIBUTES));
            if (chain.back().initial.id.dwVolumeSerialNumber != chain.front().initial.id.dwVolumeSerialNumber)
                fail(ErrorCode::UnsafeEntry, "Nested transport volumes are unsupported");
        }
        verify(security, privateOnly);
    }
    const Pinned &folder() const { return chain.back(); }
    void verify(const Security &security, bool privateOnly = false) const {
        noImpersonation(); for (const auto &p : chain) mapped(p); security.check(folder().handle.get(), privateOnly);
    }
};
std::vector<std::wstring> names(const Pinned &dir, std::size_t &remaining) {
    auto listing = open(dir.path, true, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES);
    if (!identity(listing.initial, dir.initial)) fail(ErrorCode::Changed, "Transport listing directory changed");
    // Independent handle cursor per scan, never FindFirstFile on an unpinned path.
    std::array<std::uint64_t, 8192> buffer{};
    std::set<std::wstring> sorted; bool restart = true;
    for (;;) {
        std::fill(buffer.begin(), buffer.end(), 0);
        if (!GetFileInformationByHandleEx(listing.handle.get(), restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo,
                                         buffer.data(), static_cast<DWORD>(sizeof(buffer)))) {
            if (GetLastError() == ERROR_NO_MORE_FILES) break;
            io();
        }
        restart = false; std::size_t offset = 0;
        for (;;) {
            constexpr auto header = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
            const auto *entry = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO *>(reinterpret_cast<const unsigned char *>(buffer.data()) + offset);
            const auto size = entry->FileNameLength;
            if (!size || size % sizeof(wchar_t) || size > 510 || header + size > sizeof(buffer) - offset)
                fail(ErrorCode::UnsafeEntry, "Invalid transport directory entry");
            const std::wstring name(entry->FileName, size / sizeof(wchar_t));
            if (name != L"." && name != L"..") {
                if (!remaining) fail(ErrorCode::ScanLimit, "Transport directory entry budget exceeded");
                --remaining;
                if (!sorted.insert(name).second) fail(ErrorCode::Changed, "Transport changed while listing");
            }
            if (!entry->NextEntryOffset) break;
            if (entry->NextEntryOffset < header + size || entry->NextEntryOffset % alignof(FILE_ID_BOTH_DIR_INFO) ||
                entry->NextEntryOffset > sizeof(buffer) - offset - header)
                fail(ErrorCode::UnsafeEntry, "Invalid transport listing offset");
            offset += entry->NextEntryOffset;
        }
    }
    mapped(listing); return {sorted.begin(), sorted.end()};
}
std::string ascii(const std::wstring &name) {
    std::string out; out.reserve(name.size());
    for (const auto c : name) { if (c < 0x21 || c > 0x7e) fail(ErrorCode::UnsafeEntry, "Noncanonical transport name"); out += static_cast<char>(c); }
    return out;
}
std::string eventId(const std::string &device, const std::wstring &wide) {
    const auto name = ascii(wide);
    if (name.size() != 16 || name.compare(12,4,".cqs") != 0) fail(ErrorCode::UnsafeEntry, "Unexpected event or conflict copy; not skipped");
    std::uint64_t sequence = 0;
    for (std::size_t i = 0; i < 12; ++i) {
        if (name[i] < '0' || name[i] > '9') fail(ErrorCode::UnsafeEntry, "Noncanonical transport sequence");
        sequence = sequence * 10 + static_cast<unsigned>(name[i] - '0');
    }
    try { return history::makeId(device, sequence); }
    catch (const history::Error &) { fail(ErrorCode::UnsafeEntry, "Invalid transport event identity"); }
}
void sameVolume(const Pinned &file, const Pinned &root) {
    if (file.initial.id.dwVolumeSerialNumber != root.initial.id.dwVolumeSerialNumber)
        fail(ErrorCode::UnsafeEntry, "Nested transport volume not supported");
}
std::string read(const Pinned &file) {
    mapped(file,true); const auto size = static_cast<std::size_t>(file.initial.standard.EndOfFile.QuadPart);
    std::string out(size,'\0'); std::size_t offset = 0;
    while (offset < size) {
        DWORD count = 0; const auto wanted = static_cast<DWORD>(std::min<std::size_t>(16384,size-offset));
        if (!ReadFile(file.handle.get(), out.data()+offset, wanted, &count, nullptr)) io();
        if (!count || count > wanted) fail(ErrorCode::Changed, "Transport read incomplete");
        offset += count; CQS_HOOK(ReadChunk);
    }
    char extra = 0; DWORD count = 0;
    if (!ReadFile(file.handle.get(), &extra,1,&count,nullptr)) io();
    if (count) fail(ErrorCode::Changed, "Transport event grew during read");
    mapped(file,true); return out;
}
void flush(HANDLE file) { if (!FlushFileBuffers(file)) io(); }
void write(HANDLE file, std::string_view wire) {
    while (!wire.empty()) {
        DWORD count = 0; const auto size = static_cast<DWORD>(std::min<std::size_t>(16384,wire.size()));
        if (!WriteFile(file, wire.data(), size, &count,nullptr) || !count || count > size) io();
        wire.remove_prefix(count);
    }
}
std::wstring temporaryName() {
    std::wstring name = L".cqs-publish-"; constexpr wchar_t hex[] = L"0123456789abcdef";
    for (const auto byte : crypto::random(16)) { name += hex[byte >> 4]; name += hex[byte & 15]; }
    return name + L".tmp";
}
struct Staging {
    Pinned file;
    bool cleanup = true;
    ~Staging() { if (cleanup) { FILE_DISPOSITION_INFO remove{TRUE}; SetFileInformationByHandle(file.handle.get(),FileDispositionInfo,&remove,sizeof(remove)); } }
};
} // namespace
struct Directory::Impl {
    Security security;
    Root root;
    Pinned events;
    explicit Impl(const std::filesystem::path &path) : root(path,security,false),
        events(open(child(root.folder(),L"events"),true,inspect|FILE_LIST_DIRECTORY)) { verify(); }
    void verify() const { root.verify(security); mapped(events); security.check(events.handle.get()); sameVolume(events,root.folder()); }
    Root staging(const std::filesystem::path &path) const {
        if(path.empty())fail(ErrorCode::InvalidPath,"Windows publication requires explicit private staging outside transport");
        verify();Root staged(path,security,true,FILE_ADD_FILE);
        if(_wcsicmp(staged.volume.c_str(),root.volume.c_str())!=0)
            fail(ErrorCode::UnsupportedFilesystem,"Transport staging must be on the same NTFS volume");
        for(const auto &p:staged.chain)if(identity(p.initial,root.folder().initial))
            fail(ErrorCode::InvalidPath,"Private staging overlaps transport");
        for(const auto &p:root.chain)if(identity(p.initial,staged.folder().initial))
            fail(ErrorCode::InvalidPath,"Private staging contains transport");
        return staged;
    }
};
Directory::Directory(const std::filesystem::path &path) : impl_(std::make_unique<Impl>(path)) {}
Directory::~Directory() = default;
void Directory::confirm(const crypto::Bytes &key,const events::Envelope &envelope,events::Limits limits) const {
    const auto event=events::decode(key,envelope,limits);impl_->verify();
    const std::wstring device(event.revision.device.begin(),event.revision.device.end());
    auto dir=open(child(impl_->events,device),true,inspect|FILE_LIST_DIRECTORY);
    impl_->security.check(dir.handle.get());sameVolume(dir,impl_->events);
    const auto name=event.revision.id.substr(event.revision.device.size()+1)+".cqs";
    auto file=open(child(dir,std::wstring(name.begin(),name.end())),false,GENERIC_READ|GENERIC_WRITE|READ_CONTROL,FILE_SHARE_READ);
    impl_->security.check(file.handle.get());sameVolume(file,impl_->events);mapped(file,true);
    if(file.initial.standard.EndOfFile.QuadPart<0 || static_cast<ULONGLONG>(file.initial.standard.EndOfFile.QuadPart)!=envelope.bytes.size())
        fail(ErrorCode::Changed,"Reserved ciphertext size differs");
    if(read(file)!=envelope.bytes)fail(ErrorCode::Changed,"Reserved ciphertext differs");
    flush(file.handle.get());mapped(file,true);mapped(dir);impl_->verify();
}
events::AuthenticatedHistory Directory::scan(const crypto::Bytes &key, Limits limits) const {
    const Limits ceiling;
    if (!limits.entries || !limits.devices || limits.entries > ceiling.entries || limits.devices > ceiling.devices)
        fail(ErrorCode::InvalidLimits, "Invalid transport scan limits");
    (void)events::AuthenticatedHistory(key,{},limits.reader); impl_->verify();
    const auto eventsStamp = stamp(impl_->events.handle.get(),true);
    std::size_t remaining = limits.entries, totalBytes = 0;
    const auto devices = names(impl_->events,remaining);
    if (devices.size() > limits.devices) fail(ErrorCode::ScanLimit, "Too many transport devices");
    std::vector<Pinned> dirs;
    std::vector<std::vector<std::wstring>> files;
    struct Input { Pinned file; std::string id, bytes; };
    std::vector<Input> input;
    for (const auto &wide : devices) {
        const auto device = ascii(wide);
        try { (void)history::makeId(device,1); }
        catch (const history::Error &) { fail(ErrorCode::UnsafeEntry, "Unexpected transport device directory"); }
        dirs.push_back(open(child(impl_->events,wide),true,inspect|FILE_LIST_DIRECTORY));
        const auto &dir = dirs.back(); impl_->security.check(dir.handle.get()); sameVolume(dir,impl_->events);
        files.push_back(names(dir,remaining));
        for (const auto &name : files.back()) {
            const auto id = eventId(device,name);
            if (input.size() == limits.reader.events) fail(ErrorCode::ScanLimit, "Too many transport events");
            auto file = open(child(dir,name),false,GENERIC_READ|READ_CONTROL,FILE_SHARE_READ);
            impl_->security.check(file.handle.get()); sameVolume(file,impl_->events); mapped(file,true);
            const auto size = static_cast<ULONGLONG>(file.initial.standard.EndOfFile.QuadPart);
            if (size > limits.reader.eventBytes || size > limits.reader.historyBytes-totalBytes)
                fail(ErrorCode::ScanLimit, "Transport wire budget exceeded");
            totalBytes += static_cast<std::size_t>(size); input.push_back({std::move(file),id,{}});
        }
    }
    CQS_HOOK(FilePinned);
    for (auto &item : input) item.bytes = read(item.file);
    CQS_HOOK(ScanRead);
    std::vector<events::Envelope> envelopes; envelopes.reserve(input.size());
    for (const auto &item : input) envelopes.push_back({item.id,item.bytes});
    events::AuthenticatedHistory result(key,envelopes,limits.reader);
    CQS_HOOK(ScanAuthenticated);
    // NTFS directory timestamp updates alone are not a namespace snapshot.
    // Independently re-enumerate all names with the same bounded inventory.
    std::size_t verifyBudget = limits.entries;
    if (names(impl_->events,verifyBudget) != devices) fail(ErrorCode::Changed, "Transport device names changed during scan");
    for (std::size_t i = 0; i < dirs.size(); ++i)
        if (names(dirs[i],verifyBudget) != files[i]) fail(ErrorCode::Changed, "Transport event names changed during scan");
    for (const auto &item : input) { mapped(item.file,true); impl_->security.check(item.file.handle.get()); }
    for (const auto &dir : dirs) { mapped(dir,true); impl_->security.check(dir.handle.get()); }
    if (!same(stamp(impl_->events.handle.get(),true),eventsStamp)) fail(ErrorCode::Changed, "Transport device listing changed");
    impl_->verify(); return result;
}
void Directory::checkPublicationDevice(const std::string &device) const {
    (void)history::makeId(device,1);impl_->verify();
    const Limits ceiling;std::size_t remaining=ceiling.entries;
    const auto devices=names(impl_->events,remaining);
    const std::wstring name(device.begin(),device.end());
    if(devices.size()>ceiling.devices || (devices.size()==ceiling.devices&&std::find(devices.begin(),devices.end(),name)==devices.end()))
        fail(ErrorCode::ScanLimit,"No transport device slot for publication");
    impl_->verify();
}
void Directory::checkPublicationStaging(const std::filesystem::path &path) const { (void)impl_->staging(path); }
void Directory::publish(const crypto::Bytes &key, const events::Envelope &envelope, events::Limits limits,
                        const std::filesystem::path &privateStaging) const {
    (void)events::AuthenticatedHistory(key,{},limits);
    if (!limits.events || envelope.bytes.size() > limits.eventBytes || envelope.bytes.size() > limits.historyBytes)
        fail(ErrorCode::ScanLimit, "Transport publication exceeds budget");
    const std::string wire(envelope.bytes);
    limits.plaintextBytes = std::min(limits.plaintextBytes,limits.historyPlaintextBytes);
    auto event = events::decode(key,{envelope.expectedId,wire},limits);
    checkPublicationDevice(event.revision.device);
    const std::wstring device(event.revision.device.begin(),event.revision.device.end());
    const auto number = event.revision.id.substr(event.revision.device.size()+1);
    const std::wstring filename(number.begin(),number.end());
    for (auto &item : event.items) std::fill(item.begin(),item.end(),'\0');
    event.items.clear();
    auto stagingRoot=impl_->staging(privateStaging);
    const auto devicePath = child(impl_->events,device);
    if (!CreateDirectoryW(devicePath.c_str(),&impl_->security.attributes) && GetLastError() != ERROR_ALREADY_EXISTS) io();
    auto dir = open(devicePath,true,inspect|FILE_LIST_DIRECTORY);
    impl_->security.check(dir.handle.get()); sameVolume(dir,impl_->events);
    const auto source = child(stagingRoot.folder(),temporaryName());
    Handle raw(CreateFileW(source.c_str(),GENERIC_READ|GENERIC_WRITE|DELETE|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_DELETE,
                           &impl_->security.attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr));
    const auto initial = stamp(raw.get(),false); Staging staged{{std::move(raw),source,initial,false}};
    impl_->security.check(staged.file.handle.get(),true); write(staged.file.handle.get(),wire);
    CQS_HOOK(PublishWritten); flush(staged.file.handle.get()); staged.file.initial = stamp(staged.file.handle.get(),false);
    if (staged.file.initial.standard.EndOfFile.QuadPart != static_cast<LONGLONG>(wire.size())) fail(ErrorCode::Io, "Transport ciphertext staging incomplete");
    CQS_HOOK(PublishReady);
    impl_->verify(); mapped(dir); impl_->security.check(dir.handle.get()); stagingRoot.verify(impl_->security,true);
    mapped(staged.file,true); impl_->security.check(staged.file.handle.get(),true);
    const auto destination = child(dir,filename+L".cqs"); staged.cleanup = false;
    // Source namespace is private and outside the cloud root. WRITE_THROUGH
    // is required; no REPLACE_EXISTING or cross-volume copy fallback is used.
    if (!MoveFileExW(source.c_str(),destination.c_str(),MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) {
            staged.cleanup = true; fail(ErrorCode::AlreadyExists, "Transport event ID exists; never overwritten");
        }
        fail(ErrorCode::PublishedUnconfirmed, "Transport move unconfirmed; reconcile the exact event ID");
    }
    try {
        const auto current = stamp(staged.file.handle.get(),false);
        if (!identity(current,staged.file.initial) || current.standard.EndOfFile.QuadPart != staged.file.initial.standard.EndOfFile.QuadPart ||
            current.basic.LastWriteTime.QuadPart != staged.file.initial.basic.LastWriteTime.QuadPart)
            fail(ErrorCode::Changed, "Transport event changed during publication");
        staged.file.path = destination; staged.file.initial = current;
        CQS_HOOK(PublishLinked); flush(staged.file.handle.get());
        impl_->verify(); mapped(dir); impl_->security.check(dir.handle.get());
        mapped(staged.file,true); impl_->security.check(staged.file.handle.get());
        stagingRoot.verify(impl_->security,true);
    } catch (...) { fail(ErrorCode::PublishedUnconfirmed, "Transport event may be published; flush or identity unconfirmed"); }
}
} // namespace cqs::storage
