// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _WIN32
#error This file implements the Windows private-state backend only
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "state_store.h"
#include "windows_state_path.h"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <limits>
#include <mutex>
#include <thread>
#include <utility>
#ifdef CQS_STATE_TESTING
#include "../tests/state_hooks.h"
#define STATE_HOOK(p) do { if (testing::hook) testing::hook(testing::Point::p); } while (false)
#else
#define STATE_HOOK(p) do {} while (false)
#endif

namespace cqs::state {
namespace {
using crypto::Bytes;
using transaction::Record;
constexpr DWORD shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
constexpr DWORD inspectAccess = FILE_READ_ATTRIBUTES | READ_CONTROL;
constexpr DWORD inspectFlags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
constexpr wchar_t recordName[] = L"record-v1.cqr";
constexpr wchar_t lockName[] = L".cqs-state.lock";
[[noreturn]] void fail(ErrorCode c, const char *text) { throw Error(c, text); }
[[noreturn]] void io(DWORD code = GetLastError()) {
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
        fail(ErrorCode::Missing, "Private state is missing; not reinitialized");
    if (code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION)
        fail(ErrorCode::Busy, "Private state is in use");
    if (code == ERROR_CANT_ACCESS_FILE || code == ERROR_DIRECTORY)
        fail(ErrorCode::UnsafePath, "Unsafe private state entry");
    fail(ErrorCode::Io, "Windows private-state I/O failed");
}
class Handle final {
public:
    explicit Handle(HANDLE h) : h_(h) { if (h == INVALID_HANDLE_VALUE || !h) io(); }
    ~Handle() { reset(); }
    Handle(Handle &&o) noexcept : h_(std::exchange(o.h_, INVALID_HANDLE_VALUE)) {}
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    HANDLE get() const { return h_; }
    void reset() noexcept { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(std::exchange(h_, INVALID_HANDLE_VALUE)); }
private:
    HANDLE h_;
};
struct LocalFreeGuard { void *p = nullptr; ~LocalFreeGuard() { if (p) LocalFree(p); } };
struct Wiped { Bytes bytes; ~Wiped() { crypto::wipe(bytes); } };
void noImpersonation() {
    HANDLE raw = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        CloseHandle(raw);
        fail(ErrorCode::UnsafePath, "Private state must not run under impersonation");
    }
    if (GetLastError() != ERROR_NO_TOKEN) io();
}
struct Security final {
    Bytes sid;
    LocalFreeGuard descriptor;
    SECURITY_ATTRIBUTES attributes{};
    Security() {
        noImpersonation();
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) io();
        Handle token(raw);
        DWORD size = 0;
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size || size > 65536) io();
        Bytes data(size);
        if (!GetTokenInformation(token.get(), TokenUser, data.data(), size, &size)) io();
        const auto user = reinterpret_cast<const TOKEN_USER *>(data.data())->User.Sid;
        if (!IsValidSid(user)) fail(ErrorCode::UnsafePath, "Invalid process identity");
        sid.resize(GetLengthSid(user));
        if (!CopySid(static_cast<DWORD>(sid.size()), sid.data(), user)) io();
        LPWSTR text = nullptr;
        if (!ConvertSidToStringSidW(sid.data(), &text)) io();
        LocalFreeGuard sidText{text};
        // Explicit owner and protected DACL: never inherit public parent grants.
        const std::wstring sddl = L"O:" + std::wstring(text) + L"D:P(A;;FA;;;" + text + L")(A;;FA;;;SY)(A;;FA;;;BA)";
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) io();
        descriptor.p = sd;
        attributes = {sizeof(SECURITY_ATTRIBUTES), sd, FALSE};
    }
    void check(HANDLE file) const {
        PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
        const auto status = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                            &owner, nullptr, &acl, nullptr, &sd);
        LocalFreeGuard memory{sd};
        if (status != ERROR_SUCCESS) io(status);
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        if (!owner || !IsValidSid(owner) || !EqualSid(owner, const_cast<std::uint8_t *>(sid.data())) ||
            !acl || !IsValidAcl(acl) || !GetSecurityDescriptorControl(sd, &control, &revision) ||
            !(control & SE_DACL_PRESENT) || !(control & SE_DACL_PROTECTED))
            fail(ErrorCode::UnsafePath, "Private state needs a user-owned protected DACL");
        bool userGrant = false;
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void *raw = nullptr;
            if (!GetAce(acl, i, &raw)) io();
            const auto header = static_cast<const ACE_HEADER *>(raw);
            // Reject object/callback/conditional ACEs rather than approximate them.
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE)
                fail(ErrorCode::UnsafePath, "Unsupported private-state access rule");
            if (header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8)
                fail(ErrorCode::UnsafePath, "Invalid private-state access rule");
            const auto ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
            auto trustee = reinterpret_cast<PSID>(&ace->SidStart);
            const auto sidHeader = static_cast<SID *>(trustee);
            if (GetSidLengthRequired(sidHeader->SubAuthorityCount) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) ||
                !IsValidSid(trustee)) fail(ErrorCode::UnsafePath, "Invalid ACL trustee");
            if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
            const bool user = EqualSid(trustee, const_cast<std::uint8_t *>(sid.data())) != FALSE;
            if (!user && !IsWellKnownSid(trustee, WinLocalSystemSid) && !IsWellKnownSid(trustee, WinBuiltinAdministratorsSid))
                fail(ErrorCode::UnsafePath, "Private state grants access to another principal");
            if (user && !(header->AceFlags & INHERIT_ONLY_ACE) && ace->Mask) userGrant = true;
        }
        if (!userGrant) fail(ErrorCode::UnsafePath, "Private state lacks an explicit user grant");
    }
};
struct Stamp { BY_HANDLE_FILE_INFORMATION id{}; FILE_BASIC_INFO basic{}; FILE_STANDARD_INFO standard{}; };
Stamp stamp(HANDLE h, bool directory) {
    Stamp s;
    if (GetFileType(h) != FILE_TYPE_DISK) fail(ErrorCode::UnsafePath, "Private state must be on a local disk");
    if (!GetFileInformationByHandle(h, &s.id) ||
        !GetFileInformationByHandleEx(h, FileBasicInfo, &s.basic, sizeof(s.basic)) ||
        !GetFileInformationByHandleEx(h, FileStandardInfo, &s.standard, sizeof(s.standard))) io();
    if ((s.basic.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_DEVICE)) ||
        !!(s.basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory ||
        s.standard.DeletePending || s.standard.EndOfFile.QuadPart < 0 ||
        (!directory && s.standard.NumberOfLinks != 1))
        fail(ErrorCode::UnsafePath, "Private state rejects reparse points, offline files and hard links");
    return s;
}
bool identity(const Stamp &a, const Stamp &b) {
    return a.id.dwVolumeSerialNumber == b.id.dwVolumeSerialNumber &&
        a.id.nFileIndexHigh == b.id.nFileIndexHigh && a.id.nFileIndexLow == b.id.nFileIndexLow &&
        a.basic.CreationTime.QuadPart == b.basic.CreationTime.QuadPart;
}
bool same(const Stamp &a, const Stamp &b) {
    return identity(a, b) && a.basic.FileAttributes == b.basic.FileAttributes &&
        a.basic.LastWriteTime.QuadPart == b.basic.LastWriteTime.QuadPart &&
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
void mapped(const Pinned &p, bool content = false) {
    auto named = open(p.path, p.directory, FILE_READ_ATTRIBUTES, shareAll);
    const auto current = stamp(p.handle.get(), p.directory);
    if (!identity(p.initial, named.initial) || !identity(p.initial, current) ||
        (content && (!same(p.initial, named.initial) || !same(p.initial, current))))
        fail(ErrorCode::Changed, "Private state mapping or content changed");
}
void flush(HANDLE h) { if (!FlushFileBuffers(h)) io(); }
void writeAll(HANDLE h, const Bytes &wire) {
    std::size_t pos = 0;
    while (pos < wire.size()) {
        DWORD written = 0; const auto count = static_cast<DWORD>(std::min<std::size_t>(16384, wire.size() - pos));
        if (!WriteFile(h, wire.data() + pos, count, &written, nullptr) || !written || written > count) io();
        pos += written;
    }
}
std::wstring tempName() {
    const auto random = crypto::random(16); constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring name = L".cqs-record-";
    for (auto c : random) { name += hex[c >> 4]; name += hex[c & 15]; }
    return name + L".tmp";
}
struct Staging {
    Pinned file;
    bool cleanup = true;
    ~Staging() {
        // Delete only via OUR handle, and only while publication has never been
        // attempted. After an ambiguous move the handle may name the final record.
        if (cleanup) { FILE_DISPOSITION_INFO remove{TRUE};
            SetFileInformationByHandle(file.handle.get(), FileDispositionInfo, &remove, sizeof(remove)); }
    }
};
} // namespace

struct FileStore::Impl {
    Security security;
    std::vector<Pinned> chain;
    Wiped key;
    std::string binding;
    Limits limits;
    Protection protection;
    LeaseKind kind;
    std::mutex mutex;
    HANDLE leaseHandle = INVALID_HANDLE_VALUE;
    std::thread::id owner;
    DWORD process = 0;
    Stamp lockStamp{};
    Impl(const std::filesystem::path &path, std::string b, const Bytes &k, Limits l, Protection p, LeaseKind domain)
        : binding(std::move(b)), limits(l), protection(p),kind(domain) {
        if(kind!=LeaseKind::Record&&kind!=LeaseKind::Session)fail(ErrorCode::InvalidRecord,"Invalid lease domain");
        validateLimits(limits); validateBinding(binding);
        validateSecret(k, protection);
        windows_detail::LocalPath parts;
        try { parts = windows_detail::localPath(path.native()); }
        catch (const std::invalid_argument &) { fail(ErrorCode::UnsafePath, "Explicit local drive path required"); }
        if (GetDriveTypeW(parts.drive.c_str()) != DRIVE_FIXED)
            fail(ErrorCode::UnsupportedFilesystem, "Private state requires a fixed local NTFS volume");
        wchar_t volume[64]{};
        if (!GetVolumeNameForVolumeMountPointW(parts.drive.c_str(), volume, 64))
            fail(ErrorCode::UnsupportedFilesystem, "Substituted or unmapped drives are not supported");
        // Anchor subsequent opens to the volume GUID, not a mutable DOS drive mapping.
        std::wstring current(volume);
        chain.push_back(open(current, true, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE));
        wchar_t filesystem[32]{}; DWORD flags = 0;
        if (!GetVolumeInformationByHandleW(chain.back().handle.get(), nullptr, 0, nullptr, nullptr,
                                           &flags, filesystem, 32)) io();
        if (std::wstring(filesystem) != L"NTFS" || !(flags & FILE_PERSISTENT_ACLS))
            fail(ErrorCode::UnsupportedFilesystem, "Only local NTFS private state is supported");
        for (std::size_t i = 0; i < parts.components.size(); ++i) {
            if (current.back() != L'\\') current += L'\\';
            current += parts.components[i];
            const bool last = i + 1 == parts.components.size();
            chain.push_back(open(current, true, FILE_READ_ATTRIBUTES | (last ? READ_CONTROL | FILE_LIST_DIRECTORY : 0),
                                 FILE_SHARE_READ | FILE_SHARE_WRITE));
            if (chain.back().initial.id.dwVolumeSerialNumber != chain.front().initial.id.dwVolumeSerialNumber)
                fail(ErrorCode::UnsafePath, "Nested private-state volume not supported");
        }
        verify(); key.bytes = k;
    }
    std::wstring child(const wchar_t *name) const { return chain.back().path + L'\\' + name; }
    void verify() const {
        noImpersonation();
        for (const auto &p : chain) mapped(p);
        security.check(chain.back().handle.get());
    }
    void checkFile(const Pinned &file) const {
        if (file.initial.id.dwVolumeSerialNumber != chain.back().initial.id.dwVolumeSerialNumber)
            fail(ErrorCode::UnsafePath, "Private state file is on another volume");
        security.check(file.handle.get()); mapped(file, true);
    }
    void requireLease() const {
        if (kind!=LeaseKind::Record || leaseHandle == INVALID_HANDLE_VALUE || process != GetCurrentProcessId() || owner != std::this_thread::get_id())
            fail(ErrorCode::LeaseRequired, "Private state operation requires this thread's lease");
        verify();
        auto named = open(child(lockName), false, inspectAccess, shareAll);
        if (!same(stamp(leaseHandle, false), lockStamp) || !same(named.initial, lockStamp))
            fail(ErrorCode::Changed, "Private state lock changed");
        security.check(leaseHandle);
    }
    struct Loaded { Record record; Pinned file; };
    Loaded read() {
        requireLease();
        auto file = open(child(recordName), false, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ);
        checkFile(file);
        const auto size = static_cast<ULONGLONG>(file.initial.standard.EndOfFile.QuadPart);
        if (size > limits.recordBytes + envelopeOverhead(protection)) fail(ErrorCode::SizeLimit, "Private state file exceeds budget");
        STATE_HOOK(ReadPinned);
        Bytes wire(static_cast<std::size_t>(size)); std::size_t pos = 0;
        while (pos < wire.size()) {
            DWORD readBytes = 0;
            const auto count = static_cast<DWORD>(std::min<std::size_t>(16384, wire.size() - pos));
            if (!ReadFile(file.handle.get(), wire.data() + pos, count, &readBytes, nullptr)) io();
            if (!readBytes || readBytes > count) fail(ErrorCode::Changed, "Private state read was incomplete");
            pos += readBytes;
        }
        char extra; DWORD count = 0;
        if (!ReadFile(file.handle.get(), &extra, 1, &count, nullptr)) io();
        if (count) fail(ErrorCode::Changed, "Private state grew during read");
        STATE_HOOK(ReadComplete);
        checkFile(file); requireLease();
        auto record = unseal(key.bytes, binding, wire, limits, protection);
        checkFile(file); requireLease();
        return {std::move(record), std::move(file)};
    }
    void write(const Bytes &wire, Pinned *expected) {
        requireLease();
        const auto name = child(tempName().c_str());
        Handle raw(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL,
                               FILE_SHARE_READ | FILE_SHARE_DELETE, &security.attributes, CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        const auto start = stamp(raw.get(), false);
        Staging staged{{std::move(raw), name, start, false}};
        checkFile(staged.file);
        writeAll(staged.file.handle.get(), wire); flush(staged.file.handle.get());
        staged.file.initial = stamp(staged.file.handle.get(), false);
        if (staged.file.initial.standard.EndOfFile.QuadPart != static_cast<LONGLONG>(wire.size()))
            fail(ErrorCode::Io, "Private ciphertext staging is incomplete");
        STATE_HOOK(StageSynced);
        // Named ciphertext staging is private and is never scanned as a record.
        STATE_HOOK(StageLinked);
        STATE_HOOK(BeforePublish);
        requireLease(); checkFile(staged.file);
        if (expected) { checkFile(*expected); expected->handle.reset(); }
        // Windows cannot replace the destination while our non-delete-sharing
        // read handle is open. The lease serializes cooperating writers across
        // this close/move interval; strict DACLs exclude other ordinary users.
        // The backend does NOT claim isolation from a hostile process with our SID.
        staged.cleanup = false;
        const DWORD moveFlags = MOVEFILE_WRITE_THROUGH | (expected ? MOVEFILE_REPLACE_EXISTING : 0);
        if (!MoveFileExW(name.c_str(), child(recordName).c_str(), moveFlags)) {
            const auto error = GetLastError();
            if (!expected && (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)) {
                staged.cleanup = true;
                fail(ErrorCode::AlreadyInitialized, "Private state already exists; never reset");
            }
            // Even a failure may be after namespace mutation but before flush.
            fail(ErrorCode::CommitUnconfirmed, "Private state move unconfirmed; release lease and reload");
        }
        try {
            staged.file.path = child(recordName);
            staged.file.initial = stamp(staged.file.handle.get(), false);
            STATE_HOOK(Published);
            flush(staged.file.handle.get());
            // Not a POSIX directory-fsync claim: Windows uses WRITE_THROUGH move
            // plus file flush. See STATE-WINDOWS.md for durability limitations.
            STATE_HOOK(DirectorySynced);
            requireLease(); checkFile(staged.file);
        } catch (...) {
            fail(ErrorCode::CommitUnconfirmed, "Private state may be committed; release lease and reload");
        }
    }
};
struct FileStore::FileLease final : Store::Lease {
    std::shared_ptr<Impl> state;
    Handle handle;
    FileLease(std::shared_ptr<Impl> s, Handle &&h) : state(std::move(s)), handle(std::move(h)) {}
    ~FileLease() override {
        std::lock_guard<std::mutex> guard(state->mutex);
        OVERLAPPED offset{};
        UnlockFileEx(handle.get(), 0, 1, 0, &offset);
        state->leaseHandle = INVALID_HANDLE_VALUE;
        // Close while still serialized; otherwise a concurrent lock() could race
        // an old handle even though the in-process lease indicator was cleared.
        handle.reset();
    }
};
FileStore::FileStore(const std::filesystem::path &path, std::string binding, const Bytes &key, Limits l, Protection p, LeaseKind domain)
    : impl_(std::make_shared<Impl>(path, std::move(binding), key, l, p,domain)) {}
FileStore::~FileStore() = default;
std::unique_ptr<transaction::Store::Lease> FileStore::lock() {
    auto &s = *impl_; std::unique_lock<std::mutex> guard(s.mutex, std::try_to_lock);
    if (!guard.owns_lock()) return nullptr;
    s.verify(); if (s.leaseHandle != INVALID_HANDLE_VALUE) return nullptr;
    const auto path = s.child(s.kind==LeaseKind::Session?L".cqs-session.lock":lockName);
    HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, &s.security.attributes, CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
    bool created = raw != INVALID_HANDLE_VALUE;
    if (!created) {
        const auto error = GetLastError();
        if (error == ERROR_SHARING_VIOLATION) return nullptr;
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) io(error);
        raw = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, inspectFlags, nullptr);
        if (raw == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION) return nullptr;
    }
    Handle handle(raw);
    const auto before = stamp(handle.get(), false);
    Pinned pinned{std::move(handle), path, before, false};
    s.checkFile(pinned);
    if (before.standard.EndOfFile.QuadPart != 0) fail(ErrorCode::UnsafePath, "Private lock must be empty");
    OVERLAPPED offset{};
    if (!LockFileEx(pinned.handle.get(), LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &offset)) {
        if (GetLastError() == ERROR_LOCK_VIOLATION) return nullptr;
        io();
    }
    if (created) flush(pinned.handle.get());
    s.verify(); s.checkFile(pinned);
    auto lease = std::make_unique<FileLease>(impl_, std::move(pinned.handle));
    s.lockStamp = before; s.leaseHandle = lease->handle.get();
    s.process = GetCurrentProcessId(); s.owner = std::this_thread::get_id();
    return lease;
}
Record FileStore::load() {
    std::unique_lock<std::mutex> guard(impl_->mutex, std::try_to_lock);
    if (!guard.owns_lock()) fail(ErrorCode::Busy, "Private state operation in progress");
    return impl_->read().record;
}
void FileStore::initialize() { initialize(Record{1, impl_->binding, 0, {}, {}}); }
void FileStore::checkInitializable() {
    auto &s = *impl_; std::unique_lock<std::mutex> guard(s.mutex, std::try_to_lock);
    if (!guard.owns_lock()) fail(ErrorCode::Busy, "Private state operation in progress");
    s.requireLease();
    WIN32_FIND_DATAW entry{};
    HANDLE raw = FindFirstFileW(s.child(L"*").c_str(), &entry);
    if (raw == INVALID_HANDLE_VALUE) io();
    struct Listing { HANDLE h; ~Listing() { FindClose(h); } } listing{raw};
    do {
        const std::wstring name(entry.cFileName);
        if (_wcsicmp(name.c_str(), recordName) == 0)
            fail(ErrorCode::AlreadyInitialized, "Private state already exists; not reset");
        if (name != L"." && name != L".." && name != lockName && name!=L".cqs-session.lock")
            fail(ErrorCode::InvalidRecord, "Private setup directory contains legacy or unknown state");
    } while (FindNextFileW(raw, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) io();
}
void FileStore::initialize(const Record &initial) {
    checkInitializable();
    auto &s=*impl_;std::unique_lock<std::mutex> guard(s.mutex,std::try_to_lock);
    if(!guard.owns_lock())fail(ErrorCode::Busy,"Private state operation in progress");
    s.requireLease();
    s.write(seal(s.key.bytes, s.binding, initial, s.limits, s.protection), nullptr);
}
void FileStore::commit(const Record &expected, const Record &replacement) {
    auto &s = *impl_; std::unique_lock<std::mutex> guard(s.mutex, std::try_to_lock);
    if (!guard.owns_lock()) fail(ErrorCode::Busy, "Private state operation in progress");
    s.requireLease();
    if (expected.binding != s.binding || replacement.binding != s.binding)
        fail(ErrorCode::WrongBinding, "Commit belongs to another private profile");
    if (expected.generation == std::numeric_limits<std::uint64_t>::max() || replacement.generation != expected.generation + 1)
        fail(ErrorCode::Generation, "Private state generation must advance exactly once");
    auto current = s.read();
    Wiped wanted{serialize(expected, s.limits)}, actual{serialize(current.record, s.limits)};
    if (wanted.bytes != actual.bytes) fail(ErrorCode::Stale, "Whole-record compare-and-swap failed");
    const auto wire = seal(s.key.bytes, s.binding, replacement, s.limits, s.protection);
    s.write(wire, &current.file);
}
void FileStore::transition(const Record &expected, const Record &replacement, const Bytes &newSecret, Protection newProtection) {
    auto &s = *impl_; std::unique_lock<std::mutex> guard(s.mutex, std::try_to_lock);
    if (!guard.owns_lock()) fail(ErrorCode::Busy, "Private state operation in progress");
    s.requireLease(); validateSecret(newSecret, newProtection); validateBinding(replacement.binding);
    if (expected.binding != s.binding) fail(ErrorCode::WrongBinding, "Transition belongs to another private profile");
    if (expected.generation == std::numeric_limits<std::uint64_t>::max() || replacement.generation != expected.generation + 1)
        fail(ErrorCode::Generation, "Private state generation must advance exactly once");
    auto current = s.read();
    Wiped wanted{serialize(expected, s.limits)}, actual{serialize(current.record, s.limits)}, nextSecret{newSecret};
    if (wanted.bytes != actual.bytes) fail(ErrorCode::Stale, "Whole-record compare-and-swap failed");
    auto nextBinding = replacement.binding;
    const auto wire = seal(nextSecret.bytes, nextBinding, replacement, s.limits, newProtection);
    s.write(wire, &current.file);
    crypto::wipe(s.key.bytes); s.key.bytes = std::move(nextSecret.bytes);
    s.binding = std::move(nextBinding); s.protection = newProtection;
}
} // namespace cqs::state
