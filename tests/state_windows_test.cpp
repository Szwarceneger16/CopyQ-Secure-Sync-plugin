// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _WIN32
#error These tests require real Windows/NTFS, not a POSIX simulation
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "state_store.h"
#include "state_hooks.h"
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <numeric>
#include <thread>

namespace cqs::state::testing { std::function<void(Point)> hook; }
namespace fs = std::filesystem;
using cqs::state::FileStore;
using cqs::state::Error;
using cqs::state::ErrorCode;
using cqs::state::testing::Point;
using cqs::transaction::Record;
namespace {
int passed = 0, skipped = 0;
const std::string binding = "public-windows-state-test";
void check(bool ok) { if (!ok) throw std::runtime_error("Windows state regression"); }
struct Skip {};
void test(const char *name, const std::function<void()> &body) {
    cqs::state::testing::hook = {};
    std::cout << "RUN " << name << std::endl;
    try { body(); ++passed; std::cout << "PASS " << name << std::endl; }
    catch (const Skip &) { ++skipped; std::cout << "SKIP " << name << " (symlink privilege/Developer Mode absent)\n"; }
    cqs::state::testing::hook = {};
}
void rejects(ErrorCode code, const std::function<void()> &body) {
    bool rejected = false;
    try { body(); } catch (const Error &e) {
        if (e.code() != code) std::cerr << "Wrong error: " << e.what() << '\n';
        check(e.code() == code); rejected = true;
    }
    check(rejected);
}
void on(Point point, std::function<void()> body) {
    cqs::state::testing::hook = [point, body = std::move(body), done = false](Point p) mutable {
        if (!done && point == p) { done = true; body(); }
    };
}
cqs::crypto::Bytes key() { cqs::crypto::Bytes k(32); std::iota(k.begin(), k.end(), 0); return k; }
cqs::crypto::Bytes password() { return cqs::crypto::Bytes(24, 'p'); } // Public fixture.
struct SD {
    PSECURITY_DESCRIPTOR data = nullptr;
    SECURITY_ATTRIBUTES sa{};
    explicit SD(const std::wstring &extra = L"") {
        HANDLE token = nullptr; check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
        DWORD n = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &n);
        std::vector<unsigned char> buffer(n);
        const BOOL success = GetTokenInformation(token, TokenUser, buffer.data(), n, &n);
        CloseHandle(token); check(success);
        LPWSTR user = nullptr;
        check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &user));
        const auto text = L"O:" + std::wstring(user) + L"D:P(A;OICI;FA;;;" + user + L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + extra;
        LocalFree(user);
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1, &data, nullptr));
        sa = {sizeof(sa), data, FALSE};
    }
    ~SD() { if (data) LocalFree(data); }
};
void applyDacl(const fs::path &p, SD &sd) {
    BOOL present = FALSE, defaulted = FALSE; PACL acl = nullptr;
    check(GetSecurityDescriptorDacl(sd.data, &present, &acl, &defaulted));
    check(SetNamedSecurityInfoW(const_cast<wchar_t *>(p.c_str()), SE_FILE_OBJECT,
          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS);
}
struct Temp {
    fs::path root;
    Temp() {
        wchar_t path[32768]{}; DWORD n = GetTempPathW(32768, path); check(n && n < 32768);
        std::wstring name = L"cqs-state-win-"; constexpr wchar_t hex[] = L"0123456789abcdef";
        for (auto c : cqs::crypto::random(16)) { name += hex[c >> 4]; name += hex[c & 15]; }
        root = fs::path(path) / name; SD sd;
        check(CreateDirectoryW(root.c_str(), &sd.sa));
    }
    fs::path record() const { return root / FileStore::RecordName; }
    ~Temp() { std::error_code ignored; fs::remove_all(root, ignored); }
};
std::string wire(const fs::path &path) {
    std::ifstream input(path, std::ios::binary); check(input.good());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void overwrite(const fs::path &path, const std::string &data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc); check(out.good());
    out.write(data.data(), static_cast<std::streamsize>(data.size())); out.close(); check(!out.fail());
}
Record bumped(const Record &record) { auto next = record; ++next.generation; return next; }
void provision(const fs::path &path) { FileStore store(path, binding, key()); auto l = store.lock(); check(bool(l)); store.initialize(); }
Record readState(const fs::path &path) { FileStore store(path, binding, key()); auto l = store.lock(); check(bool(l)); return store.load(); }
std::wstring executable() {
    std::wstring p(32768, L'\0'); const auto n = GetModuleFileNameW(nullptr, p.data(), static_cast<DWORD>(p.size()));
    check(n && n < p.size()); p.resize(n); return p;
}
DWORD child(const std::wstring &args) {
    auto command = L"\"" + executable() + L"\" " + args;
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
    check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &process));
    CloseHandle(process.hThread);
    const auto waited = WaitForSingleObject(process.hProcess, 15000);
    if (waited != WAIT_OBJECT_0) { TerminateProcess(process.hProcess, 99); CloseHandle(process.hProcess); check(false); }
    DWORD exit = 0; check(GetExitCodeProcess(process.hProcess, &exit)); CloseHandle(process.hProcess); return exit;
}
void symlink(const fs::path &target, const fs::path &path, bool directory) {
    if (!CreateSymbolicLinkW(path.c_str(), target.c_str(), (directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0) | 0x2)) {
        const auto error = GetLastError();
        if (error == ERROR_PRIVILEGE_NOT_HELD || error == ERROR_INVALID_PARAMETER) throw Skip{};
        check(false);
    }
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        // Children use only their parent's disposable path and the fixed public
        // test key. Handles/leases are never inherited into these new processes.
        if (argc == 3 && std::wstring(argv[1]) == L"--busy") {
            FileStore store(fs::path(argv[2]), binding, key()); return store.lock() ? 2 : 0;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--crash") {
            const auto point = static_cast<Point>(std::stoi(argv[3]));
            FileStore store(fs::path(argv[2]), binding, key()); auto lease = store.lock(); check(bool(lease));
            const auto old = store.load();
            on(point, [] { TerminateProcess(GetCurrentProcess(), 86); });
            store.commit(old, bumped(old)); return 3;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--transition-crash") {
            const auto point = static_cast<Point>(std::stoi(argv[3]));
            FileStore store(fs::path(argv[2]), binding, key()); auto lease = store.lock(); check(bool(lease));
            const auto old = store.load(); auto next = bumped(old); next.binding = "password-profile";
            on(point, [] { TerminateProcess(GetCurrentProcess(), 86); });
            store.transition(old, next, password(), cqs::state::Protection::Password); return 3;
        }
        check(argc == 1);
        test("explicit provisioning, encrypted bytes and reopen", [] {
            Temp t; provision(t.root); auto r = readState(t.root);
            check(r.generation == 0 && r.binding == binding && !r.head && !r.pending);
            auto w = wire(t.record()); check(w.substr(0, 8) == "CQSREC01" && w.find(binding) == std::string::npos);
            FileStore store(t.root, binding, key()); auto l = store.lock();
            rejects(ErrorCode::AlreadyInitialized, [&] { store.initialize(); });
            check(wire(t.record()) == w);
        });
        test("missing record is not initialized by load", [] {
            Temp t; FileStore store(t.root, binding, key()); auto l = store.lock();
            rejects(ErrorCode::Missing, [&] { store.load(); }); check(!fs::exists(t.record()));
        });
        test("invalid key and relative path", [] {
            Temp t; rejects(ErrorCode::InvalidKey, [&] { FileStore s(t.root, binding, {}); });
            rejects(ErrorCode::UnsafePath, [&] { FileStore s(L"relative", binding, key()); });
        });
        test("no implicit creation of missing directory", [] {
            Temp t; auto missing = t.root / "missing";
            rejects(ErrorCode::Missing, [&] { FileStore s(missing, binding, key()); }); check(!fs::exists(missing));
        });
        test("legacy or orphan artifacts block initialization", [] {
            Temp t; overwrite(t.root / "state.json", "legacy");
            FileStore store(t.root, binding, key()); auto l = store.lock();
            rejects(ErrorCode::InvalidRecord, [&] { store.initialize(); }); check(!fs::exists(t.record()));
        });
        test("load initialize and commit all require a lease", [] {
            Temp t; FileStore store(t.root, binding, key());
            rejects(ErrorCode::LeaseRequired, [&] { store.load(); });
            rejects(ErrorCode::LeaseRequired, [&] { store.initialize(); });
            rejects(ErrorCode::LeaseRequired, [&] { store.commit({}, {}); });
        });
        test("exclusive lease across instances and processes", [] {
            Temp t; provision(t.root); FileStore a(t.root, binding, key()), b(t.root, binding, key());
            auto l = a.lock(); check(bool(l) && !a.lock() && !b.lock());
            check(child(L"--busy \"" + t.root.wstring() + L"\"") == 0);
            l.reset(); check(bool(b.lock()));
        });
        test("lease cannot authorize another thread", [] {
            Temp t; provision(t.root); FileStore store(t.root, binding, key()); auto l = store.lock(); bool rejected = false;
            std::thread other([&] { try { store.load(); } catch (const Error &e) { rejected = e.code() == ErrorCode::LeaseRequired; } });
            other.join(); check(rejected);
            std::thread release([&] { l.reset(); }); release.join(); check(bool(store.lock()));
        });
        test("pending journal and binary backup survive reopen", [] {
            Temp t; provision(t.root); Record next;
            {
                FileStore store(t.root, binding, key()); auto l = store.lock();
                auto before = store.load();
                // A nonempty backup must correspond to a previously accepted
                // checkpoint, not to an unjoined record whose original is empty.
                const cqs::transaction::Head original{
                    {{"mint-lab/000000000001", "mint-lab", 1, {}}, {"AP8="}, 64},
                    {{{"text/plain", {0, 255}}}}};
                auto checkpoint = bumped(before); checkpoint.head = original;
                store.commit(before, checkpoint);
                before = store.load(); next = bumped(before);
                const cqs::transaction::Head target{
                    {{"win-lab/000000000001", "win-lab", 1, {original.event.revision.id}}, {"AAF//w0K"}, 64},
                    {{{"application/octet-stream", {0, 1, 127, 255, 13, 10}}}}};
                next.pending = cqs::transaction::Pending{target, original.snapshot, cqs::transaction::Phase::Import};
                auto inconsistent = next; inconsistent.pending->original.clear();
                const auto priorWire = wire(t.record());
                rejects(ErrorCode::InvalidRecord, [&] { store.commit(before, inconsistent); });
                check(wire(t.record()) == priorWire);
                store.commit(before, next);
            }
            const auto actual = readState(t.root); check(actual.pending.has_value());
            check(cqs::state::serialize(actual) == cqs::state::serialize(next));
        });
        test("whole-record CAS refuses stale generation and different content", [] {
            Temp t; provision(t.root); FileStore store(t.root, binding, key()); auto l = store.lock();
            const auto old = store.load(); auto next = bumped(old); store.commit(old, next);
            const auto bytes = wire(t.record()); rejects(ErrorCode::Stale, [&] { store.commit(old, next); });
            auto lie = next;
            lie.head = cqs::transaction::Head{{{"win-lab/000000000001", "win-lab", 1, {}}, {}, 40}, {}};
            rejects(ErrorCode::Stale, [&] { store.commit(lie, bumped(lie)); }); check(wire(t.record()) == bytes);
        });
        test("generation and binding guards", [] {
            Temp t; provision(t.root); FileStore store(t.root, binding, key()); auto l = store.lock(); auto r = store.load();
            rejects(ErrorCode::Generation, [&] { store.commit(r, r); });
            auto bad = bumped(r); bad.binding = "other";
            rejects(ErrorCode::WrongBinding, [&] { store.commit(r, bad); });
        });
        test("wrong key wrong binding and corrupted ciphertext fail closed", [] {
            Temp t; provision(t.root); const auto original = wire(t.record());
            { auto wrong = key(); wrong[0] ^= 1; FileStore store(t.root, binding, wrong); auto l = store.lock();
              rejects(ErrorCode::AuthenticationFailed, [&] { store.load(); }); }
            { FileStore store(t.root, "another-profile", key()); auto l = store.lock();
              rejects(ErrorCode::AuthenticationFailed, [&] { store.load(); }); }
            auto damaged = original; damaged.back() ^= 1; overwrite(t.record(), damaged);
            { FileStore store(t.root, binding, key()); auto l = store.lock();
              rejects(ErrorCode::AuthenticationFailed, [&] { store.load(); }); }
            check(wire(t.record()) == damaged);
        });
        test("file byte budget enforced before decode", [] {
            Temp t; provision(t.root); cqs::state::Limits limits; limits.recordBytes = 1;
            FileStore store(t.root, binding, key(), limits); auto l = store.lock();
            rejects(ErrorCode::SizeLimit, [&] { store.load(); });
        });
        test("root ACL exposing Everyone is rejected", [] {
            Temp t; SD publicAcl(L"(A;;FR;;;WD)"); applyDacl(t.root, publicAcl);
            rejects(ErrorCode::UnsafePath, [&] { FileStore store(t.root, binding, key()); });
        });
        test("record ACL exposing Everyone is rejected", [] {
            Temp t; provision(t.root); SD publicAcl(L"(A;;FR;;;WD)"); applyDacl(t.record(), publicAcl);
            FileStore store(t.root, binding, key()); auto l = store.lock();
            rejects(ErrorCode::UnsafePath, [&] { store.load(); });
        });
        test("hardlinked record rejected", [] {
            Temp t; provision(t.root); check(CreateHardLinkW((t.root / "second").c_str(), t.record().c_str(), nullptr));
            FileStore store(t.root, binding, key()); auto l = store.lock();
            rejects(ErrorCode::UnsafePath, [&] { store.load(); });
        });
        test("nonempty lock is neither truncated nor accepted", [] {
            Temp t; provision(t.root); overwrite(t.root / FileStore::LockName, "bad-lock");
            FileStore store(t.root, binding, key()); rejects(ErrorCode::UnsafePath, [&] { store.lock(); });
            check(wire(t.root / FileStore::LockName) == "bad-lock");
        });
        test("directory pretending to be a record rejected", [] {
            Temp t; SD sd; check(CreateDirectoryW(t.record().c_str(), &sd.sa));
            FileStore store(t.root, binding, key()); auto l = store.lock();
            rejects(ErrorCode::UnsafePath, [&] { store.load(); });
        });
        test("root symlink is rejected", [] {
            Temp t, alias; const auto link = alias.root / "link"; symlink(t.root, link, true);
            rejects(ErrorCode::UnsafePath, [&] { FileStore store(link, binding, key()); });
        });
        test("intermediate symlink is rejected", [] {
            Temp t, alias; const auto link = alias.root / "link"; symlink(t.root, link, true);
            SD sd; check(CreateDirectoryW((t.root / "inner").c_str(), &sd.sa));
            rejects(ErrorCode::UnsafePath, [&] { FileStore store(link / "inner", binding, key()); });
        });
        test("record symlink is rejected without reading target", [] {
            Temp t, outside; provision(outside.root); symlink(outside.record(), t.record(), false);
            FileStore store(t.root, binding, key()); auto l = store.lock();
            rejects(ErrorCode::UnsafePath, [&] { store.load(); });
        });
        test("record cannot be overwritten during pinned read", [] {
            Temp t; provision(t.root); FileStore store(t.root, binding, key()); auto l = store.lock();
            on(Point::ReadPinned, [&] {
                auto h = CreateFileW(t.record().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     nullptr, OPEN_EXISTING, 0, nullptr);
                const auto error = GetLastError(); if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
                check(h == INVALID_HANDLE_VALUE && error == ERROR_SHARING_VIOLATION);
            });
            check(store.load().generation == 0);
        });
        test("pinned directory cannot be renamed", [] {
            Temp t; FileStore store(t.root, binding, key());
            check(!MoveFileExW(t.root.c_str(), (t.root.wstring() + L"-moved").c_str(), 0));
        });
        test("failure before publication preserves record", [] {
            Temp t; provision(t.root); FileStore store(t.root, binding, key()); auto l = store.lock();
            const auto before = store.load(); const auto bytes = wire(t.record());
            on(Point::StageSynced, [] { throw Error(ErrorCode::Io, "Injected pre-publication failure"); });
            rejects(ErrorCode::Io, [&] { store.commit(before, bumped(before)); });
            check(wire(t.record()) == bytes && store.load().generation == 0);
        });
        test("post-publication error retains authoritative new record", [] {
            Temp t; provision(t.root);
            { FileStore store(t.root, binding, key()); auto l = store.lock(); const auto before = store.load();
              on(Point::Published, [] { throw Error(ErrorCode::Io, "Injected post-publication failure"); });
              rejects(ErrorCode::CommitUnconfirmed, [&] { store.commit(before, bumped(before)); }); }
            check(readState(t.root).generation == 1);
        });
        test("process termination at each write boundary", [] {
            for (auto point : {Point::StageSynced, Point::StageLinked, Point::BeforePublish, Point::Published, Point::DirectorySynced}) {
                Temp t; provision(t.root);
                check(child(L"--crash \"" + t.root.wstring() + L"\" " + std::to_wstring(static_cast<int>(point))) == 86);
                const auto actual = readState(t.root);
                const bool published = point == Point::Published || point == Point::DirectorySynced;
                check(actual.generation == (published ? 1U : 0U));
            }
        });
        test("password and binding transition is atomic and refuses stale credentials", [] {
            Temp t; provision(t.root);
            { FileStore store(t.root, binding, key()); auto l = store.lock(); const auto old = store.load();
              auto next = bumped(old); next.binding = "password-profile";
              store.transition(old, next, password(), cqs::state::Protection::Password);
              check(store.load().binding == next.binding && store.load().generation == 1); }
            { FileStore old(t.root, binding, key()); auto l = old.lock();
              rejects(ErrorCode::InvalidRecord, [&] { old.load(); }); }
            { FileStore current(t.root, "password-profile", password(), {}, cqs::state::Protection::Password);
              auto l = current.lock(); check(current.load().generation == 1); }
        });
        test("process termination during password rewrap leaves one complete credential set", [] {
            for (auto point : {Point::StageSynced, Point::StageLinked, Point::BeforePublish, Point::Published, Point::DirectorySynced}) {
                Temp t; provision(t.root);
                check(child(L"--transition-crash \"" + t.root.wstring() + L"\" " + std::to_wstring(static_cast<int>(point))) == 86);
                const bool published = point == Point::Published || point == Point::DirectorySynced;
                FileStore old(t.root, binding, key()); auto oldLease = old.lock();
                if (published) rejects(ErrorCode::InvalidRecord, [&] { old.load(); });
                else check(old.load().generation == 0);
                oldLease.reset();
                FileStore next(t.root, "password-profile", password(), {}, cqs::state::Protection::Password); auto nextLease = next.lock();
                if (published) check(next.load().generation == 1);
                else rejects(ErrorCode::InvalidRecord, [&] { next.load(); });
            }
        });
        test("rejected operations release handles", [] {
            Temp t; provision(t.root); DWORD before = 0, after = 0;
            check(GetProcessHandleCount(GetCurrentProcess(), &before));
            for (int i = 0; i < 100; ++i) {
                auto wrong = key(); wrong[0] ^= 1; FileStore store(t.root, binding, wrong); auto l = store.lock();
                rejects(ErrorCode::AuthenticationFailed, [&] { store.load(); });
            }
            check(GetProcessHandleCount(GetCurrentProcess(), &after)); check(before == after);
        });
        std::cout << passed << " Windows/NTFS scenarios passed; " << skipped << " explicitly skipped\n";
        return 0;
    } catch (const std::exception &e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
