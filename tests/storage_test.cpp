// SPDX-License-Identifier: GPL-3.0-or-later
#include "storage.h"
#include "storage_hooks.h"
#include "test_check.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <numeric>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

namespace cqs::storage::testing { std::function<void(Point)> hook; }
namespace fs = std::filesystem;
using cqs::storage::Directory;
using cqs::storage::Error;
using cqs::storage::ErrorCode;
using cqs::storage::Limits;
using cqs::storage::testing::Point;
namespace {
const std::string id = "mint-lab/000000000001";
const std::string childId = "win-lab/000000000001";
const std::string file = "000000000001.cqs";
cqs::crypto::Bytes key(32);
std::string rootWire, childWire;
int cases = 0;
std::string read(const fs::path &p) {
    std::ifstream f(p, std::ios::binary); CHECK(f.good());
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
void write(const fs::path &p, const std::string &s) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc); CHECK(f.good());
    f.write(s.data(), static_cast<std::streamsize>(s.size())); f.close(); CHECK(!f.fail());
}
struct Temp {
    fs::path base, root, events, device, event;
    Temp() {
        char name[] = "/tmp/cqs-storage-XXXXXX";
        const char *p = ::mkdtemp(name); CHECK(p != nullptr); base = p;
        root = base / "transport"; events = root / "events";
        device = events / "mint-lab"; event = device / file;
        fs::create_directories(events);
    }
    void seeded() { fs::create_directory(device); write(event, rootWire); }
    ~Temp() { std::error_code ec; fs::remove_all(base, ec); }
};
void test(const char *label, const std::function<void()> &body) {
    cqs::storage::testing::hook = {};
    body();
    cqs::storage::testing::hook = {};
    ++cases; std::cout << "PASS " << label << std::endl;
}
template<class Exception, class Code, class Body>
void rejects(Code code, Body body) {
    bool rejected = false;
    try { body(); }
    catch (const Exception &e) {
        if (e.code() != code) std::cerr << "Wrong error: " << e.what() << '\n';
        CHECK(e.code() == code); rejected = true;
    }
    CHECK(rejected);
}
void bad(ErrorCode code, const std::function<void()> &f) { rejects<Error>(code, f); }
void eventBad(cqs::events::ErrorCode code, const std::function<void()> &f) {
    rejects<cqs::events::Error>(code, f);
}
void on(Point point, std::function<void()> f) {
    cqs::storage::testing::hook = [point, f = std::move(f), used = false](Point p) mutable {
        if (p == point && !used) { used = true; f(); }
    };
}
} // namespace
int main(int argc, char **argv) {
    CHECK(argc == 2); std::iota(key.begin(), key.end(), 0);
    rootWire = read(fs::path(argv[1]) / "mint-lab-000000000001.cqs");
    childWire = read(fs::path(argv[1]) / "win-lab-000000000001.cqs");
    test("empty existing events directory", [] {
        Temp t; Directory d(t.root); CHECK(d.scan(key).graph().size() == 0);
    });
    test("publication preflight keeps Linux staging anonymous and creates nothing", [] {
        Temp t; Directory d(t.root); d.checkPublicationStaging();
        bad(ErrorCode::InvalidPath, [&] { d.checkPublicationStaging(t.base / "staging"); });
        CHECK(fs::is_empty(t.events)); CHECK(!fs::exists(t.base / "staging"));
    });
    test("missing transport is not an empty history and is not created", [] {
        Temp t; auto missing = t.base / "missing";
        bad(ErrorCode::Unavailable, [&] { Directory d(missing); }); CHECK(!fs::exists(missing));
        fs::remove(t.events);
        bad(ErrorCode::Unavailable, [&] { Directory d(t.root); }); CHECK(!fs::exists(t.events));
    });
    test("root path validation", [] {
        for (const fs::path &p : {fs::path("relative"), fs::path("/"), fs::path("/tmp/../tmp"),
                                  fs::path("/tmp/."), fs::path(std::string("/tmp\0evil", 9))})
            bad(ErrorCode::InvalidPath, [&] { Directory d(p); });
    });
    test("Unicode path and repeated scans", [] {
        Temp t; auto renamed = t.base / fs::u8path("folder-żółć");
        fs::rename(t.root, renamed); Directory d(renamed);
        d.publish(key, {id, rootWire});
        for (int i = 0; i < 5; ++i) {
            auto h = d.scan(key); CHECK(h.graph().size() == 1);
            CHECK(h.graph().tips() == std::vector<std::string>{id}); CHECK(h.events()[0].items.size() == 1);
        }
    });
    test("root, ancestor and events symlinks rejected", [] {
        Temp t; auto alias = t.base / "alias";
        fs::create_directory_symlink(t.root, alias);
        bad(ErrorCode::UnsafeEntry, [&] { Directory d(alias); });
        fs::remove(alias); fs::create_directory_symlink(t.base, alias);
        bad(ErrorCode::UnsafeEntry, [&] { Directory d(alias / "transport"); });
        fs::remove(t.events); fs::create_directory(t.base / "outside");
        fs::create_directory_symlink(t.base / "outside", t.events);
        bad(ErrorCode::UnsafeEntry, [&] { Directory d(t.root); });
    });
    test("device symlink rejected on scan and publish", [] {
        Temp t; fs::create_directory(t.base / "outside");
        fs::create_directory_symlink(t.base / "outside", t.device); Directory d(t.root);
        bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
        bad(ErrorCode::UnsafeEntry, [&] { d.publish(key, {id, rootWire}); });
        CHECK(fs::is_empty(t.base / "outside"));
    });
    test("event symlink and dangling symlink rejected", [] {
        Temp t; fs::create_directory(t.device); write(t.base / "outside", rootWire);
        fs::create_symlink(t.base / "outside", t.event); Directory d(t.root);
        bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
        fs::remove(t.base / "outside"); bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
    });
    test("hardlinked file rejected", [] {
        Temp t; t.seeded(); fs::create_hard_link(t.event, t.base / "other"); Directory d(t.root);
        bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
    });
    test("FIFO is rejected without blocking", [] {
        Temp t; fs::create_directory(t.device); CHECK(::mkfifo(t.event.c_str(), 0600) == 0);
        Directory d(t.root); bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
    });
    test("UNIX socket is rejected without opening its content", [] {
        Temp t; fs::create_directory(t.device); int s = ::socket(AF_UNIX, SOCK_STREAM, 0); CHECK(s >= 0);
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        const auto path = t.event.string(); CHECK(path.size() < sizeof(address.sun_path));
        std::copy(path.begin(), path.end(), address.sun_path);
        CHECK(::bind(s, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
        Directory d(t.root); bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); }); ::close(s);
    });
    test("directory pretending to be an event rejected", [] {
        Temp t; fs::create_directories(t.event); Directory d(t.root);
        bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
    });
    test("broadly writable transport root rejected", [] {
        Temp t; CHECK(::chmod(t.root.c_str(), 0777) == 0);
        bad(ErrorCode::UnsafeEntry, [&] { Directory d(t.root); });
    });
    test("broadly writable device and event rejected", [] {
        Temp t; t.seeded(); CHECK(::chmod(t.device.c_str(), 0777) == 0); Directory d(t.root);
        bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
        CHECK(::chmod(t.device.c_str(), 0700) == 0); CHECK(::chmod(t.event.c_str(), 0666) == 0);
        bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
    });
    test("unknown names including Nextcloud conflict copies fail closed", [] {
        for (const auto &name : {"000000000000.cqs", "000000000001.CQS", "1.cqs", ".partial",
                                 "000000000001 (conflicted copy).cqs", "000000000001.cqs.tmp", "key.txt"}) {
            Temp t; fs::create_directory(t.device); write(t.device / name, rootWire); Directory d(t.root);
            bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); }); CHECK(fs::exists(t.device / name));
        }
    });
    test("invalid device names are not ignored", [] {
        for (const auto &name : {"WIN-PC", "ab", ".temp", "bad_name"}) {
            Temp t; fs::create_directory(t.events / name); Directory d(t.root);
            bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
        }
    });
    test("filename must match authenticated identity", [] {
        Temp t; fs::create_directory(t.device); write(t.device / "000000000002.cqs", rootWire);
        Directory d(t.root); eventBad(cqs::events::ErrorCode::WrongIdentity, [&] { d.scan(key); });
    });
    test("missing parents defer without discarding child", [] {
        Temp t; Directory d(t.root); d.publish(key, {childId, childWire});
        rejects<cqs::history::Error>(cqs::history::ErrorCode::MissingParent, [&] { d.scan(key); });
        d.publish(key, {id, rootWire}); auto h = d.scan(key);
        CHECK(h.graph().tips() == std::vector<std::string>{childId});
        CHECK(h.events()[1].items.empty());
    });
    test("authentication failure never yields a partial history", [] {
        Temp t; t.seeded(); Directory d(t.root); d.publish(key, {childId, childWire});
        auto broken = childWire; broken[15] = broken[15] == 'A' ? 'B' : 'A';
        write(t.events / "win-lab" / file, broken);
        eventBad(cqs::events::ErrorCode::AuthenticationFailed, [&] { d.scan(key); });
    });
    test("empty directory still validates key and budgets", [] {
        Temp t; Directory d(t.root);
        eventBad(cqs::events::ErrorCode::InvalidKey, [&] { d.scan({}); });
        Limits limits; limits.reader.eventBytes++;
        eventBad(cqs::events::ErrorCode::InvalidLimits, [&] { d.scan(key, limits); });
        for (bool device : {false, true}) {
            Limits badLimits; if (device) badLimits.devices = 129; else badLimits.entries = 4097;
            bad(ErrorCode::InvalidLimits, [&] { d.scan(key, badLimits); });
        }
    });
    test("metadata budgets checked before content reads", [] {
        Temp t; t.seeded(); Directory d(t.root); bool readCalled = false;
        on(Point::ReadChunk, [&] { readCalled = true; });
        Limits limits; limits.reader.eventBytes = rootWire.size() - 1;
        bad(ErrorCode::ScanLimit, [&] { d.scan(key, limits); }); CHECK(!readCalled);
        limits.reader.eventBytes = rootWire.size(); CHECK(d.scan(key, limits).graph().size() == 1);
        limits.reader.events = 0; bad(ErrorCode::ScanLimit, [&] { d.scan(key, limits); });
    });
    test("aggregate wire budget enforced", [] {
        Temp t; t.seeded(); Directory d(t.root); d.publish(key, {childId, childWire});
        Limits limits; limits.reader.historyBytes = rootWire.size() + childWire.size() - 1;
        bad(ErrorCode::ScanLimit, [&] { d.scan(key, limits); });
        ++limits.reader.historyBytes; CHECK(d.scan(key, limits).graph().size() == 2);
    });
    test("empty device directories consume scan budget", [] {
        Temp t; fs::create_directory(t.events / "other-pc"); t.seeded(); Directory d(t.root);
        Limits limits; limits.devices = 1; bad(ErrorCode::ScanLimit, [&] { d.scan(key, limits); });
        limits.devices = 2; limits.entries = 2;
        bad(ErrorCode::ScanLimit, [&] { d.scan(key, limits); });
        limits.entries = 3; CHECK(d.scan(key, limits).graph().size() == 1);
    });
    test("replaced file after pin is detected before reading", [] {
        Temp t; t.seeded(); Directory d(t.root);
        on(Point::FilePinned, [&] { fs::remove(t.event); write(t.event, rootWire); });
        bad(ErrorCode::Changed, [&] { d.scan(key); });
    });
    test("symlink replacement after pin is not followed", [] {
        Temp t; t.seeded(); Directory d(t.root); write(t.base / "outside", "DO_NOT_READ");
        on(Point::FilePinned, [&] { fs::remove(t.event); fs::create_symlink(t.base / "outside", t.event); });
        bad(ErrorCode::Changed, [&] { d.scan(key); }); CHECK(read(t.base / "outside") == "DO_NOT_READ");
    });
    test("event growth and truncation during read detected", [] {
        for (bool grow : {false, true}) {
            Temp t; t.seeded(); Directory d(t.root);
            on(Point::ReadChunk, [&] { write(t.event, grow ? rootWire + " " : ""); });
            bad(ErrorCode::Changed, [&] { d.scan(key); });
        }
    });
    test("same-size mutation with restored mtime detected", [] {
        Temp t; t.seeded(); Directory d(t.root); struct stat s{}; CHECK(::stat(t.event.c_str(), &s) == 0);
        on(Point::ScanRead, [&] {
            auto changed = rootWire; changed.back() = ' '; write(t.event, changed);
            const timespec times[2]{s.st_atim, s.st_mtim}; CHECK(::utimensat(AT_FDCWD, t.event.c_str(), times, 0) == 0);
        });
        bad(ErrorCode::Changed, [&] { d.scan(key); });
    });
    test("late change after authentication rejected", [] {
        Temp t; t.seeded(); Directory d(t.root);
        on(Point::ScanAuthenticated, [&] { fs::remove(t.event); });
        bad(ErrorCode::Changed, [&] { d.scan(key); });
    });
    test("device added during scan does not produce a partial graph", [] {
        Temp t; t.seeded(); Directory d(t.root);
        on(Point::ScanAuthenticated, [&] { fs::create_directory(t.events / "new-pc"); });
        bad(ErrorCode::Changed, [&] { d.scan(key); });
    });
    test("file added during scan detected", [] {
        Temp t; t.seeded(); Directory d(t.root);
        on(Point::ScanAuthenticated, [&] { write(t.device / "000000000002.cqs", rootWire); });
        bad(ErrorCode::Changed, [&] { d.scan(key); });
    });
    test("renamed root invalidates persistent directory handle", [] {
        Temp t; t.seeded(); Directory d(t.root); fs::rename(t.root, t.base / "old");
        fs::create_directories(t.events);
        bad(ErrorCode::Changed, [&] { d.scan(key); });
        bad(ErrorCode::Changed, [&] { d.publish(key, {childId, childWire}); });
        CHECK(fs::is_empty(t.events));
    });
    test("publication writes exact authenticated wire bytes and private permissions", [] {
        Temp t; Directory d(t.root); d.publish(key, {id, rootWire}); CHECK(read(t.event) == rootWire);
        struct stat s{}; CHECK(::stat(t.event.c_str(), &s) == 0);
        CHECK((s.st_mode & 0777) == 0600); CHECK(s.st_nlink == 1);
        CHECK(d.scan(key).graph().size() == 1);
    });
    test("duplicate publication never truncates or replaces", [] {
        Temp t; Directory d(t.root); d.publish(key, {id, rootWire}); struct stat before{}, after{};
        CHECK(::stat(t.event.c_str(), &before) == 0);
        bad(ErrorCode::AlreadyExists, [&] { d.publish(key, {id, rootWire}); });
        bad(ErrorCode::AlreadyExists, [&] { d.publish(key, {id, rootWire + " "}); });
        CHECK(::stat(t.event.c_str(), &after) == 0); CHECK(before.st_ino == after.st_ino);
        CHECK(before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
        CHECK(read(t.event) == rootWire);
    });
    test("existing symlink destination is not overwritten or followed", [] {
        Temp t; fs::create_directory(t.device); fs::create_symlink(t.base / "absent", t.event);
        Directory d(t.root); bad(ErrorCode::AlreadyExists, [&] { d.publish(key, {id, rootWire}); });
        CHECK(fs::is_symlink(t.event)); CHECK(!fs::exists(t.base / "absent"));
    });
    test("unauthenticated publication cannot create directories or files", [] {
        Temp t; Directory d(t.root); auto wrong = key; wrong[0] ^= 1;
        eventBad(cqs::events::ErrorCode::AuthenticationFailed, [&] { d.publish(wrong, {id, rootWire}); });
        eventBad(cqs::events::ErrorCode::WrongIdentity, [&] { d.publish(key, {"../../outside", rootWire}); });
        CHECK(fs::is_empty(t.events));
    });
    test("staging is invisible and failures leave no partial final", [] {
        Temp t; Directory d(t.root);
        on(Point::PublishWritten, [&] {
            CHECK(fs::is_empty(t.device)); throw Error(ErrorCode::Io, "Injected write failure");
        });
        bad(ErrorCode::Io, [&] { d.publish(key, {id, rootWire}); }); CHECK(fs::is_empty(t.device));
        CHECK(d.scan(key).graph().size() == 0);
    });
    test("device replacement before publication never writes replacement", [] {
        Temp t; Directory d(t.root); fs::create_directory(t.base / "outside");
        on(Point::PublishReady, [&] {
            fs::rename(t.device, t.events / "old-pc");
            fs::create_directory_symlink(t.base / "outside", t.device);
        });
        bad(ErrorCode::Changed, [&] { d.publish(key, {id, rootWire}); });
        CHECK(fs::is_empty(t.base / "outside")); CHECK(fs::is_empty(t.events / "old-pc"));
    });
    test("post-link failure is unconfirmed, never rolled back", [] {
        Temp t; Directory d(t.root);
        on(Point::PublishLinked, [&] { throw Error(ErrorCode::Io, "Injected sync failure"); });
        bad(ErrorCode::PublishedUnconfirmed, [&] { d.publish(key, {id, rootWire}); });
        CHECK(read(t.event) == rootWire); CHECK(d.scan(key).graph().size() == 1);
        bad(ErrorCode::AlreadyExists, [&] { d.publish(key, {id, rootWire}); });
    });
    test("same-size modification after link is unconfirmed", [] {
        Temp t; Directory d(t.root);
        on(Point::PublishLinked, [&] { auto changed = rootWire; changed.back() = ' '; write(t.event, changed); });
        bad(ErrorCode::PublishedUnconfirmed, [&] { d.publish(key, {id, rootWire}); });
        CHECK(fs::exists(t.event));
    });
    test("publication respects lowered plaintext history budget", [] {
        Temp t; Directory d(t.root); cqs::events::Limits limits; limits.historyPlaintextBytes = 1;
        eventBad(cqs::events::ErrorCode::InvalidPayload, [&] { d.publish(key, {id, rootWire}, limits); });
        CHECK(fs::is_empty(t.events));
    });
    test("publication respects lowered wire and count budgets", [] {
        Temp t; Directory d(t.root); cqs::events::Limits limits;
        limits.eventBytes = rootWire.size() - 1;
        bad(ErrorCode::ScanLimit, [&] { d.publish(key, {id, rootWire}, limits); });
        limits = {}; limits.historyBytes = rootWire.size() - 1;
        bad(ErrorCode::ScanLimit, [&] { d.publish(key, {id, rootWire}, limits); });
        limits = {}; limits.events = 0;
        bad(ErrorCode::ScanLimit, [&] { d.publish(key, {id, rootWire}, limits); });
        CHECK(fs::is_empty(t.events));
    });
    test("large file crosses read chunk boundaries", [] {
        Temp t; t.seeded(); write(t.event, std::string(65536, ' ') + rootWire);
        Directory d(t.root); CHECK(d.scan(key).graph().size() == 1);
    });
    test("directory and file type changes after pin are rejected", [] {
        Temp t; t.seeded(); Directory d(t.root);
        on(Point::FilePinned, [&] { fs::rename(t.device, t.events / "old-pc"); fs::create_directory(t.device); });
        bad(ErrorCode::Changed, [&] { d.scan(key); });
    });
    test("repeated rejected scans release all file descriptors", [] {
        Temp t; t.seeded(); fs::create_symlink(t.base / "outside", t.device / "000000000002.cqs");
        Directory d(t.root);
        const auto descriptors = [] { return std::distance(fs::directory_iterator("/proc/self/fd"), fs::directory_iterator()); };
        const auto before = descriptors();
        for (int i = 0; i < 200; ++i) bad(ErrorCode::UnsafeEntry, [&] { d.scan(key); });
        CHECK(descriptors() == before);
    });
    test("competing publishers: exactly one commits the name", [] {
        for (int trial = 0; trial < 6; ++trial) {
            Temp t; int ready[2], go[2]; CHECK(::pipe(ready) == 0); CHECK(::pipe(go) == 0);
            const pid_t child = ::fork(); CHECK(child >= 0);
            if (!child) {
                ::close(ready[0]); ::close(go[1]);
                on(Point::PublishReady, [&] {
                    char token; CHECK(::write(ready[1], "x", 1) == 1); CHECK(::read(go[0], &token, 1) == 1);
                });
                try { Directory d(t.root); d.publish(key, {id, rootWire}); ::_exit(0); }
                catch (const Error &e) { ::_exit(e.code() == ErrorCode::AlreadyExists ? 2 : 9); }
                catch (...) { ::_exit(9); }
            }
            ::close(ready[1]); ::close(go[0]);
            on(Point::PublishReady, [&] {
                char token; CHECK(::read(ready[0], &token, 1) == 1); CHECK(::write(go[1], "x", 1) == 1);
            });
            int parent = 0;
            try { Directory d(t.root); d.publish(key, {id, rootWire + " "}); }
            catch (const Error &e) { CHECK(e.code() == ErrorCode::AlreadyExists); parent = 2; }
            ::close(ready[0]); ::close(go[1]);
            int status; CHECK(::waitpid(child, &status, 0) == child); CHECK(WIFEXITED(status));
            const int result = WEXITSTATUS(status); CHECK((parent == 0 && result == 2) || (parent == 2 && result == 0));
            CHECK(read(t.event) == (parent == 0 ? rootWire + " " : rootWire));
            Directory d(t.root); CHECK(d.scan(key).graph().size() == 1);
        }
    });
    std::cout << cases << " storage test cases passed\n";
}
