// SPDX-License-Identifier: GPL-3.0-or-later
#include "key_reader.h"
#include "key_reader_hooks.h"
#include "test_check.h"
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <numeric>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace cqs::native::testing { std::function<void(Point)> hook; }
namespace {
int count = 0;
struct Temp {
    fs::path dir, key;
    Temp() {
        char pattern[] = "/tmp/cqs-key-test-XXXXXX";
        const auto path = ::mkdtemp(pattern); CHECK(path != nullptr); dir = path; key = dir / "ksync.key";
    }
    ~Temp() { std::error_code ec; fs::remove_all(dir, ec); }
    void put(std::size_t size = 32) {
        std::ofstream f(key, std::ios::binary);
        for (std::size_t i=0;i<size;++i) f.put(static_cast<char>(i));
        f.close(); CHECK(!f.fail()); CHECK(::chmod(key.c_str(), 0600) == 0);
    }
};
void reject(const std::function<void()> &f) {
    bool caught=false;
    try { f(); } catch (const cqs::crypto::Error &e) {
        caught=true;
        CHECK(std::string(e.what()) == "K-SYNC path, permissions, type, size or stability check failed");
    }
    CHECK(caught);
}
void test(const char *name,const std::function<void()> &f) {
    cqs::native::testing::hook = {};
    std::cout << "RUN " << name << std::endl;
    f(); ++count; std::cout << "PASS " << name << std::endl;
    cqs::native::testing::hook = {};
}
void on(cqs::native::testing::Point point, std::function<void()> body) {
    cqs::native::testing::hook = [point, body = std::move(body), done = false](auto p) mutable {
        if (!done && point == p) { done = true; body(); }
    };
}
}
int main() {
    using cqs::native::readKeyStrict;
    test("exact key bytes returned",[] { Temp t; t.put(); auto key=readKeyStrict(t.key);
        CHECK(key.size()==32); for (unsigned i=0;i<32;++i) CHECK(key[i]==i); cqs::crypto::wipe(key); });
    test("missing file not created",[] { Temp t; reject([&]{readKeyStrict(t.key);}); CHECK(!fs::exists(t.key)); });
    test("relative path rejected",[] { reject([]{readKeyStrict("ksync.key");}); });
    test("filesystem root rejected",[] { reject([]{readKeyStrict("/");}); });
    test("dot paths rejected",[] { Temp t; t.put(); reject([&]{readKeyStrict(t.dir / "." / "ksync.key");});
        reject([&]{readKeyStrict(t.dir / ".." / t.dir.filename() / "ksync.key");}); });
    test("NUL rejected",[] { reject([]{readKeyStrict(fs::path(std::string("/tmp/key\0x",10)));}); });
    test("wrong sizes rejected",[] { for(auto n:{0,1,31,33,4096}) { Temp t; t.put(n); reject([&]{readKeyStrict(t.key);}); } });
    test("permissions unchanged by failure",[] { Temp t; t.put(); CHECK(::chmod(t.key.c_str(),0644)==0);
        reject([&]{readKeyStrict(t.key);}); struct stat s{}; CHECK(::stat(t.key.c_str(),&s)==0); CHECK((s.st_mode&0777)==0644); });
    test("all group and other permissions rejected",[] { for(auto mode:{0610,0604,0620,0602,0640,0601}) {
        Temp t;t.put();CHECK(::chmod(t.key.c_str(),mode)==0);reject([&]{readKeyStrict(t.key);});} });
    test("leaf symlink rejected",[] { Temp t;t.put();auto link=t.dir/"alias";fs::create_symlink(t.key,link);reject([&]{readKeyStrict(link);}); });
    test("ancestor symlink rejected",[] { Temp t;t.put();auto link=t.dir/"alias";fs::create_directory_symlink(t.dir,link);reject([&]{readKeyStrict(link/"ksync.key");}); });
    test("hardlink rejected",[] { Temp t;t.put();fs::create_hard_link(t.key,t.dir/"alias");reject([&]{readKeyStrict(t.key);}); });
    test("FIFO rejected without blocking",[] { Temp t; CHECK(::mkfifo(t.key.c_str(),0600)==0);reject([&]{readKeyStrict(t.key);}); });
    test("directory rejected",[] { Temp t;fs::create_directory(t.key);reject([&]{readKeyStrict(t.key);}); });
    test("writable parent rejected",[] { Temp t;t.put();CHECK(::chmod(t.dir.c_str(),0777)==0);reject([&]{readKeyStrict(t.key);}); });
    test("ordinary Unicode and spaces supported",[] { Temp t;t.key=t.dir/fs::u8path("klucz żółć.key");t.put();CHECK(readKeyStrict(t.key).size()==32); });
    test("unrelated sibling changes do not invalidate the key", [] {
        Temp t; t.put();
        on(cqs::native::testing::Point::ReadPinned, [&] {
            CHECK(fs::create_directory(t.dir / "sibling"));
            // Other test workers create/remove disposable directories in /tmp.
            Temp unrelated; unrelated.put();
        });
        auto key = readKeyStrict(t.key); CHECK(key.size() == 32);
        for (unsigned i = 0; i < 32; ++i) CHECK(key[i] == i);
        cqs::crypto::wipe(key);
    });
    test("parent permissions changing during read rejected", [] {
        Temp t; t.put(); on(cqs::native::testing::Point::ReadPinned, [&] { CHECK(::chmod(t.dir.c_str(), 0777) == 0); });
        reject([&] { readKeyStrict(t.key); });
    });
    test("same-size key mutation during read rejected", [] {
        Temp t; t.put(); on(cqs::native::testing::Point::ReadPinned, [&] {
            std::fstream f(t.key, std::ios::binary | std::ios::in | std::ios::out); CHECK(f.good());
            f.put('x'); f.close(); CHECK(!f.fail());
        });
        reject([&] { readKeyStrict(t.key); });
    });
    test("key mode changing after read rejected", [] {
        Temp t; t.put(); on(cqs::native::testing::Point::ReadComplete, [&] { CHECK(::chmod(t.key.c_str(), 0644) == 0); });
        reject([&] { readKeyStrict(t.key); });
    });
    test("parent replacement during pinned read rejected", [] {
        Temp t; t.put(); const auto moved = fs::path(t.dir.string() + "-moved");
        struct Cleanup { fs::path path; ~Cleanup() { std::error_code ec; fs::remove_all(path, ec); } } cleanup{moved};
        on(cqs::native::testing::Point::ReadPinned, [&] {
            fs::rename(t.dir, moved); CHECK(fs::create_directory(t.dir));
            CHECK(::chmod(t.dir.c_str(), 0700) == 0); t.put();
        });
        reject([&] { readKeyStrict(t.key); });
    });
    test("special mode bits rejected",[] { Temp t;t.put();CHECK(::chmod(t.key.c_str(),04600)==0);reject([&]{readKeyStrict(t.key);}); });
    test("repeat errors release descriptors",[] { Temp t;t.put();CHECK(::chmod(t.key.c_str(),0666)==0);
        auto fds=[] { return std::distance(fs::directory_iterator("/proc/self/fd"),fs::directory_iterator()); };
        const auto before=fds();for(int i=0;i<300;++i) reject([&]{readKeyStrict(t.key);});CHECK(fds()==before); });
    std::cout<<count<<" key-reader scenarios passed\n";
}
