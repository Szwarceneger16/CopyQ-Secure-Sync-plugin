// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _WIN32
#error Real Windows/NTFS is required; no filesystem emulation
#endif
#include "storage.h"
#include "storage_hooks.h"
#include "windows_test_acl.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <numeric>

namespace cqs::storage::testing { std::function<void(Point)> hook; }
namespace fs = std::filesystem;
using cqs::storage::Directory;
using cqs::storage::Error;
using cqs::storage::ErrorCode;
using cqs::storage::Limits;
using cqs::storage::testing::Point;
namespace {
int passed = 0;
constexpr DWORD shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const std::string id = "mint-lab/000000000001", childId = "win-lab/000000000001";
const std::wstring filename = L"000000000001.cqs";
cqs::crypto::Bytes key(32);
std::string rootWire, childWire, binaryWire;
std::string read(const fs::path &path) {
    std::ifstream file(path,std::ios::binary); CHECK(file.good());
    return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
}
std::wstring randomName() {
    std::wstring out = L"cqs-storage-win-"; constexpr wchar_t hex[] = L"0123456789abcdef";
    for (const auto c : cqs::crypto::random(16)) { out += hex[c >> 4]; out += hex[c & 15]; }
    return out;
}
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) { CHECK(h && h != INVALID_HANDLE_VALUE); }
    ~Handle() { CloseHandle(value); }
    Handle(const Handle &) = delete;
};
struct Temp {
    fs::path base, root, stage;
    Temp() {
        wchar_t path[32768]{}; const auto n = GetTempPathW(32768,path); CHECK(n && n < 32768);
        base = fs::path(path)/randomName(); root = base/L"transport"; stage = base/L"private-staging";
        cqs::testing::directory(base); cqs::testing::directory(root); cqs::testing::directory(events()); cqs::testing::directory(stage);
    }
    ~Temp() { std::error_code ec; fs::remove_all(base,ec); }
    fs::path events() const { return root/L"events"; }
    fs::path device(const std::wstring &name = L"mint-lab") const { return events()/name; }
    fs::path event() const { return device()/filename; }
    void seeded() { cqs::testing::directory(device()); cqs::testing::write(event(),rootWire); }
};
void fixtures(const fs::path &path) {
    rootWire = read(path/L"mint-lab-000000000001.cqs");
    childWire = read(path/L"win-lab-000000000001.cqs");
    binaryWire = read(path/L"binary-pc-000000000001.cqs");
    std::iota(key.begin(),key.end(),0);
}
void rejects(ErrorCode expected, const std::function<void()> &body) {
    bool caught = false;
    try { body(); }
    catch (const Error &e) {
        if (e.code() != expected) std::cerr << "Unexpected transport error code " << static_cast<int>(e.code())
            << "; expected " << static_cast<int>(expected) << ": " << e.what() << std::endl;
        CHECK(e.code() == expected); caught = true;
    }
    CHECK(caught);
}
void changedOrUnsafe(const std::function<void()> &body) {
    bool caught = false; try { body(); } catch (const Error &e) { CHECK(e.code() == ErrorCode::Changed || e.code() == ErrorCode::UnsafeEntry); caught = true; } CHECK(caught);
}
void on(Point point, std::function<void()> body) {
    cqs::storage::testing::hook = [point,body = std::move(body),done = false](Point p) mutable {
        if (!done && point == p) { done = true; body(); }
    };
}
void test(const char *name, const std::function<void()> &body) {
    cqs::storage::testing::hook = {}; std::cout << "RUN " << name << std::endl;
    body(); ++passed; cqs::storage::testing::hook = {}; std::cout << "PASS " << name << std::endl;
}
void symlink(const fs::path &target, const fs::path &link, bool directory) {
    CHECK(CreateSymbolicLinkW(link.c_str(),target.c_str(),(directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0)|0x2));
}
std::wstring executable() {
    std::wstring path(32768,L'\0'); const auto n = GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    CHECK(n && n < path.size()); path.resize(n); return path;
}
struct Child {
    HANDLE process = nullptr;
    explicit Child(const std::wstring &args) {
        auto command = L"\""+executable()+L"\" "+args;
        STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION child{};
        CHECK(CreateProcessW(nullptr,command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&child));
        CloseHandle(child.hThread); process = child.hProcess;
    }
    ~Child() { if (process) CloseHandle(process); }
    DWORD wait() {
        if (WaitForSingleObject(process,30000) != WAIT_OBJECT_0) { TerminateProcess(process,99); CHECK(false); }
        DWORD result = 0; CHECK(GetExitCodeProcess(process,&result)); return result;
    }
};
std::wstring quote(const fs::path &path) { return L"\""+path.wstring()+L"\""; }
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        if (argc == 7 && std::wstring(argv[1]) == L"--race") {
            fixtures(argv[4]); Handle ready(OpenEventW(EVENT_MODIFY_STATE,FALSE,argv[5])), go(OpenEventW(SYNCHRONIZE,FALSE,argv[6]));
            on(Point::PublishReady,[&] { CHECK(SetEvent(ready.value)); CHECK(WaitForSingleObject(go.value,15000) == WAIT_OBJECT_0); });
            try { Directory d(argv[2]); d.publish(key,{id,rootWire},{},argv[3]); return 0; }
            catch (const Error &e) {
                if (e.code() != ErrorCode::AlreadyExists) std::cerr << "Race child error " << static_cast<int>(e.code()) << ": " << e.what() << std::endl;
                return e.code() == ErrorCode::AlreadyExists ? 2 : 9;
            }
        }
        if (argc == 6 && std::wstring(argv[1]) == L"--crash") {
            fixtures(argv[4]); const auto point = static_cast<Point>(std::stoi(argv[5]));
            on(point,[] { TerminateProcess(GetCurrentProcess(),86); });
            Directory d(argv[2]); d.publish(key,{id,rootWire},{},argv[3]); return 9;
        }
        CHECK(argc == 2); const fs::path fixtureDir(argv[1]); fixtures(fixtureDir);
        test("empty existing transport and repeated scans", [] {
            Temp t; Directory d(t.root); for (int i=0;i<3;++i) CHECK(d.scan(key).graph().size() == 0);
        });
        test("missing root or events is never initialized", [] {
            Temp t; rejects(ErrorCode::Unavailable,[&] { Directory d(t.base/L"missing"); }); CHECK(!fs::exists(t.base/L"missing"));
            fs::remove(t.events()); rejects(ErrorCode::Unavailable,[&] { Directory d(t.root); }); CHECK(!fs::exists(t.events()));
        });
        test("unsafe path syntax rejected", [] {
            for (const auto *path : {L"relative",L"C:\\",L"C:relative",L"\\\\server\\share",L"\\\\?\\C:\\dir",L"C:\\dir:stream",L"C:\\dir\\..\\root"})
                rejects(ErrorCode::InvalidPath,[&] { Directory d(path); });
        });
        test("Unicode and spaces in selected root", [] {
            Temp t; const auto newRoot = t.base/L"transport \u017c\u00f3\u0142\u0107"; fs::rename(t.root,newRoot); t.root = newRoot;
            t.seeded(); Directory d(t.root); CHECK(d.scan(key).graph().tips() == std::vector<std::string>{id});
        });
        test("root ancestor and events reparse points rejected", [] {
            Temp t, alias;
            const auto link = alias.base/L"link"; symlink(t.root,link,true); rejects(ErrorCode::UnsafeEntry,[&] { Directory d(link); });
            rejects(ErrorCode::UnsafeEntry,[&] { Directory d(link/L"events"); });
            fs::remove(alias.events()); symlink(t.events(),alias.events(),true); rejects(ErrorCode::UnsafeEntry,[&] { Directory d(alias.root); });
        });
        test("event symlink and hardlink rejected", [] {
            Temp t, outside; outside.seeded(); cqs::testing::directory(t.device()); symlink(outside.event(),t.event(),false);
            Directory d(t.root); rejects(ErrorCode::UnsafeEntry,[&] { d.scan(key); }); fs::remove(t.event());
            cqs::testing::write(t.event(),rootWire); CHECK(CreateHardLinkW((t.device()/L"alias").c_str(),t.event().c_str(),nullptr));
            rejects(ErrorCode::UnsafeEntry,[&] { d.scan(key); });
        });
        test("wrong entry types and noncanonical names rejected", [] {
            Temp t; cqs::testing::write(t.events()/L"mint-lab",rootWire); Directory d(t.root);
            rejects(ErrorCode::UnsafeEntry,[&] { d.scan(key); }); fs::remove(t.events()/L"mint-lab");
            cqs::testing::directory(t.device()); cqs::testing::directory(t.event()); rejects(ErrorCode::UnsafeEntry,[&] { d.scan(key); });
        });
        test("conflict copies and hidden leftovers block scan", [] {
            for (const auto *name : {L"000000000001 (conflict).cqs",L".leftover",L"000000000001.CQS",L"000000000000.cqs"}) {
                std::wcout << L"CASE " << name << std::endl;
                Temp t;
                // NTFS preserves an existing name's casing when CREATE_ALWAYS
                // opens a case alias. Start empty for the uppercase-extension
                // case so it really creates the noncanonical directory entry.
                if (std::wstring(name) == L"000000000001.CQS") cqs::testing::directory(t.device());
                else t.seeded();
                cqs::testing::write(t.device()/name,rootWire);
                CHECK(std::any_of(fs::directory_iterator(t.device()),fs::directory_iterator(),[&](const auto &entry) {
                    return entry.path().filename().native() == name;
                }));
                Directory d(t.root);
                rejects(ErrorCode::UnsafeEntry,[&] { d.scan(key); });
            }
        });
        test("transport rejects public write ACLs and preserves read-only grants", [] {
            for (int entry=0;entry<4;++entry) {
                Temp t; t.seeded(); const auto path = entry == 0 ? t.root : entry == 1 ? t.events() : entry == 2 ? t.device() : t.event();
                cqs::testing::WindowsAcl publicWrite(L"(A;;FA;;;WD)"); publicWrite.apply(path);
                rejects(ErrorCode::UnsafeEntry,[&] { Directory d(t.root); d.scan(key); });
            }
            Temp t; t.seeded(); cqs::testing::WindowsAcl publicRead(L"(A;;FR;;;WD)"); publicRead.apply(t.event());
            Directory d(t.root); CHECK(d.scan(key).graph().size() == 1);
        });
        test("NULL DACL rejected without repair", [] {
            Temp t; CHECK(SetNamedSecurityInfoW(const_cast<wchar_t *>(t.root.c_str()),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,
                                              nullptr,nullptr,nullptr,nullptr) == ERROR_SUCCESS);
            rejects(ErrorCode::UnsafeEntry,[&] { Directory d(t.root); });
        });
        test("entry device event and wire budgets checked", [] {
            Temp t; t.seeded(); cqs::testing::directory(t.device(L"other-pc")); Directory d(t.root); Limits l;
            l.entries=1; rejects(ErrorCode::ScanLimit,[&] { d.scan(key,l); });
            l={}; l.devices=1; rejects(ErrorCode::ScanLimit,[&] { d.scan(key,l); });
            l={}; l.reader.events=0; rejects(ErrorCode::ScanLimit,[&] { d.scan(key,l); });
            l={}; l.reader.eventBytes=1; rejects(ErrorCode::ScanLimit,[&] { d.scan(key,l); });
            l={}; l.reader.historyBytes=1; rejects(ErrorCode::ScanLimit,[&] { d.scan(key,l); });
        });
        test("empty scan validates key and reader limits", [] {
            Temp t; Directory d(t.root); bool badKey=false,badLimits=false;
            try { d.scan({}); } catch (const cqs::events::Error&e) { badKey=e.code()==cqs::events::ErrorCode::InvalidKey; }
            Limits l; l.reader.eventBytes=cqs::events::Limits{}.eventBytes+1;
            try { d.scan(key,l); } catch (const cqs::events::Error&e) { badLimits=e.code()==cqs::events::ErrorCode::InvalidLimits; }
            CHECK(badKey && badLimits);
        });
        test("authenticated ancestry missing parents and conflicts", [] {
            Temp t; cqs::testing::directory(t.device(L"win-lab")); cqs::testing::write(t.device(L"win-lab")/filename,childWire); Directory d(t.root);
            bool missing=false; try { d.scan(key); } catch(const cqs::history::Error&e) { missing=e.code()==cqs::history::ErrorCode::MissingParent; } CHECK(missing);
            t.seeded(); CHECK(d.scan(key).graph().tips()==std::vector<std::string>{childId});
            cqs::testing::directory(t.device(L"binary-pc")); cqs::testing::write(t.device(L"binary-pc")/filename,binaryWire); CHECK(d.scan(key).graph().hasConflict());
        });
        test("wrong key and damaged envelope never return a graph", [] {
            Temp t; t.seeded(); Directory d(t.root); auto wrong=key; wrong[0]^=1; bool rejected=false;
            try { d.scan(wrong); } catch(const cqs::events::Error&) { rejected=true; } CHECK(rejected);
            cqs::testing::write(t.event(),"malformed"); rejected=false; try { d.scan(key); } catch(const cqs::events::Error&) { rejected=true; } CHECK(rejected);
        });
        test("existing writer defers scan and pinned file rejects new writers", [] {
            Temp t; t.seeded(); Directory d(t.root);
            { Handle writer(CreateFileW(t.event().c_str(),GENERIC_WRITE,shareAll,nullptr,OPEN_EXISTING,0,nullptr));
              rejects(ErrorCode::Unavailable,[&] { d.scan(key); }); }
            on(Point::FilePinned,[&] {
                const auto h=CreateFileW(t.event().c_str(),GENERIC_WRITE,shareAll,nullptr,OPEN_EXISTING,0,nullptr); const auto error=GetLastError();
                if(h!=INVALID_HANDLE_VALUE)CloseHandle(h); CHECK(h==INVALID_HANDLE_VALUE && error==ERROR_SHARING_VIOLATION);
                CHECK(!DeleteFileW(t.event().c_str()));
            }); CHECK(d.scan(key).graph().size()==1);
        });
        test("late file and device additions invalidate whole scan", [] {
            for(bool device:{false,true}) {
                Temp t; t.seeded(); Directory d(t.root);
                on(Point::ScanAuthenticated,[&] {
                    if(device)cqs::testing::directory(t.device(L"new-pc")); else cqs::testing::write(t.device()/L"000000000002.cqs",rootWire);
                }); rejects(ErrorCode::Changed,[&] { d.scan(key); });
            }
        });
        test("late access changes and impersonation refused", [] {
            Temp t; t.seeded(); Directory d(t.root);
            on(Point::ScanRead,[&] { cqs::testing::WindowsAcl publicWrite(L"(A;;FA;;;WD)"); publicWrite.apply(t.event()); });
            changedOrUnsafe([&] { d.scan(key); }); cqs::storage::testing::hook={};
            cqs::testing::WindowsAcl normal; normal.apply(t.event()); CHECK(ImpersonateSelf(SecurityImpersonation));
            struct Revert { ~Revert(){RevertToSelf();} } guard;
            rejects(ErrorCode::UnsafeEntry,[&] { d.scan(key); }); CHECK(RevertToSelf());
        });
        test("pinned selected directories cannot be relocated", [] {
            Temp t; Directory d(t.root); auto moved=t.base/L"moved"; CHECK(!MoveFileExW(t.root.c_str(),moved.c_str(),0));
            CHECK(fs::is_directory(t.root) && !fs::exists(moved)); CHECK(d.scan(key).graph().size()==0);
        });
        test("publication requires explicit private staging before writes", [] {
            Temp t; Directory d(t.root); rejects(ErrorCode::InvalidPath,[&] { d.publish(key,{id,rootWire}); });
            rejects(ErrorCode::InvalidPath,[&] { d.checkPublicationStaging(); });
            d.checkPublicationStaging(t.stage);
            CHECK(!fs::exists(t.device()) && fs::is_empty(t.stage));
        });
        test("staging overlap missing path and public ACL rejected", [] {
            Temp t; Directory d(t.root);
            for(const auto &path:{t.root,t.events(),t.base}) {
                rejects(ErrorCode::InvalidPath,[&] { d.checkPublicationStaging(path); });
                rejects(ErrorCode::InvalidPath,[&] { d.publish(key,{id,rootWire},{},path); });
            }
            rejects(ErrorCode::Unavailable,[&] { d.publish(key,{id,rootWire},{},t.base/L"missing"); });
            cqs::testing::WindowsAcl publicRead(L"(A;;FR;;;WD)"); publicRead.apply(t.stage);
            rejects(ErrorCode::UnsafeEntry,[&] { d.checkPublicationStaging(t.stage); });
            rejects(ErrorCode::UnsafeEntry,[&] { d.publish(key,{id,rootWire},{},t.stage); }); CHECK(!fs::exists(t.device()));
        });
        test("bad publication is authenticated before creating anything", [] {
            Temp t; Directory d(t.root); bool refused=false;
            try { d.publish(key,{childId,rootWire},{},t.stage); } catch(const cqs::events::Error&) { refused=true; }
            CHECK(refused && !fs::exists(t.device()) && fs::is_empty(t.stage));
        });
        test("complete ciphertext publication and repeated IDs never overwritten", [] {
            Temp t; Directory d(t.root); d.publish(key,{id,rootWire},{},t.stage);
            CHECK(read(t.event())==rootWire && fs::is_empty(t.stage) && d.scan(key).graph().size()==1);
            rejects(ErrorCode::AlreadyExists,[&] { d.publish(key,{id,rootWire+" "},{},t.stage); });
            CHECK(read(t.event())==rootWire && fs::is_empty(t.stage));
        });
        test("staging stays outside transport and pre-move failure cleans only itself", [] {
            Temp t; Directory d(t.root); cqs::testing::write(t.stage/L"retained-orphan.tmp","opaque ciphertext");
            on(Point::PublishReady,[&] {
                CHECK(!fs::exists(t.event()) && fs::is_empty(t.device())); CHECK(d.scan(key).graph().size()==0);
                throw Error(ErrorCode::Io,"Injected pre-move failure");
            }); rejects(ErrorCode::Io,[&] { d.publish(key,{id,rootWire},{},t.stage); });
            CHECK(!fs::exists(t.event()) && std::distance(fs::directory_iterator(t.stage),fs::directory_iterator())==1);
        });
        test("post-move failure preserves authoritative event", [] {
            Temp t; Directory d(t.root); on(Point::PublishLinked,[] { throw Error(ErrorCode::Io,"Injected post-move failure"); });
            rejects(ErrorCode::PublishedUnconfirmed,[&] { d.publish(key,{id,rootWire},{},t.stage); });
            CHECK(read(t.event())==rootWire && d.scan(key).graph().size()==1);
        });
        test("process interruption before and after publication", [&] {
            for(const auto point:{Point::PublishWritten,Point::PublishReady,Point::PublishLinked}) {
                Temp t; Child child(L"--crash "+quote(t.root)+L" "+quote(t.stage)+L" "+quote(fixtureDir)+L" "+std::to_wstring(static_cast<int>(point)));
                CHECK(child.wait()==86); Directory d(t.root);
                CHECK(d.scan(key).graph().size()==(point==Point::PublishLinked ? 1U : 0U));
                if(point==Point::PublishLinked)CHECK(read(t.event())==rootWire);
            }
        });
        test("two-process publication races yield one immutable winner", [&] {
            for(int i=0;i<3;++i) {
                Temp t; const auto token=randomName(), readyName=L"Local\\"+token+L"-ready", goName=L"Local\\"+token+L"-go";
                Handle ready(CreateEventW(nullptr,TRUE,FALSE,readyName.c_str())), go(CreateEventW(nullptr,TRUE,FALSE,goName.c_str()));
                Child child(L"--race "+quote(t.root)+L" "+quote(t.stage)+L" "+quote(fixtureDir)+L" \""+readyName+L"\" \""+goName+L"\"");
                on(Point::PublishReady,[&] { CHECK(WaitForSingleObject(ready.value,15000)==WAIT_OBJECT_0); CHECK(SetEvent(go.value)); });
                int parent=0; Directory d(t.root);
                try { d.publish(key,{id,rootWire+" "},{},t.stage); } catch(const Error&e) { CHECK(e.code()==ErrorCode::AlreadyExists); parent=2; }
                const auto result=child.wait(); CHECK((parent==0 && result==2)||(parent==2 && result==0));
                CHECK(read(t.event())==(parent==0 ? rootWire+" " : rootWire)); CHECK(d.scan(key).graph().size()==1 && fs::is_empty(t.stage));
            }
        });
        test("successful and rejected scans release handles", [] {
            Temp t; t.seeded(); Directory d(t.root); CHECK(d.scan(key).graph().size()==1); DWORD before=0,after=0;
            CHECK(GetProcessHandleCount(GetCurrentProcess(),&before));
            for(int i=0;i<50;++i)CHECK(d.scan(key).graph().size()==1);
            auto wrong=key; wrong[0]^=1;
            for(int i=0;i<200;++i) { bool refused=false; try { d.scan(wrong); } catch(const cqs::events::Error&) { refused=true; } CHECK(refused); }
            CHECK(GetProcessHandleCount(GetCurrentProcess(),&after)); CHECK(before==after);
        });
        std::cout << passed << " native Windows transport scenarios passed\n"; return 0;
    } catch(const std::exception&e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
