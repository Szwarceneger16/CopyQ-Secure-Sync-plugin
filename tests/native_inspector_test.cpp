// SPDX-License-Identifier: GPL-3.0-or-later
#include "inspector.h"
#include "test_check.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QTemporaryDir>
#include <QTimer>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <numeric>
#ifdef _WIN32
#include "windows_test_acl.h"
#else
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;
using cqs::native::Inspector;
using cqs::native::Profile;
namespace {
int passed = 0;
std::string rootWire, childWire, binaryWire;
fs::path path(const QString &text) { return fs::u8path(text.toStdString()); }
std::string read(const fs::path &p) { std::ifstream file(p,std::ios::binary); CHECK(file.good()); return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()}; }
void directory(const fs::path &p) {
#ifdef _WIN32
    cqs::testing::directory(p);
#else
    CHECK(fs::create_directory(p)); CHECK(::chmod(p.c_str(),0700)==0);
#endif
}
void write(const fs::path &p, const std::string &wire) {
#ifdef _WIN32
    cqs::testing::write(p,wire);
#else
    std::ofstream file(p,std::ios::binary|std::ios::trunc); CHECK(file.good()); file.write(wire.data(),static_cast<std::streamsize>(wire.size()));
    file.close(); CHECK(!file.fail()); CHECK(::chmod(p.c_str(),0600)==0);
#endif
}
struct Temp {
    QTemporaryDir temp;
    Profile profile;
    Temp() {
        CHECK(temp.isValid()); profile={"local-pc",temp.path()+"/transport",temp.path()+"/keys/ksync.key",temp.path()+"/state"};
        directory(path(profile.transport)); directory(events()); directory(path(temp.path()+"/keys")); directory(path(profile.stateDirectory));
        std::string key(32,'\0'); std::iota(key.begin(),key.end(),0); write(path(profile.keyFile),key);
    }
    fs::path events() const { return path(profile.transport)/"events"; }
    fs::path device(const char *name) const { return events()/name; }
    void put(const char *name, const std::string &wire) { directory(device(name)); write(device(name)/"000000000001.cqs",wire); }
};
QString inspect(Inspector &inspector, const Profile &profile, bool verifyBusy = false) {
    QEventLoop loop; QTimer deadline; deadline.setSingleShot(true); bool done=false; QString result;
    const auto connection=QObject::connect(&inspector,&Inspector::finished,&loop,[&](const QString &status){done=true;result=status;loop.quit();});
    QObject::connect(&deadline,&QTimer::timeout,&loop,&QEventLoop::quit); deadline.start(20000);
    CHECK(inspector.request(profile)); if(verifyBusy)CHECK(inspector.busy() && !inspector.request(profile));
    loop.exec(); QObject::disconnect(connection); CHECK(done && !inspector.busy()); return result;
}
void test(const char *name, const std::function<void()> &body) { std::cout << "RUN " << name << std::endl; body(); ++passed; std::cout << "PASS " << name << std::endl; }
} // namespace
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); CHECK(argc==2); const auto fixtureDir=fs::u8path(argv[1]);
    rootWire=read(fixtureDir/"mint-lab-000000000001.cqs"); childWire=read(fixtureDir/"win-lab-000000000001.cqs"); binaryWire=read(fixtureDir/"binary-pc-000000000001.cqs");
    test("real key and transport worker authenticates without writes", [] {
        Temp t; t.put("mint-lab",rootWire); Inspector inspector;
        const auto result=inspect(inspector,t.profile);
        CHECK(result.startsWith("Authenticated 1 event(s); 1 tip(s).")); CHECK(!result.contains("mint-lab"));
        CHECK(result.contains("Read only:")); CHECK(fs::is_empty(path(t.profile.stateDirectory)));
        CHECK(read(t.device("mint-lab")/"000000000001.cqs")==rootWire && fs::file_size(path(t.profile.keyFile))==32);
    });
    test("busy worker rejects duplicate requests and can inspect again", [] {
        Temp t; Inspector inspector; CHECK(inspect(inspector,t.profile,true).startsWith("Authenticated 0 event(s); 0 tip(s)."));
        CHECK(inspect(inspector,t.profile).startsWith("Authenticated 0 event(s); 0 tip(s)."));
    });
    test("missing parents defer history without accepting a graph", [] {
        Temp t; t.put("win-lab",childWire); Inspector inspector;
        CHECK(inspect(inspector,t.profile)=="Waiting for referenced event files. No history is accepted and nothing is changed.");
    });
    test("authenticated conflicts are retained with no winner", [] {
        Temp t; t.put("mint-lab",rootWire); t.put("binary-pc",binaryWire); Inspector inspector;
        const auto result=inspect(inspector,t.profile); CHECK(result.startsWith("Authenticated 2 event(s); 2 tip(s)."));
        CHECK(result.contains("Conflict retained;") && !result.contains("binary-pc") && !result.contains("mint-lab"));
    });
    test("wrong key reports fixed authentication status", [] {
        Temp t; t.put("mint-lab",rootWire); std::string wrong(32,'x'); write(path(t.profile.keyFile),wrong); Inspector inspector;
        CHECK(inspect(inspector,t.profile)=="Event authentication or payload validation failed. Nothing is changed.");
    });
    test("malformed data and names never enter diagnostic text", [] {
        Temp t; t.put("mint-lab","SHOULD_NOT_BE_DISPLAYED"); Inspector inspector;
        CHECK(inspect(inspector,t.profile)=="Event authentication or payload validation failed. Nothing is changed.");
        write(t.device("mint-lab")/"000000000001.cqs",rootWire); write(t.device("mint-lab")/"UNTRUSTED_REMOTE_NAME",rootWire);
        CHECK(inspect(inspector,t.profile)=="Transport path, permissions, budget or stability check failed. Nothing is changed.");
    });
    test("invalid drafts do not create folders or save state", [] {
        Temp t; t.profile.stateDirectory=t.temp.path()+"/missing-state"; Inspector inspector;
        const auto result=inspect(inspector,t.profile); CHECK(!result.startsWith("Authenticated"));
        CHECK(!fs::exists(path(t.profile.stateDirectory)) && fs::is_empty(t.events()));
    });
    test("unsafe key permissions are refused unchanged", [] {
        Temp t; Inspector inspector;
#ifdef _WIN32
        cqs::testing::WindowsAcl publicAcl(L"(A;;FR;;;WD)"); publicAcl.apply(path(t.profile.keyFile));
#else
        CHECK(::chmod(path(t.profile.keyFile).c_str(),0644)==0);
#endif
        CHECK(inspect(inspector,t.profile)=="K-SYNC cannot be read safely or is invalid. No key material is displayed.");
    });
    test("worker shutdown waits without modifying source or private state", [] {
        Temp t; t.put("mint-lab",rootWire);
        { Inspector inspector; CHECK(inspector.request(t.profile)); }
        CHECK(read(t.device("mint-lab")/"000000000001.cqs")==rootWire && fs::is_empty(path(t.profile.stateDirectory)));
    });
    std::cout << passed << " native inspector scenarios passed\n";
}
