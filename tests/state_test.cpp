// SPDX-License-Identifier: GPL-3.0-or-later
#include "state_store.h"
#include "state_hooks.h"
#include "test_check.h"
#include <algorithm>
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <random>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>

namespace cqs::state::testing { std::function<void(Point)> hook; }
namespace fs = std::filesystem;
namespace st = cqs::state;
namespace tx = cqs::transaction;
using cqs::crypto::Bytes;
using st::FileStore;
using st::ErrorCode;
using st::testing::Point;
namespace {
const std::string binding = "test-binding-mint-v1";
const Bytes key(32, 0x42); // PUBLIC TEST KEY, never a user key
int cases = 0;
void test(const char *name, const std::function<void()> &f) {
    st::testing::hook = {}; f(); st::testing::hook = {};
    std::cout << "PASS " << ++cases << " " << name << std::endl;
}
template<class F> void rejects(ErrorCode code, F f) {
    bool caught = false;
    try { f(); } catch (const st::Error &e) {
        if (e.code() != code) std::cerr << "Unexpected error: " << e.what() << '\n';
        CHECK(e.code() == code); caught = true;
    }
    CHECK(caught);
}
void anyBad(const std::function<void()> &f) {
    bool caught = false; try { f(); } catch (const st::Error &) { caught = true; } CHECK(caught);
}
void on(Point point, std::function<void()> fn) {
    st::testing::hook = [point, fn=std::move(fn), used=false](Point p) mutable {
        if (point == p && !used) { used = true; fn(); }
    };
}
Bytes read(const fs::path &p) {
    std::ifstream f(p, std::ios::binary); CHECK(f.good());
    return {std::istreambuf_iterator<char>(f), {}};
}
void write(const fs::path &p, const Bytes &b) {
    std::ofstream f(p, std::ios::binary|std::ios::trunc); CHECK(f.good());
    f.write(reinterpret_cast<const char *>(b.data()), b.size()); f.close(); CHECK(!f.fail());
    CHECK(::chmod(p.c_str(), 0600) == 0);
}
struct Temp {
    fs::path root;
    Temp() { char p[] = "/tmp/cqs-state-XXXXXX"; auto *s = ::mkdtemp(p); CHECK(s); root=s; }
    ~Temp() { std::error_code ec; fs::remove_all(root, ec); }
    fs::path record() const { return root / FileStore::RecordName; }
    fs::path lock() const { return root / FileStore::LockName; }
};
tx::Record empty() { return {1, binding, 0, {}, {}}; }
tx::Head target(std::uint64_t sequence=1) {
    const std::string secret = "LOCAL-SECRET-MIME-NEVER-ON-DISK";
    tx::Head h; h.event.revision = {cqs::history::makeId("mint-lab", sequence), "mint-lab", sequence, {}};
    h.event.items = {"YQ=="}; h.event.plaintextBytes = 55;
    h.snapshot = {{{"application/binary", Bytes{0, 255, 0, 13, 10}}, {"text/plain", Bytes(secret.begin(), secret.end())}, {"zero-length", {}}}};
    return h;
}
tx::Record pending() {
    auto r = empty(); r.generation=1; r.pending = tx::Pending{target(), {}, tx::Phase::Import}; return r;
}
bool eq(const tx::Record &a, const tx::Record &b) { return st::serialize(a) == st::serialize(b); }
void initialize(FileStore &s) { auto lease=s.lock(); CHECK(lease); s.initialize(); }
void prepare(FileStore &s) { auto lease=s.lock(); CHECK(lease); s.initialize(); s.commit(s.load(), pending()); }
// Construct malformed but authenticated plaintexts ONLY for codec tests.
Bytes authenticated(const Bytes &plain, const std::string &b=binding) {
    constexpr char domain[]="CopyQ-Secure-Sync-private-state-v1";
    Bytes aad(domain, domain+sizeof(domain)); const std::string magic="CQSREC01";
    aad.insert(aad.end(), magic.begin(), magic.end()); aad.insert(aad.end(), b.begin(), b.end());
    const Bytes nonce(12, 0x33); // fixed test-only nonce
    auto cipher=cqs::crypto::aes256GcmEncrypt(key, nonce, plain, aad);
    Bytes wire(magic.begin(), magic.end()); wire.insert(wire.end(), nonce.begin(), nonce.end()); wire.insert(wire.end(),cipher.begin(),cipher.end()); return wire;
}
struct Clipboard final : tx::Clipboard {
    tx::Snapshot data;
    std::uint64_t epoch=0;
    int writes=0;
    tx::Snapshot decode(const std::vector<std::string> &packed, tx::Limits) override {
        if (packed.empty()) return {};
        CHECK(packed == std::vector<std::string>{"YQ=="}); return target().snapshot;
    }
    tx::View capture(tx::Limits) override { return {data,epoch}; }
    tx::View replace(const tx::View &expected, const tx::Snapshot &desired) override {
        CHECK(expected.epoch==epoch && expected.snapshot==data); data=desired; ++epoch; ++writes; return {data,epoch};
    }
    tx::Snapshot persist(const tx::View &expected, tx::Limits) override {
        CHECK(expected.epoch==epoch && expected.snapshot==data); return data; // deliberately a MODEL, not CopyQ durability
    }
};
} // namespace
int main() {
    test("codec empty record and fresh nonce per seal", [] {
        const auto a=st::seal(key,binding,empty()), b=st::seal(key,binding,empty()); CHECK(a!=b);
        CHECK(eq(st::unseal(key,binding,a),empty())); CHECK(eq(st::unseal(key,binding,b),empty()));
    });
    test("binary MIME, empty fields, head and recovery journal roundtrip", [] {
        auto r=pending(); r.head=target(2); r.pending->original=r.head->snapshot; r.generation=4;
        for (auto phase : {tx::Phase::Import,tx::Phase::Restore}) {
            r.pending->phase=phase; const auto raw=st::serialize(r);
            CHECK(st::serialize(st::parse(raw))==raw); CHECK(eq(st::unseal(key,binding,st::seal(key,binding,r)),r));
        }
    });
    test("wrong key and binding fail authentication", [] {
        auto wire=st::seal(key,binding,pending()); auto k=key; k[0]^=1;
        rejects(ErrorCode::AuthenticationFailed,[&]{st::unseal(k,binding,wire);});
        rejects(ErrorCode::AuthenticationFailed,[&]{st::unseal(key,"other-binding",wire);});
        rejects(ErrorCode::InvalidKey,[&]{st::seal({},binding,empty());});
        rejects(ErrorCode::WrongBinding,[&]{st::seal(key,"other",empty());});
    });
    test("truncation, trailing and ciphertext/header/nonce/tag mutation", [] {
        auto wire=st::seal(key,binding,pending());
        for (std::size_t n=0;n<wire.size();++n) { auto shortWire=wire; shortWire.resize(n); anyBad([&]{st::unseal(key,binding,shortWire);}); }
        for (std::size_t n=0;n<wire.size();++n) { auto changed=wire; changed[n]^=1; anyBad([&]{st::unseal(key,binding,changed);}); }
        wire.push_back(0); anyBad([&]{st::unseal(key,binding,wire);});
    });
    test("bounded parser with full-width generation", [] {
        auto r=empty(); r.generation=std::numeric_limits<std::uint64_t>::max(); CHECK(eq(st::parse(st::serialize(r)),r));
        auto b=st::serialize(empty()); b[15]=255; anyBad([&]{st::parse(b);});
        b=st::serialize(empty()); b.back()=2; rejects(ErrorCode::InvalidRecord,[&]{st::parse(b);});
        b=st::serialize(empty()); b.push_back(0); rejects(ErrorCode::InvalidRecord,[&]{st::parse(b);});
        b=st::serialize(empty()); b[7]=2; rejects(ErrorCode::InvalidRecord,[&]{st::unseal(key,binding,authenticated(b));});
    });
    test("invalid records rejected before encryption", [] {
        auto r=empty(); r.schema=2; rejects(ErrorCode::InvalidRecord,[&]{st::serialize(r);});
        r=pending(); r.generation=0; rejects(ErrorCode::InvalidRecord,[&]{st::serialize(r);});
        r=pending(); r.pending->phase=static_cast<tx::Phase>(9); rejects(ErrorCode::InvalidRecord,[&]{st::serialize(r);});
        r=pending(); r.pending->original=target().snapshot; rejects(ErrorCode::InvalidRecord,[&]{st::serialize(r);});
        r=pending(); r.head=target(); r.pending->original=r.head->snapshot; rejects(ErrorCode::InvalidRecord,[&]{st::serialize(r);});
        r=pending(); r.pending->target.event.items={"YR=="}; rejects(ErrorCode::InvalidRecord,[&]{st::serialize(r);});
        r=pending(); r.pending->target.snapshot[0]["bad mime"]={}; rejects(ErrorCode::InvalidRecord,[&]{st::serialize(r);});
    });
    test("limits checked for encoder and decoder", [] {
        const auto r=pending(); auto bytes=st::serialize(r); st::Limits l; l.recordBytes=bytes.size(); CHECK(eq(st::parse(bytes,l),r));
        --l.recordBytes; rejects(ErrorCode::SizeLimit,[&]{st::serialize(r,l);}); rejects(ErrorCode::SizeLimit,[&]{st::parse(bytes,l);});
        l={}; l.snapshot.items=0; anyBad([&]{st::serialize(r,l);}); anyBad([&]{st::parse(bytes,l);});
        l={}; l.snapshot.formatsPerItem=1; anyBad([&]{st::serialize(r,l);}); anyBad([&]{st::parse(bytes,l);});
        l={}; l.snapshot.snapshotBytes=1; anyBad([&]{st::parse(bytes,l);});
        l={}; ++l.recordBytes; rejects(ErrorCode::InvalidLimits,[&]{st::serialize(empty(),l);});
    });
    test("canonical MIME map rejects duplicate and unsorted keys", [] {
        auto r=pending(); r.pending->target.snapshot={{{"aaa",{}},{"bbb",{}}}};
        auto b=st::serialize(r);
        auto where=std::search(b.begin(),b.end(),std::begin("bbb"),std::end("bbb")-1); CHECK(where!=b.end());
        std::fill(where,where+3,'a'); rejects(ErrorCode::InvalidRecord,[&]{st::parse(b);});
        std::fill(where,where+3,'A'); rejects(ErrorCode::InvalidRecord,[&]{st::parse(b);});
    });
    test("10000 deterministic malformed plaintext parser inputs", [] {
        std::mt19937 rng(0x43515331); const auto base=st::serialize(pending());
        for(int i=0;i<10000;++i) {
            auto b=base;
            if(i%2) {b.resize(rng()%512); for(auto &v:b) v=static_cast<std::uint8_t>(rng());}
            else b[rng()%b.size()]^=static_cast<std::uint8_t>(1+(rng()%255));
            try { auto r=st::parse(b); CHECK(st::serialize(r)==b); } catch (const st::Error &) {}
        }
    });
    test("explicit initialization and reopen on real disk", [] {
        Temp t; {FileStore s(t.root,binding,key); auto lease=s.lock(); CHECK(lease);
        rejects(ErrorCode::Missing,[&]{s.load();}); CHECK(!fs::exists(t.record())); s.initialize(); CHECK(eq(s.load(),empty()));
        rejects(ErrorCode::AlreadyInitialized,[&]{s.initialize();});}
        FileStore s(t.root,binding,key); auto lease=s.lock(); CHECK(eq(s.load(),empty()));
    });
    test("commit persists checkpoint and backup in one encrypted file", [] {
        Temp t; {FileStore s(t.root,binding,key); prepare(s);}
        FileStore s(t.root,binding,key); auto lease=s.lock(); CHECK(eq(s.load(),pending()));
        const auto wire=read(t.record()); const std::string text(wire.begin(),wire.end());
        CHECK(text.find("LOCAL-SECRET-MIME-NEVER-ON-DISK")==std::string::npos);
        CHECK(text.find("text/plain")==std::string::npos); CHECK(text.find(binding)==std::string::npos);
        CHECK(std::search(wire.begin(),wire.end(),key.begin(),key.end())==wire.end());
        struct stat mode{}; CHECK(::stat(t.record().c_str(),&mode)==0); CHECK((mode.st_mode&0777)==0600); CHECK(mode.st_nlink==1);
    });
    test("whole-record CAS rejects altered data even at same generation", [] {
        Temp t; FileStore s(t.root,binding,key); prepare(s); auto lease=s.lock(); auto expected=s.load();
        auto replacement=expected; replacement.generation++;
        expected.pending->target.event.plaintextBytes++; rejects(ErrorCode::Stale,[&]{s.commit(expected,replacement);});
        expected=s.load(); expected.pending->target.snapshot[0]["text/plain"].push_back(0);
        rejects(ErrorCode::Stale,[&]{s.commit(expected,replacement);}); CHECK(eq(s.load(),pending()));
    });
    test("stale generations, skipped increments and wrong binding rejected", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock(); auto r=s.load(), next=r;
        rejects(ErrorCode::Generation,[&]{s.commit(r,next);}); next.generation=2;
        rejects(ErrorCode::Generation,[&]{s.commit(r,next);}); next.generation=1; s.commit(r,next);
        rejects(ErrorCode::Stale,[&]{s.commit(r,next);}); next.binding="other";
        rejects(ErrorCode::WrongBinding,[&]{s.commit(r,next);});
    });
    test("operations require same-thread lease, including inherited process", [] {
        Temp t; FileStore s(t.root,binding,key);
        rejects(ErrorCode::LeaseRequired,[&]{s.load();}); rejects(ErrorCode::LeaseRequired,[&]{s.initialize();});
        auto lease=s.lock(); CHECK(lease); s.initialize(); CHECK(!s.lock());
        std::thread other([&]{rejects(ErrorCode::LeaseRequired,[&]{s.load();});}); other.join();
        auto pid=::fork(); CHECK(pid>=0);
        if(!pid) { rejects(ErrorCode::LeaseRequired,[&]{s.load();}); lease.reset(); ::_exit(0); }
        int result; CHECK(::waitpid(pid,&result,0)==pid); CHECK(WIFEXITED(result)&&WEXITSTATUS(result)==0);
        FileStore competitor(t.root,binding,key); CHECK(!competitor.lock()); CHECK(eq(s.load(),empty()));
    });
    test("cross-instance and cross-process nonblocking lease", [] {
        Temp t; FileStore s(t.root,binding,key), other(t.root,binding,key); auto lease=s.lock(); CHECK(!other.lock());
        auto pid=::fork(); CHECK(pid>=0);
        if(!pid) {FileStore child(t.root,binding,key); ::_exit(child.lock()?9:0);}
        int status; CHECK(::waitpid(pid,&status,0)==pid); CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
        lease.reset(); CHECK(other.lock()!=nullptr);
    });
    test("lease safely outlives FileStore object", [] {
        Temp t; auto s=std::make_unique<FileStore>(t.root,binding,key); auto lease=s->lock(); s.reset();
        FileStore other(t.root,binding,key); CHECK(!other.lock()); lease.reset(); CHECK(other.lock()!=nullptr);
    });
    test("missing, relative, traversal and broad-mode directories rejected", [] {
        Temp t; rejects(ErrorCode::Missing,[&]{FileStore s(t.root/"absent",binding,key);});
        CHECK(!fs::exists(t.root/"absent"));
        for(auto p:{fs::path("relative"),fs::path("/"),t.root/"..",t.root/"."})
            rejects(ErrorCode::UnsafePath,[&]{FileStore s(p,binding,key);});
        CHECK(::chmod(t.root.c_str(),0755)==0); rejects(ErrorCode::UnsafePath,[&]{FileStore s(t.root,binding,key);});
    });
    test("Unicode private directory", [] {
        Temp t; auto dir=t.root/fs::u8path("żółć 🗝"); fs::create_directory(dir); CHECK(::chmod(dir.c_str(),0700)==0);
        FileStore s(dir,binding,key); initialize(s); auto lease=s.lock(); CHECK(eq(s.load(),empty()));
    });
    test("symlinked ancestors and final private directory rejected", [] {
        Temp t; auto alias=t.root/"alias"; fs::create_directory_symlink(t.root,alias);
        rejects(ErrorCode::UnsafePath,[&]{FileStore s(alias,binding,key);});
        fs::create_directory(t.root/"child"); CHECK(::chmod((t.root/"child").c_str(),0700)==0);
        rejects(ErrorCode::UnsafePath,[&]{FileStore s(alias/"child",binding,key);});
    });
    test("record symlink, hardlink, FIFO, directory and broad mode rejected", [] {
        for(int kind=0;kind<5;++kind) {
            Temp t; FileStore s(t.root,binding,key); initialize(s); auto original=read(t.record()); fs::remove(t.record());
            if(kind==0) fs::create_symlink(t.root/"absent",t.record());
            if(kind==1) {write(t.root/"outside",original); fs::create_hard_link(t.root/"outside",t.record());}
            if(kind==2) CHECK(::mkfifo(t.record().c_str(),0600)==0);
            if(kind==3) fs::create_directory(t.record());
            if(kind==4) {write(t.record(),original); CHECK(::chmod(t.record().c_str(),0644)==0);}
            auto lease=s.lock(); rejects(ErrorCode::UnsafePath,[&]{s.load();});
            rejects(ErrorCode::AlreadyInitialized,[&]{s.initialize();});
        }
    });
    test("lock symlink, FIFO and nonempty file never opened as content", [] {
        for(int kind=0;kind<3;++kind) {
            Temp t; if(kind==0) fs::create_symlink(t.root/"absent",t.lock());
            if(kind==1) CHECK(::mkfifo(t.lock().c_str(),0600)==0);
            if(kind==2) write(t.lock(),Bytes{1});
            FileStore s(t.root,binding,key); rejects(ErrorCode::UnsafePath,[&]{s.lock();});
        }
    });
    test("legacy state directory never silently initialized", [] {
        Temp t; write(t.root/"pending-import.json",Bytes{'x'}); FileStore s(t.root,binding,key); auto lease=s.lock();
        rejects(ErrorCode::InvalidRecord,[&]{s.initialize();}); CHECK(!fs::exists(t.record()));
    });
    test("wrong key and corrupted record never reset", [] {
        Temp t; {FileStore s(t.root,binding,key); initialize(s);} auto saved=read(t.record());
        auto k=key; k[0]^=1; FileStore wrong(t.root,binding,k); auto lease=wrong.lock();
        rejects(ErrorCode::AuthenticationFailed,[&]{wrong.load();}); rejects(ErrorCode::AlreadyInitialized,[&]{wrong.initialize();});
        CHECK(read(t.record())==saved); lease.reset();
        saved.back()^=1; write(t.record(),saved); FileStore s(t.root,binding,key); lease=s.lock();
        rejects(ErrorCode::AuthenticationFailed,[&]{s.load();}); CHECK(read(t.record())==saved);
    });
    test("oversized file rejected before allocation", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); fs::resize_file(t.record(),1024*1024);
        st::Limits limits; limits.recordBytes=1024; FileStore bounded(t.root,binding,key,limits); auto lease=bounded.lock();
        rejects(ErrorCode::SizeLimit,[&]{bounded.load();});
    });
    test("lock replacement invalidates lease before any write", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock(); auto saved=read(t.record());
        fs::remove(t.lock()); write(t.lock(),{}); rejects(ErrorCode::Changed,[&]{s.commit(empty(),pending());}); CHECK(read(t.record())==saved);
    });
    test("root relocation invalidates pinned directory", [] {
        Temp t; auto p=t.root/"private"; fs::create_directory(p); CHECK(::chmod(p.c_str(),0700)==0);
        FileStore s(p,binding,key); initialize(s); auto lease=s.lock(); fs::rename(p,t.root/"moved"); fs::create_directory(p);
        rejects(ErrorCode::Changed,[&]{s.load();}); CHECK(fs::is_empty(p));
    });
    test("file replacement and mutation during reads detected", [] {
        for(auto point:{Point::ReadPinned,Point::ReadComplete}) {
            Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock();
            on(point,[&]{auto b=read(t.record()); fs::remove(t.record()); write(t.record(),b);});
            rejects(ErrorCode::Changed,[&]{s.load();});
        }
    });
    test("rejected writes leave old record and no plaintext staging", [] {
        for(auto point:{Point::StageSynced,Point::StageLinked,Point::BeforePublish}) {
            Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock(); const auto saved=read(t.record());
            on(point,[]{throw st::Error(ErrorCode::Io,"Injected");}); rejects(ErrorCode::Io,[&]{s.commit(empty(),pending());});
            CHECK(read(t.record())==saved); CHECK(std::distance(fs::directory_iterator(t.root),fs::directory_iterator())==2);
        }
    });
    test("post-rename failure retains authenticated new record", [] {
        for(auto point:{Point::Published,Point::DirectorySynced}) {
            Temp t; {FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock();
                on(point,[]{throw st::Error(ErrorCode::Io,"Injected");}); rejects(ErrorCode::CommitUnconfirmed,[&]{s.commit(empty(),pending());});}
            FileStore reopened(t.root,binding,key); auto lease=reopened.lock(); CHECK(eq(reopened.load(),pending()));
        }
    });
    test("CAS rechecks old inode immediately before rename", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock();
        on(Point::BeforePublish,[&]{const auto b=read(t.record()); fs::remove(t.record()); write(t.record(),b);});
        rejects(ErrorCode::Changed,[&]{s.commit(empty(),pending());}); CHECK(eq(s.load(),empty()));
    });
    test("process termination at five commit points yields complete old or new record", [] {
        for(auto point:{Point::StageSynced,Point::StageLinked,Point::BeforePublish,Point::Published,Point::DirectorySynced}) {
            Temp t; {FileStore s(t.root,binding,key); initialize(s);}
            auto pid=::fork(); CHECK(pid>=0);
            if(!pid) {FileStore child(t.root,binding,key); auto lease=child.lock(); on(point,[]{::_exit(73);}); child.commit(empty(),pending()); ::_exit(9);}
            int result; CHECK(::waitpid(pid,&result,0)==pid); CHECK(WIFEXITED(result)&&WEXITSTATUS(result)==73);
            st::testing::hook={}; FileStore reopened(t.root,binding,key); auto lease=reopened.lock(); CHECK(lease);
            const bool after=point==Point::Published || point==Point::DirectorySynced;
            CHECK(eq(reopened.load(),after?pending():empty()));
        }
    });
    test("competing processes serialize and stale full records fail", [] {
        Temp t; {FileStore s(t.root,binding,key); initialize(s);}
        int ready[2],go[2]; CHECK(::pipe(ready)==0); CHECK(::pipe(go)==0); auto pid=::fork(); CHECK(pid>=0);
        if(!pid) {::close(ready[0]); ::close(go[1]); FileStore c(t.root,binding,key); auto lease=c.lock(); CHECK(lease);
            CHECK(::write(ready[1],"x",1)==1); char ch; CHECK(::read(go[0],&ch,1)==1); c.commit(empty(),pending()); ::_exit(0);}
        ::close(ready[1]); ::close(go[0]); char ch; CHECK(::read(ready[0],&ch,1)==1);
        FileStore parent(t.root,binding,key); CHECK(!parent.lock()); CHECK(::write(go[1],"x",1)==1);
        ::close(ready[0]); ::close(go[1]); int result; CHECK(::waitpid(pid,&result,0)==pid); CHECK(WIFEXITED(result)&&WEXITSTATUS(result)==0);
        auto lease=parent.lock(); CHECK(lease); rejects(ErrorCode::Stale,[&]{parent.commit(empty(),pending());}); CHECK(eq(parent.load(),pending()));
    });
    test("coordinator recovery uses real encrypted disk store", [] {
        for(auto mode:{tx::Recovery::AcceptTarget,tx::Recovery::RetryImport,tx::Recovery::RestoreOriginal}) {
            Temp t; {FileStore s(t.root,binding,key); prepare(s);}
            FileStore s(t.root,binding,key); Clipboard clipboard;
            if(mode!=tx::Recovery::RetryImport) clipboard.data=target().snapshot;
            tx::Importer engine(binding,s,clipboard); const auto result=engine.recover(mode);
            auto lease=s.lock(); auto r=s.load(); CHECK(!r.pending);
            if(mode==tx::Recovery::RestoreOriginal) {CHECK(result==tx::Result::Restored); CHECK(!r.head); CHECK(clipboard.data.empty());}
            else {CHECK(result==tx::Result::Applied); CHECK(r.head); CHECK(clipboard.data==target().snapshot);}
        }
    });
    test("recovery never discards manual post-failure changes", [] {
        Temp t; FileStore s(t.root,binding,key); prepare(s); Clipboard c; c.data={{{"text/plain",Bytes{'x'}}}};
        tx::Importer engine(binding,s,c);
        for(auto mode:{tx::Recovery::AcceptTarget,tx::Recovery::RetryImport,tx::Recovery::RestoreOriginal}) {
            bool refused=false; try {engine.recover(mode);} catch(const tx::Error &e){CHECK(e.code()==tx::ErrorCode::LocalChanges);refused=true;}
            CHECK(refused); CHECK(c.writes==0); auto lease=s.lock(); CHECK(eq(s.load(),pending()));
        }
    });
    test("disk-persisted restore intent survives failure before clipboard write", [] {
        Temp t; FileStore s(t.root,binding,key); prepare(s); Clipboard c; c.data=target().snapshot; tx::Importer engine(binding,s,c);
        on(Point::Published,[]{throw st::Error(ErrorCode::Io,"Injected restore intent acknowledgement loss");});
        rejects(ErrorCode::CommitUnconfirmed,[&]{engine.recover(tx::Recovery::RestoreOriginal);}); CHECK(c.writes==0);
        {auto lease=s.lock(); CHECK(s.load().pending->phase==tx::Phase::Restore);}
        CHECK(engine.recover(tx::Recovery::RestoreOriginal)==tx::Result::Restored); CHECK(c.data.empty());
    });
    test("completion acknowledgement loss does not reapply recovered target", [] {
        Temp t; FileStore s(t.root,binding,key); prepare(s); Clipboard c; tx::Importer engine(binding,s,c);
        on(Point::Published,[]{throw st::Error(ErrorCode::Io,"Injected completion acknowledgement loss");});
        rejects(ErrorCode::CommitUnconfirmed,[&]{engine.recover(tx::Recovery::RetryImport);}); CHECK(c.writes==1);
        {auto lease=s.lock(); auto r=s.load(); CHECK(!r.pending); CHECK(r.head);}
        bool refused=false; try {engine.recover(tx::Recovery::RetryImport);} catch(const tx::Error &e){CHECK(e.code()==tx::ErrorCode::NoPending);refused=true;}
        CHECK(refused); CHECK(c.writes==1);
    });
    test("same-size state mutation with restored mtime detected", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock();
        struct stat before{}; CHECK(::stat(t.record().c_str(),&before)==0);
        on(Point::ReadComplete,[&]{auto b=read(t.record()); b.back()^=1; write(t.record(),b);
            const timespec times[]{before.st_atim,before.st_mtim}; CHECK(::utimensat(AT_FDCWD,t.record().c_str(),times,0)==0);});
        rejects(ErrorCode::Changed,[&]{s.load();});
    });
    test("staging mutation is rejected before replacing authoritative state", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock(); const auto saved=read(t.record());
        on(Point::StageLinked,[&]{for(const auto &entry:fs::directory_iterator(t.root)) {
            if(entry.path().extension()!=".tmp") continue;
            struct stat before{}; CHECK(::stat(entry.path().c_str(),&before)==0);
            auto b=read(entry.path()); b.back()^=1; write(entry.path(),b);
            const timespec times[]{before.st_atim,before.st_mtim}; CHECK(::utimensat(AT_FDCWD,entry.path().c_str(),times,0)==0);
        }});
        rejects(ErrorCode::Changed,[&]{s.commit(empty(),pending());}); CHECK(read(t.record())==saved);
    });
    test("post-publish mutation is unconfirmed and never reset", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock();
        on(Point::Published,[&]{struct stat before{}; CHECK(::stat(t.record().c_str(),&before)==0);
            auto b=read(t.record()); b.back()^=1; write(t.record(),b);
            const timespec times[]{before.st_atim,before.st_mtim}; CHECK(::utimensat(AT_FDCWD,t.record().c_str(),times,0)==0);});
        rejects(ErrorCode::CommitUnconfirmed,[&]{s.commit(empty(),pending());});
        rejects(ErrorCode::AuthenticationFailed,[&]{s.load();}); rejects(ErrorCode::AlreadyInitialized,[&]{s.initialize();});
    });
    test("initialization failure is explicit and leaves missing or complete state", [] {
        for(auto point:{Point::StageSynced,Point::BeforePublish,Point::Published,Point::DirectorySynced}) {
            Temp t; {FileStore s(t.root,binding,key); auto lease=s.lock();
                on(point,[]{throw st::Error(ErrorCode::Io,"Injected initialization failure");});
                const bool after=point==Point::Published||point==Point::DirectorySynced;
                rejects(after?ErrorCode::CommitUnconfirmed:ErrorCode::Io,[&]{s.initialize();});}
            FileStore reopened(t.root,binding,key); auto lease=reopened.lock(); CHECK(lease);
            if(point==Point::Published||point==Point::DirectorySynced) CHECK(eq(reopened.load(),empty()));
            else {rejects(ErrorCode::Missing,[&]{reopened.load();}); CHECK(!fs::exists(t.record()));}
        }
    });
    test("hardlinked lock and broad lock permissions are rejected", [] {
        Temp t; write(t.lock(),{}); fs::create_hard_link(t.lock(),t.root/"alias");
        FileStore s(t.root,binding,key); rejects(ErrorCode::UnsafePath,[&]{s.lock();}); fs::remove(t.root/"alias");
        CHECK(::chmod(t.lock().c_str(),0644)==0); rejects(ErrorCode::UnsafePath,[&]{s.lock();});
    });
    test("generation exhaustion does not overwrite persisted record", [] {
        Temp t; auto r=empty(); r.generation=std::numeric_limits<std::uint64_t>::max();
        write(t.record(),st::seal(key,binding,r)); FileStore s(t.root,binding,key); auto lease=s.lock();
        rejects(ErrorCode::Generation,[&]{s.commit(r,empty());}); CHECK(eq(s.load(),r));
    });
    test("300 refused loads do not leak file descriptors", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock();
        auto b=read(t.record()); b.back()^=1; write(t.record(),b);
        const auto count=[] {return std::distance(fs::directory_iterator("/proc/self/fd"),fs::directory_iterator());};
        const auto before=count(); for(int i=0;i<300;++i) rejects(ErrorCode::AuthenticationFailed,[&]{s.load();}); CHECK(count()==before);
    });
    test("invalid key/binding/configuration fails before lock creation", [] {
        Temp t; rejects(ErrorCode::InvalidKey,[&]{FileStore s(t.root,binding,Bytes(31));});
        rejects(ErrorCode::WrongBinding,[&]{FileStore s(t.root,"../bad",key);});
        st::Limits limits; limits.recordBytes=0; rejects(ErrorCode::InvalidLimits,[&]{FileStore s(t.root,binding,key,limits);});
        CHECK(fs::is_empty(t.root));
    });
    test("same-instance contention during disk work fails instead of waiting", [] {
        Temp t; FileStore s(t.root,binding,key); initialize(s); auto lease=s.lock();
        on(Point::ReadComplete,[&]{std::thread t2([&]{CHECK(!s.lock()); rejects(ErrorCode::Busy,[&]{s.load();});}); t2.join();});
        CHECK(eq(s.load(),empty()));
    });
    test("atomic key/password/binding transition preserves contents and enforces CAS", [] {
        Temp t; FileStore s(t.root,binding,key); prepare(s); auto lease=s.lock(); auto previous=s.load();
        auto next=previous; ++next.generation; next.binding="NewVaultBinding";
        const Bytes password{'p','u','b','l','i','c','-','f','i','x','t','u','r','e'};
        s.transition(previous,next,password,st::Protection::Password); CHECK(eq(s.load(),next));
        rejects(ErrorCode::WrongBinding,[&]{s.transition(previous,next,key);});
        lease.reset(); FileStore reloaded(t.root,next.binding,password,{},st::Protection::Password);
        auto l=reloaded.lock(); CHECK(eq(reloaded.load(),next)); l.reset();
        FileStore old(t.root,binding,key); auto oldLease=old.lock(); anyBad([&]{old.load();});
    });
    test("key transition interruption preserves an old or new complete record", [] {
        for(auto point:{Point::StageSynced,Point::StageLinked,Point::BeforePublish,Point::Published,Point::DirectorySynced}) {
            Temp t; { FileStore s(t.root,binding,key); prepare(s); }
            const Bytes changed(32,0x71);
            const auto child=::fork(); CHECK(child>=0);
            if(!child) { FileStore s(t.root,binding,key); auto lease=s.lock(); const auto before=s.load(); auto next=before; ++next.generation;
                on(point,[]{::_exit(86);}); s.transition(before,next,changed); ::_exit(99); }
            int status=0; CHECK(::waitpid(child,&status,0)==child); CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==86);
            const bool published=point==Point::Published||point==Point::DirectorySynced;
            FileStore loaded(t.root,binding,published?changed:key); auto lease=loaded.lock();
            const auto r=loaded.load(); CHECK(r.generation==(published?2U:1U)); CHECK(r.pending.has_value());
        }
    });
    std::cout << cases << " private state scenarios passed\n";
}
