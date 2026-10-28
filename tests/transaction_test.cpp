// SPDX-License-Identifier: GPL-3.0-or-later
#include "import_transaction.h"
#include "test_check.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <numeric>
#include <utility>

using namespace cqs::transaction;
namespace {
using Bytes = cqs::crypto::Bytes;
using History = cqs::events::AuthenticatedHistory;
int cases = 0;
struct Interrupted : std::runtime_error { Interrupted() : std::runtime_error("Injected interruption") {} };
struct Faults {
    int at = 0, calls = 0;
    std::vector<std::string> trace;
    std::function<void(const std::string &)> hook;
    void step(const std::string &name) {
        trace.push_back(name);
        if (hook) hook(name);
        if (++calls == at) throw Interrupted();
    }
    void reset(int point = 0) { at = point; calls = 0; trace.clear(); hook = {}; }
};
bool sameHead(const std::optional<Head> &a, const std::optional<Head> &b) {
    if (a.has_value() != b.has_value()) return false;
    if (!a) return true;
    const auto &x = a->event.revision; const auto &y = b->event.revision;
    return x.id == y.id && x.device == y.device && x.sequence == y.sequence && x.parents == y.parents &&
           a->event.items == b->event.items && a->snapshot == b->snapshot;
}
bool sameRecord(const Record &a, const Record &b) {
    if (a.schema != b.schema || a.binding != b.binding || a.generation != b.generation ||
        !sameHead(a.head, b.head) || a.pending.has_value() != b.pending.has_value()) return false;
    return !a.pending || (a.pending->phase == b.pending->phase && a.pending->original == b.pending->original &&
                         sameHead(a.pending->target, b.pending->target));
}
// MODEL ONLY: no plaintext is written to files; durable means the simulated
// crash-surviving copy. This is NOT a production encrypted filesystem adapter.
struct TestStore final : Store {
    Faults &faults;
    Record disk{1, "test-binding", 0, {}, {}};
    bool held = false;
    int writes = 0;
    explicit TestStore(Faults &f) : faults(f) {}
    struct Held final : Lease {
        TestStore &s;
        explicit Held(TestStore &store) : s(store) { s.held = true; }
        ~Held() override { s.held = false; }
    };
    std::unique_ptr<Lease> lock() override {
        if (held) return {};
        return std::make_unique<Held>(*this);
    }
    Record load() override {
        CHECK(held); faults.step("load"); return disk;
    }
    void commit(const Record &expected, const Record &next) override {
        CHECK(held);
        const std::string label = next.pending ?
            (next.pending->phase == Phase::Restore ? "restore-intent" : "prepare") : "commit";
        faults.step(label + ".before");
        CHECK(sameRecord(disk, expected)); CHECK(next.generation == disk.generation + 1);
        disk = next; ++writes;
        faults.step(label + ".after");
    }
};
const Snapshot a{{{"text/plain", {'A', 0, '\r', '\n'}}, {"text/html", {'<', 'b', '>'}},
                  {"application/x-copyq-item-notes", {0xc5, 0xbc}}}};
const Snapshot b{{{"text/plain", {'B'}}}, {{"image/png", {0, 255, 137, 80, 78, 71}}}};
const Snapshot manual{{{"text/plain", {'U', 'S', 'E', 'R'}}}};
struct TestClipboard final : Clipboard {
    TestStore &store;
    Faults &faults;
    Snapshot live, disk;
    std::uint64_t epoch = 0;
    bool editor = false, badDecode = false, badPersist = false, badReplace = false;
    int writes = 0, barriers = 0;
    TestClipboard(TestStore &s, Faults &f) : store(s), faults(f) {}
    Snapshot decode(const std::vector<std::string> &packed, Limits) override {
        faults.step("decode");
        Snapshot out;
        for (const auto &p : packed) {
            // Test serialization tokens, NOT real Qt pack() representations.
            if (p == "QQ==" || p == "YQ==") out.push_back(a[0]);
            else if (p == "Qg==") out.push_back(b[0]);
            else if (p == "Qw==") out.push_back(b[1]);
            else throw Error(ErrorCode::InvalidRecord, "Unsupported test token");
        }
        if (badDecode) out = {};
        return out;
    }
    View capture(Limits) override { faults.step("capture"); return {live, epoch}; }
    void check(const View &expected) {
        if (editor || expected.epoch != epoch || live != expected.snapshot)
            throw Error(ErrorCode::LocalChanges, "Clipboard changed or editor is active");
    }
    View replace(const View &expected, const Snapshot &desired) override {
        CHECK(store.held); CHECK(store.disk.pending.has_value());
        faults.step("replace.before"); check(expected);
        live.clear(); ++epoch; ++writes;
        faults.step("replace.cleared"); // simulate failure after a partial write
        live = badReplace ? manual : desired; ++epoch;
        faults.step("replace.after"); return {live, epoch};
    }
    Snapshot persist(const View &expected, Limits) override {
        CHECK(store.held); CHECK(store.disk.pending.has_value());
        faults.step("persist.before"); check(expected);
        disk = badPersist ? manual : live; ++barriers;
        faults.step("persist.after"); return disk;
    }
    void edit(Snapshot data) { live = std::move(data); ++epoch; }
    void reboot() { live = disk; ++epoch; editor = false; }
};
// Synthetic event generator using a PUBLIC TEST key and fresh test-only nonces.
// All coordinator inputs still pass through the real AES-GCM event decoder/DAG.
std::string base64(const Bytes &data) {
    constexpr char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;
    for (std::size_t i = 0; i < data.size(); i += 3) {
        const unsigned n = (static_cast<unsigned>(data[i]) << 16) |
            (i + 1 < data.size() ? static_cast<unsigned>(data[i + 1]) << 8 : 0U) |
            (i + 2 < data.size() ? data[i + 2] : 0U);
        s += t[(n >> 18) & 63]; s += t[(n >> 12) & 63];
        s += i + 1 < data.size() ? t[(n >> 6) & 63] : '=';
        s += i + 2 < data.size() ? t[n & 63] : '=';
    }
    return s;
}
std::string strings(const std::vector<std::string> &values) {
    std::string s = "[";
    for (const auto &v : values) { if (s.size() > 1) s += ','; s += '"' + v + '"'; }
    return s + ']';
}
struct Wire { std::string id, bytes; };
Bytes testKey() { Bytes k(32); std::iota(k.begin(), k.end(), 0); return k; }
Wire event(std::string device, unsigned seq, std::vector<std::string> parents,
           std::vector<std::string> packed) {
    const auto id = cqs::history::makeId(device, seq);
    const auto header = "{\"device\":\"" + device + "\",\"parents\":" + strings(parents) +
        ",\"protocol\":\"copyq-secure-sync-v1\",\"seq\":" + std::to_string(seq) + '}';
    const auto plain = "{\"items\":" + strings(packed) + ",\"tab\":\"synced_tray\",\"v\":1}";
    constexpr char domain[] = "CopyQ-Secure-Sync-event-v1";
    Bytes aad(domain, domain + sizeof(domain)); aad.insert(aad.end(), header.begin(), header.end());
    const auto nonce = cqs::crypto::random(12);
    const auto compressed = cqs::crypto::zlibCompress(Bytes(plain.begin(), plain.end()));
    const auto cipher = cqs::crypto::aes256GcmEncrypt(testKey(), nonce, compressed, aad);
    return {id, "{\"header\":" + header + ",\"nonce\":\"" + base64(nonce) +
                "\",\"ciphertext\":\"" + base64(cipher) + "\"}"};
}
History history(std::initializer_list<Wire> wires) {
    std::vector<cqs::events::Envelope> input;
    for (const auto &w : wires) input.push_back({w.id, w.bytes});
    return History(testKey(), input);
}
struct Rig {
    Faults faults;
    TestStore store{faults};
    TestClipboard clipboard{store, faults};
    Importer importer{"test-binding", store, clipboard};
    void completed(const std::string &id, const Snapshot &snapshot) {
        CHECK(!store.held); CHECK(!store.disk.pending); CHECK(store.disk.head);
        CHECK(store.disk.head->event.revision.id == id); CHECK(store.disk.head->snapshot == snapshot);
        CHECK(clipboard.live == snapshot); CHECK(clipboard.disk == snapshot);
    }
    void pristine() {
        CHECK(!store.held); CHECK(!store.disk.head); CHECK(!store.disk.pending);
        CHECK(store.writes == 0); CHECK(clipboard.writes == 0); CHECK(clipboard.barriers == 0);
    }
};
void test(const char *name, const std::function<void()> &body) {
    body(); ++cases; std::cout << "PASS " << name << std::endl;
}
void rejects(ErrorCode code, const std::function<void()> &body) {
    bool caught = false;
    try { body(); } catch (const Error &e) { CHECK(e.code() == code); caught = true; }
    CHECK(caught);
}
void interrupted(const std::function<void()> &body) {
    bool caught = false;
    try { body(); } catch (const Interrupted &) { caught = true; }
    CHECK(caught);
}
void arm(Rig &r, const std::string &point) {
    r.faults.reset();
    r.faults.hook = [point](const std::string &p) { if (p == point) throw Interrupted(); };
}
} // namespace
int main() {
    const auto root = event("mint-lab", 1, {}, {"QQ=="});
    const auto child = event("win-lab", 1, {root.id}, {});
    const auto many = event("mint-lab", 2, {root.id}, {"Qg==", "Qw=="});
    const auto hRoot = history({root});
    const auto hChild = history({root, child});
    const auto hMany = history({root, many});
    auto join = [&](Rig &r) { CHECK(r.importer.importTip(hRoot, ImportMode::Join) == Result::Applied); };

    test("empty tab joins and commits only after durable MIME verification", [&] {
        Rig r; join(r); r.completed(root.id, a); CHECK(r.store.writes == 2); CHECK(r.clipboard.barriers == 1);
        const auto &t = r.faults.trace;
        CHECK(std::find(t.begin(), t.end(), "prepare.after") < std::find(t.begin(), t.end(), "replace.before"));
        CHECK(std::find(t.begin(), t.end(), "persist.after") < std::find(t.begin(), t.end(), "commit.before"));
    });
    test("unchanged head is a no-write operation", [&] {
        Rig r; join(r); r.faults.reset(); const int w = r.store.writes;
        CHECK(r.importer.importTip(hRoot, ImportMode::FastForward) == Result::UpToDate);
        CHECK(r.store.writes == w); CHECK(r.clipboard.barriers == 1);
    });
    test("fast-forward to empty snapshot clears exactly the bound tab", [&] {
        Rig r; join(r); CHECK(r.importer.importTip(hChild, ImportMode::FastForward) == Result::Applied);
        r.completed(child.id, {});
    });
    test("an empty root is a valid join and still uses the durability barrier", [&] {
        Rig r; const auto w = event("empty-pc", 1, {}, {}); auto h = history({w});
        CHECK(r.importer.importTip(h, ImportMode::Join) == Result::Applied); r.completed(w.id, {});
        CHECK(r.clipboard.writes == 0); CHECK(r.clipboard.barriers == 1); CHECK(r.store.writes == 2);
    });
    test("local pack serialization is not compared with remote pack bytes", [&] {
        Rig r; const auto other = event("other-pc", 1, {}, {"YQ=="}); auto h = history({other});
        CHECK(r.importer.importTip(h, ImportMode::Join) == Result::Applied); r.completed(other.id, a);
        CHECK(r.importer.importTip(h, ImportMode::FastForward) == Result::UpToDate);
    });
    test("all MIME bytes, binary NUL and item ordering are retained", [&] {
        Rig r; join(r); CHECK(r.clipboard.disk[0].size() == 3);
        CHECK(r.importer.importTip(hMany, ImportMode::FastForward) == Result::Applied); r.completed(many.id, b);
    });
    test("join refuses nonempty local tab without preparing a journal", [&] {
        Rig r; r.clipboard.edit(manual);
        rejects(ErrorCode::LocalChanges, [&] { join(r); }); r.pristine(); CHECK(r.clipboard.live == manual);
    });
    test("dirty local data blocks automatic fast-forward", [&] {
        Rig r; join(r); r.clipboard.edit(manual); const auto before = r.store.disk;
        rejects(ErrorCode::LocalChanges, [&] { r.importer.importTip(hChild, ImportMode::FastForward); });
        CHECK(sameRecord(before, r.store.disk)); CHECK(r.clipboard.live == manual);
    });
    test("explicit join and fast-forward cannot substitute each other", [&] {
        Rig r; rejects(ErrorCode::NotJoined, [&] { r.importer.importTip(hRoot, ImportMode::FastForward); });
        join(r); rejects(ErrorCode::AlreadyJoined, [&] { r.importer.importTip(hRoot, ImportMode::Join); });
    });
    test("empty remote history is not permission to seed", [&] {
        Rig r; auto empty = history({}); rejects(ErrorCode::NoRemote, [&] { r.importer.importTip(empty, ImportMode::Join); });
        r.pristine();
    });
    test("withheld current head blocks import", [&] {
        Rig r; join(r); auto empty = history({});
        rejects(ErrorCode::MissingHead, [&] { r.importer.importTip(empty, ImportMode::FastForward); });
        r.completed(root.id, a);
    });
    test("parallel branches and independent seeds are never automatically resolved", [&] {
        Rig r; auto parallel = history({root, child, many});
        rejects(ErrorCode::Conflict, [&] { r.importer.importTip(parallel, ImportMode::Join); });
        auto independent = history({root, event("other-pc", 1, {}, {})});
        rejects(ErrorCode::Conflict, [&] { r.importer.importTip(independent, ImportMode::Join); }); r.pristine();
    });
    test("accepted event payload cannot be replaced even by equivalent repacking", [&] {
        Rig r; join(r); auto changed = history({event("mint-lab", 1, {}, {"YQ=="})});
        rejects(ErrorCode::Equivocation, [&] { r.importer.importTip(changed, ImportMode::FastForward); });
        r.completed(root.id, a);
    });
    test("key authentication and missing parents are checked before coordinator input exists", [&] {
        Rig r; bool failed = false;
        try { auto badKey = testKey(); badKey[0] ^= 1; History h(badKey, {{root.id, root.bytes}}); }
        catch (const cqs::events::Error &) { failed = true; } CHECK(failed);
        failed = false; try { auto h = history({child}); }
        catch (const cqs::history::Error &) { failed = true; } CHECK(failed); r.pristine();
    });
    test("write refusal keeps backup and blocks another import", [&] {
        Rig r; r.clipboard.editor = true;
        rejects(ErrorCode::LocalChanges, [&] { join(r); }); CHECK(r.store.disk.pending); CHECK(!r.store.disk.head);
        rejects(ErrorCode::PendingRecovery, [&] { join(r); }); CHECK(!r.store.held);
    });
    test("mutations between durable prepare and replacement are not overwritten", [&] {
        Rig r; r.faults.hook = [&](const std::string &p) { if (p == "prepare.after") r.clipboard.edit(manual); };
        rejects(ErrorCode::LocalChanges, [&] { join(r); }); CHECK(r.store.disk.pending);
        CHECK(r.clipboard.live == manual); CHECK(r.clipboard.writes == 0);
    });
    test("ABA edits are caught by the clipboard epoch", [&] {
        Rig r; r.faults.hook = [&](const std::string &p) {
            if (p == "prepare.after") { r.clipboard.edit(manual); r.clipboard.edit({}); }
        };
        rejects(ErrorCode::LocalChanges, [&] { join(r); }); CHECK(r.store.disk.pending); CHECK(r.clipboard.writes == 0);
    });
    test("wrong replacement data never advances head", [&] {
        Rig r; r.clipboard.badReplace = true;
        rejects(ErrorCode::VerificationFailed, [&] { join(r); }); CHECK(r.store.disk.pending); CHECK(!r.store.disk.head);
    });
    test("GUI success is insufficient when the durable snapshot differs", [&] {
        Rig r; r.clipboard.badPersist = true;
        rejects(ErrorCode::VerificationFailed, [&] { join(r); }); CHECK(r.store.disk.pending); CHECK(!r.store.disk.head);
    });
    test("persistence checks the epoch again", [&] {
        Rig r; r.faults.hook = [&](const std::string &p) { if (p == "persist.before") r.clipboard.edit(manual); };
        rejects(ErrorCode::LocalChanges, [&] { join(r); }); CHECK(r.store.disk.pending); CHECK(r.clipboard.disk.empty());
    });
    test("edits after durable import remain local edits, not silently discarded", [&] {
        Rig r; r.faults.hook = [&](const std::string &p) { if (p == "commit.before") r.clipboard.edit(manual); };
        join(r); CHECK(r.store.disk.head->snapshot == a); CHECK(r.clipboard.live == manual);
        r.faults.reset(); rejects(ErrorCode::LocalChanges, [&] { r.importer.importTip(hChild, ImportMode::FastForward); });
    });
    test("no pending journal means no recovery write", [&] {
        Rig r; rejects(ErrorCode::NoPending, [&] { r.importer.recover(Recovery::AcceptTarget); }); r.pristine();
    });
    test("explicit retry after prepared-only failure completes import", [&] {
        Rig r; arm(r, "prepare.after"); interrupted([&] { join(r); }); r.faults.reset();
        CHECK(r.importer.recover(Recovery::RetryImport) == Result::Applied); r.completed(root.id, a);
    });
    test("accept-target refuses to pretend an unapplied target is present", [&] {
        Rig r; arm(r, "prepare.after"); interrupted([&] { join(r); }); r.faults.reset();
        rejects(ErrorCode::VerificationFailed, [&] { r.importer.recover(Recovery::AcceptTarget); });
        CHECK(r.store.disk.pending); CHECK(r.clipboard.live.empty());
    });
    test("accept-target does not reinsert items but does persist them", [&] {
        Rig r; arm(r, "persist.before"); interrupted([&] { join(r); }); const int writes = r.clipboard.writes;
        r.faults.reset(); CHECK(r.importer.recover(Recovery::AcceptTarget) == Result::Applied);
        CHECK(r.clipboard.writes == writes); r.completed(root.id, a);
    });
    test("restore after a failed join returns to unjoined empty state", [&] {
        Rig r; arm(r, "persist.before"); interrupted([&] { join(r); }); r.faults.reset();
        CHECK(r.importer.recover(Recovery::RestoreOriginal) == Result::Restored);
        CHECK(!r.store.disk.pending); CHECK(!r.store.disk.head); CHECK(r.clipboard.disk.empty());
    });
    test("restore after fast-forward preserves previous checkpoint", [&] {
        Rig r; join(r); arm(r, "commit.before");
        interrupted([&] { r.importer.importTip(hMany, ImportMode::FastForward); }); r.faults.reset();
        CHECK(r.importer.recover(Recovery::RestoreOriginal) == Result::Restored); r.completed(root.id, a);
    });
    test("manual data added after failure is protected in every recovery mode", [&] {
        Rig r; arm(r, "prepare.after"); interrupted([&] { join(r); }); r.faults.reset(); r.clipboard.edit(manual);
        const auto before = r.store.disk;
        for (auto action : {Recovery::AcceptTarget, Recovery::RetryImport, Recovery::RestoreOriginal}) {
            rejects(ErrorCode::LocalChanges, [&] { r.importer.recover(action); });
            CHECK(sameRecord(before, r.store.disk)); CHECK(r.clipboard.live == manual);
        }
    });
    test("persisted restore intent cannot be changed into accept or retry", [&] {
        Rig r; arm(r, "persist.before"); interrupted([&] { join(r); }); arm(r, "restore-intent.after");
        interrupted([&] { r.importer.recover(Recovery::RestoreOriginal); }); r.faults.reset();
        CHECK(r.store.disk.pending->phase == Phase::Restore);
        for (auto action : {Recovery::AcceptTarget, Recovery::RetryImport})
            rejects(ErrorCode::WrongPhase, [&] { r.importer.recover(action); });
        CHECK(r.importer.recover(Recovery::RestoreOriginal) == Result::Restored); CHECK(r.clipboard.disk.empty());
    });
    test("store schema and binding mismatch are not treated as initial state", [&] {
        Rig r; r.store.disk.schema = 2;
        rejects(ErrorCode::InvalidRecord, [&] { join(r); }); CHECK(r.store.writes == 0);
        r.store.disk.schema = 1; r.store.disk.binding = "other-binding";
        rejects(ErrorCode::WrongBinding, [&] { join(r); }); CHECK(r.clipboard.writes == 0);
    });
    test("journal backup must correspond to previous head", [&] {
        Rig r; arm(r, "prepare.after"); interrupted([&] { join(r); }); r.faults.reset();
        r.store.disk.pending->original = manual;
        rejects(ErrorCode::InvalidRecord, [&] { r.importer.recover(Recovery::RestoreOriginal); }); CHECK(r.clipboard.writes == 0);
    });
    test("target cannot disagree with decoded MIME content", [&] {
        Rig r; arm(r, "prepare.after"); interrupted([&] { join(r); }); r.faults.reset();
        r.store.disk.pending->target.snapshot = manual;
        rejects(ErrorCode::InvalidRecord, [&] { r.importer.recover(Recovery::RetryImport); }); CHECK(r.clipboard.writes == 0);
    });
    test("unknown transaction phase is rejected", [&] {
        Rig r; arm(r, "prepare.after"); interrupted([&] { join(r); }); r.faults.reset();
        r.store.disk.pending->phase = static_cast<Phase>(7);
        rejects(ErrorCode::InvalidRecord, [&] { r.importer.recover(Recovery::RetryImport); });
    });
    test("generation space is reserved before prepare", [&] {
        Rig r; r.store.disk.generation = std::numeric_limits<std::uint64_t>::max() - 2;
        rejects(ErrorCode::GenerationExhausted, [&] { join(r); }); r.pristine();
    });
    test("invalid bounds are rejected and lowered limits are enforced", [&] {
        Rig r; Limits limits; limits.items++;
        rejects(ErrorCode::InvalidLimits, [&] { Importer i("test-binding", r.store, r.clipboard, limits); });
        limits = {}; limits.items = 0; Importer emptyOnly("test-binding", r.store, r.clipboard, limits);
        rejects(ErrorCode::InvalidRecord, [&] { emptyOnly.importTip(hRoot, ImportMode::Join); }); r.pristine();
        limits = {}; limits.snapshotBytes = 1; Importer tiny("test-binding", r.store, r.clipboard, limits);
        rejects(ErrorCode::InvalidRecord, [&] { tiny.importTip(hRoot, ImportMode::Join); }); r.pristine();
        limits = {}; limits.formatsPerItem = 2; Importer few("test-binding", r.store, r.clipboard, limits);
        rejects(ErrorCode::InvalidRecord, [&] { few.importTip(hRoot, ImportMode::Join); }); r.pristine();
    });
    test("decoder cannot silently drop remote items", [&] {
        Rig r; r.clipboard.badDecode = true;
        rejects(ErrorCode::InvalidRecord, [&] { join(r); }); r.pristine();
    });
    test("missing MIME and empty MIME bytes are not equivalent", [&] {
        Rig r; join(r); auto edited = a; edited[0]["application/test-empty"] = {}; r.clipboard.edit(edited);
        rejects(ErrorCode::LocalChanges, [&] { r.importer.importTip(hChild, ImportMode::FastForward); });
        CHECK(r.clipboard.live == edited);
    });
    test("busy store refuses without invoking the clipboard", [&] {
        Rig r; auto lease = r.store.lock();
        rejects(ErrorCode::Busy, [&] { join(r); }); CHECK(r.faults.trace.empty()); CHECK(r.store.writes == 0);
    });
    test("invalid binding characters are not accepted", [&] {
        Rig r;
        for (const auto &binding : {std::string{}, std::string("a/b"), std::string(129, 'x'), std::string("abc\0", 4)})
            rejects(ErrorCode::WrongBinding, [&] { Importer i(binding, r.store, r.clipboard); });
        r.pristine();
    });
    test("every import failpoint survives both process restart and session reboot", [&] {
        Rig reference; join(reference); const int points = reference.faults.calls;
        for (bool reboot : {false, true}) for (int point = 1; point <= points; ++point) {
            Rig r; r.faults.reset(point); interrupted([&] { join(r); }); CHECK(!r.store.held);
            r.faults.reset(); if (reboot) r.clipboard.reboot();
            Importer restarted("test-binding", r.store, r.clipboard);
            if (r.store.disk.pending) CHECK(restarted.recover(Recovery::RetryImport) == Result::Applied);
            else if (!r.store.disk.head) CHECK(restarted.importTip(hRoot, ImportMode::Join) == Result::Applied);
            else CHECK(restarted.importTip(hRoot, ImportMode::FastForward) == Result::UpToDate);
            r.completed(root.id, a);
        }
        std::cout << "  import interruption boundaries: " << points << " x 2\n";
    });
    test("every restore failpoint preserves rollback intent across a restart", [&] {
        auto failedImport = [&](Rig &r) {
            arm(r, "persist.before"); interrupted([&] { join(r); }); r.faults.reset();
        };
        Rig reference; failedImport(reference); reference.importer.recover(Recovery::RestoreOriginal);
        const int points = reference.faults.calls;
        for (bool reboot : {false, true}) for (int point = 1; point <= points; ++point) {
            Rig r; failedImport(r); r.faults.reset(point);
            interrupted([&] { r.importer.recover(Recovery::RestoreOriginal); }); CHECK(!r.store.held);
            r.faults.reset(); if (reboot) r.clipboard.reboot();
            Importer restarted("test-binding", r.store, r.clipboard);
            if (r.store.disk.pending) CHECK(restarted.recover(Recovery::RestoreOriginal) == Result::Restored);
            CHECK(!r.store.disk.pending); CHECK(!r.store.disk.head); CHECK(r.clipboard.disk.empty());
            CHECK(r.clipboard.live.empty());
        }
        std::cout << "  restore interruption boundaries: " << points << " x 2\n";
    });
    test("a genuinely partial multi-item import requires preserving data before recovery", [&] {
        Rig r; join(r); arm(r, "replace.cleared");
        interrupted([&] { r.importer.importTip(hMany, ImportMode::FastForward); }); r.faults.reset();
        CHECK(r.clipboard.live.empty()); // neither original 'a' nor desired 'b'
        for (auto action : {Recovery::RetryImport, Recovery::RestoreOriginal})
            rejects(ErrorCode::LocalChanges, [&] { r.importer.recover(action); });
        CHECK(r.store.disk.pending); // no destructive guessed rollback
        r.clipboard.reboot(); // real adapter must perform its own safe durable reload
        CHECK(r.importer.recover(Recovery::RestoreOriginal) == Result::Restored); r.completed(root.id, a);
    });
    std::cout << cases << " transaction test cases passed\n";
}
