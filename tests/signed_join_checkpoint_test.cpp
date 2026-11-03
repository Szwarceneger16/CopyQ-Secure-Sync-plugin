// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_join_checkpoint.h"
#include "packed_items.h"
#include "test_check.h"

#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <thread>

#if defined(__linux__) && defined(CQS_STATE_TESTING)
#include "state_hooks.h"
namespace cqs::state::testing { std::function<void(Point)> hook; }
#endif

using namespace cqs::trust;
using cqs::crypto::Bytes;
namespace fs = std::filesystem;
namespace st = cqs::state;
namespace tx = cqs::transaction;

#ifdef __linux__
namespace {
const Bytes key(32, 0x45); // Public synthetic test key.
const std::string profile = "signed-join-test-profile";
const std::vector<std::string> validItems{"/////gAAAAEAAAACADQAAAAAA2FiYw=="};

struct Temp {
    fs::path directory;
    Temp() {
        char name[] = "/tmp/cqs-signed-join-checkpoint-XXXXXX";
        const auto *path = ::mkdtemp(name);
        CHECK(path);
        directory = path;
    }
    ~Temp() {
        std::error_code ignored;
        fs::remove_all(directory, ignored);
    }
};

Token token(std::uint8_t value) {
    Token result{};
    result.back() = value;
    return result;
}

JoinActivation activation() {
    return {profile, token(1), token(2), token(3), token(4), token(5), 0,
            "daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000000000001"};
}

cqs::events::Event event(const JoinActivation &proof, const std::vector<std::string> &items = validItems) {
    return {{proof.tipId, proof.tipId.substr(0, 32), 1, {}}, items, 0};
}

std::string revision(std::uint64_t sequence) {
    return cqs::history::makeId(activation().tipId.substr(0, 32), sequence);
}

SignedReplicaState mergeIntent(SignedReplicaState replica, std::uint64_t sequence) {
    replica.pending = SignedReplicaIntent{sequence, token(11),
        {{revision(2), token(12)}, {revision(3), token(13)}}, token(14), revision(3)};
    return replica;
}

Bytes disk(const fs::path &directory) {
    std::ifstream input(directory / st::FileStore::RecordName, std::ios::binary);
    CHECK(input.good());
    return {std::istreambuf_iterator<char>(input), {}};
}

template<class F>
void rejects(st::ErrorCode expected, F &&run) {
    bool refused = false;
    try {
        run();
    } catch (const st::Error &error) {
        CHECK(error.code() == expected);
        refused = true;
    }
    CHECK(refused);
}
} // namespace
#endif

int main() {
#ifdef __linux__
    const auto proof = activation();
    const auto tip = event(proof);
    const auto snapshot = cqs::packed::decode(validItems);
    {
        Temp temp;
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        rejects(st::ErrorCode::Missing, [&] { (void)checkpoint.read(proof); });
        rejects(st::ErrorCode::Missing, [&] { (void)checkpoint.mount(proof); });
        CHECK(!fs::exists(temp.directory / st::FileStore::RecordName));
        checkpoint.apply(proof, tip, snapshot);
        const auto initial = disk(temp.directory);
        SignedJoinCheckpoint reopened(temp.directory, key, profile);
        CHECK(reopened.read(proof) == snapshot);
        reopened.apply(proof, tip, snapshot);
        const auto repeated = disk(temp.directory);
        CHECK(initial != repeated);
        CHECK(reopened.read(proof) == snapshot);

        auto changed = proof;
        changed.tipDigest = token(6);
        rejects(st::ErrorCode::InvalidRecord, [&] { reopened.apply(changed, tip, snapshot); });
        rejects(st::ErrorCode::InvalidRecord, [&] { (void)reopened.read(changed); });
        rejects(st::ErrorCode::InvalidRecord, [&] { (void)reopened.mount(changed); });
        const tx::Snapshot empty;
        rejects(st::ErrorCode::InvalidRecord, [&] { reopened.apply(proof, event(proof, {}), empty); });
        CHECK(disk(temp.directory) == repeated);

        st::FileStore profileSession(temp.directory, profile, key, {}, st::Protection::Key, st::LeaseKind::Session);
        const auto owner = profileSession.lock();
        CHECK(owner);
        rejects(st::ErrorCode::Busy, [&] { reopened.apply(proof, tip, snapshot); });
        CHECK(disk(temp.directory) == repeated);
    }
    {
        Temp temp;
        std::unique_ptr<SignedJoinCheckpoint::Mounted> mounted;
        {
            SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
            checkpoint.apply(proof, tip, snapshot);
            mounted = checkpoint.mount(proof);
        }
        SignedJoinCheckpoint reopened(temp.directory, key, profile);
        CHECK(mounted->generation() == 1);
        CHECK(mounted->snapshot() == snapshot);
        CHECK(mounted->replica().cursor.id == proof.tipId && mounted->replica().cursor.digest == proof.tipDigest);
        CHECK(!mounted->replica().pending);
        const auto initial = disk(temp.directory);
        rejects(st::ErrorCode::Busy, [&] { (void)reopened.mount(proof); });
        rejects(st::ErrorCode::Busy, [&] { reopened.apply(proof, tip, snapshot); });
        rejects(st::ErrorCode::Busy, [&] { (void)reopened.read(proof); });
        const tx::Snapshot edit{{{"text/plain", Bytes{0x00, 0x7f, 0xff}}, {"text/html", Bytes{'<', '>'}}}};
        rejects(st::ErrorCode::Stale, [&] { mounted->save(edit, 0); });
        mounted->save(snapshot, 1);
        CHECK(mounted->generation() == 1);
        CHECK(disk(temp.directory) == initial);

        // The session remains held even when the short record operation runs on another thread.
        std::exception_ptr workerFailure;
        std::thread worker([&] {
            try {
                mounted->save(edit, 1);
            } catch (...) {
                workerFailure = std::current_exception();
            }
        });
        worker.join();
        if (workerFailure) std::rethrow_exception(workerFailure);
        CHECK(mounted->snapshot() == edit);
        CHECK(mounted->generation() == 2);
        const auto saved = disk(temp.directory);
        CHECK(saved != initial);
        rejects(st::ErrorCode::Stale, [&] { mounted->save(snapshot, 1); });
        CHECK(disk(temp.directory) == saved);
        mounted.reset();

        CHECK(reopened.read(proof) == snapshot);
        reopened.apply(proof, tip, snapshot);
        CHECK(reopened.read(proof) == snapshot);
        mounted = reopened.mount(proof);
        CHECK(mounted->snapshot() == edit);
        CHECK(mounted->generation() == 3);
        CHECK(mounted->replica().cursor.id == proof.tipId && mounted->replica().cursor.digest == proof.tipDigest);
        CHECK(!mounted->replica().pending);
        const tx::Snapshot empty;
        mounted->save(empty, 3);
        CHECK(mounted->generation() == 4);
        mounted.reset();
        CHECK(reopened.read(proof) == snapshot);
        mounted = reopened.mount(proof);
        CHECK(mounted->snapshot().empty());

        // A previously authenticated ciphertext must not roll back a live mount.
        {
            std::ofstream restored(temp.directory / st::FileStore::RecordName, std::ios::binary | std::ios::trunc);
            restored.write(reinterpret_cast<const char *>(saved.data()), saved.size());
            CHECK(restored.good());
        }
        rejects(st::ErrorCode::Stale, [&] { mounted->save(empty, 4); });
        rejects(st::ErrorCode::Stale, [&] { mounted->save(snapshot, 4); });
        CHECK(disk(temp.directory) == saved);
    }
    {
        Temp temp;
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        checkpoint.apply(proof, tip, snapshot);
        auto mounted = checkpoint.mount(proof);
        auto pending = mounted->replica();
        const tx::Snapshot edit{{{"text/plain", Bytes{'e', 'd', 'i', 't'}}}};
        pending.pending = SignedReplicaIntent{1, token(7)};
        mounted->updateReplica(pending, edit, 1);
        CHECK(mounted->generation() == 2 && mounted->snapshot() == edit);
        const auto reserved = disk(temp.directory);
        mounted->updateReplica(pending, edit, 2);
        CHECK(mounted->generation() == 2 && disk(temp.directory) == reserved);
        rejects(st::ErrorCode::Stale, [&] { mounted->updateReplica(pending, snapshot, 1); });
        for (auto invalid : {SignedReplicaState{{"wrong", proof.tipDigest}, {}},
                             SignedReplicaState{{proof.tipId, {}}, {}},
                             SignedReplicaState{pending.cursor, SignedReplicaIntent{0, token(7)}},
                             SignedReplicaState{pending.cursor, SignedReplicaIntent{cqs::history::MaxSequence + 1, token(7)}},
                             SignedReplicaState{pending.cursor, SignedReplicaIntent{1, {}}}}) {
            rejects(st::ErrorCode::InvalidRecord, [&] { mounted->updateReplica(invalid, edit, 2); });
        }
        CHECK(disk(temp.directory) == reserved);
        mounted.reset();
        checkpoint.apply(proof, tip, snapshot);
        mounted = checkpoint.mount(proof);
        CHECK(mounted->generation() == 3 && mounted->snapshot() == edit);
        CHECK(mounted->replica().pending && mounted->replica().pending->sequence == 1 &&
              mounted->replica().pending->payload == token(7));

        const tx::Snapshot later{{{"text/plain", Bytes{'l', 'a', 't', 'e', 'r'}}}};
        mounted->save(later, 3);
        CHECK(mounted->replica().pending && mounted->replica().pending->payload == token(7));
        const SignedReplicaState accepted{{"daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000000000002", token(8)}, {}};
        mounted->updateReplica(accepted, mounted->snapshot(), 4);
        mounted.reset();
        CHECK(checkpoint.read(proof) == snapshot);
        mounted = checkpoint.mount(proof);
        CHECK(mounted->generation() == 5 && mounted->snapshot() == later);
        CHECK(mounted->replica().cursor.id == accepted.cursor.id &&
              mounted->replica().cursor.digest == accepted.cursor.digest && !mounted->replica().pending);
    }
    {
        Temp temp;
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        checkpoint.apply(proof, tip, snapshot);
        auto mounted = checkpoint.mount(proof);
        const tx::Snapshot local{{{"text/plain", Bytes{'l', 'o', 'c', 'a', 'l'}}}};
        const tx::Snapshot remote{{{"text/plain", Bytes{'r', 'e', 'm', 'o', 't', 'e'}}}};
        mounted->save(local, 1);
        const auto pending = mergeIntent(mounted->replica(), 4);
        const auto before = disk(temp.directory);
        for (unsigned invalid = 0; invalid != 6; ++invalid) {
            auto wrong = pending;
            auto &intent = *wrong.pending;
            switch (invalid) {
            case 0: intent.localBefore = {}; break;
            case 1: intent.selectedTip = revision(8); break;
            case 2: intent.mergeParents[0].digest = {}; break;
            case 3: std::swap(intent.mergeParents[0], intent.mergeParents[1]); break;
            case 4: intent.mergeParents.push_back({revision(4), token(16)}); break;
            case 5: intent.mergeParents.clear(); break;
            }
            rejects(st::ErrorCode::InvalidRecord, [&] { mounted->updateReplica(wrong, local, 2); });
        }
        rejects(st::ErrorCode::InvalidRecord, [&] { mounted->updateReplica(pending, remote, 2); });
        CHECK(disk(temp.directory) == before && mounted->conflictBackupCount() == 0);

        mounted->checkConflictBackupCapacity(remote);
        CHECK(disk(temp.directory) == before);
        mounted->updateReplica(pending, local, 2);
        const auto staged = disk(temp.directory);
        CHECK(mounted->conflictBackupCount() == 1 && mounted->conflictBackup(0) == local);
        rejects(st::ErrorCode::InvalidRecord, [&] { mounted->restoreConflictBackup(0, 3); });
        rejects(st::ErrorCode::InvalidRecord, [&] { mounted->discardConflictBackup(0, 3); });
        rejects(st::ErrorCode::InvalidRecord, [&] { mounted->checkConflictBackupCapacity(remote); });
        CHECK(disk(temp.directory) == staged);
        mounted.reset();

        mounted = checkpoint.mount(proof);
        const auto &read = *mounted->replica().pending;
        CHECK(read.mergeParents.size() == 2 && read.mergeParents[0].id == revision(2) &&
              read.mergeParents[0].digest == token(12) && read.mergeParents[1].id == revision(3) &&
              read.mergeParents[1].digest == token(13) && read.localBefore == token(14) &&
              read.selectedTip == revision(3));
        mounted->updateReplica(pending, local, 3);
        CHECK(mounted->generation() == 3 && disk(temp.directory) == staged);
        const SignedReplicaState published{{revision(4), token(17)}, {}};
        mounted->updateReplica(published, remote, 3);
        CHECK(mounted->snapshot() == remote && mounted->conflictBackupCount() == 1);
        rejects(st::ErrorCode::Stale, [&] { mounted->restoreConflictBackup(0, 3); });
        mounted->restoreConflictBackup(0, 4);
        CHECK(mounted->snapshot() == local && mounted->conflictBackup(0) == remote);
        CHECK(mounted->replica().cursor.id == revision(4));
        mounted.reset();

        CHECK(checkpoint.read(proof) == snapshot);
        checkpoint.apply(proof, tip, snapshot);
        mounted = checkpoint.mount(proof);
        CHECK(mounted->snapshot() == local && mounted->conflictBackup(0) == remote);
        rejects(st::ErrorCode::InvalidRecord, [&] { (void)mounted->conflictBackup(1); });
        mounted->discardConflictBackup(0, mounted->generation());
        CHECK(mounted->snapshot() == local && mounted->conflictBackupCount() == 0);
    }
    {
        Temp temp;
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        checkpoint.apply(proof, tip, snapshot);
        auto mounted = checkpoint.mount(proof);
        for (std::uint64_t i = 4; i != 7; ++i) {
            const auto pending = mergeIntent(mounted->replica(), i);
            const tx::Snapshot next{{{"text/plain", Bytes{static_cast<std::uint8_t>(i)}}}};
            mounted->checkConflictBackupCapacity(next);
            mounted->updateReplica(pending, mounted->snapshot(), mounted->generation());
            mounted->updateReplica({{revision(i), token(18)}, {}}, next, mounted->generation());
        }
        CHECK(mounted->conflictBackupCount() == 3);
        const auto full = disk(temp.directory);
        rejects(st::ErrorCode::SizeLimit, [&] { mounted->checkConflictBackupCapacity(snapshot); });
        const auto fourth = mergeIntent(mounted->replica(), 7);
        rejects(st::ErrorCode::SizeLimit, [&] {
            mounted->updateReplica(fourth, mounted->snapshot(), mounted->generation());
        });
        CHECK(disk(temp.directory) == full && !mounted->replica().pending);
        mounted->discardConflictBackup(0, mounted->generation());
        mounted->checkConflictBackupCapacity(snapshot);
    }
    {
        Temp temp;
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        const tx::Snapshot empty;
        checkpoint.apply(proof, event(proof, {}), empty);
        CHECK(checkpoint.read(proof).empty());
        const auto original = disk(temp.directory);
        SignedJoinCheckpoint foreign(temp.directory, Bytes(32, 0x33), profile);
        rejects(st::ErrorCode::AuthenticationFailed, [&] { foreign.apply(proof, event(proof, {}), empty); });
        rejects(st::ErrorCode::AuthenticationFailed, [&] { (void)foreign.mount(proof); });
        CHECK(disk(temp.directory) == original);
        Temp relocated;
        CHECK(fs::copy_file(temp.directory / st::FileStore::RecordName,
                            relocated.directory / st::FileStore::RecordName));
        SignedJoinCheckpoint moved(relocated.directory, key, profile);
        rejects(st::ErrorCode::AuthenticationFailed, [&] { (void)moved.read(proof); });
    }
    {
        Temp temp;
        const auto unrelated = temp.directory / "existing-state";
        std::ofstream(unrelated) << "preserve";
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        rejects(st::ErrorCode::InvalidRecord, [&] { checkpoint.apply(proof, tip, snapshot); });
        CHECK(fs::exists(unrelated));
        CHECK(!fs::exists(temp.directory / st::FileStore::RecordName));
    }
#ifdef CQS_STATE_TESTING
    {
        Temp temp;
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        checkpoint.apply(proof, tip, snapshot);
        auto mounted = checkpoint.mount(proof);
        const auto pending = mergeIntent(mounted->replica(), 4);
        mounted->checkConflictBackupCapacity(snapshot);
        st::testing::hook = [](st::testing::Point point) {
            if (point == st::testing::Point::Published) throw std::runtime_error("Interrupted backup commit");
        };
        rejects(st::ErrorCode::CommitUnconfirmed, [&] { mounted->updateReplica(pending, snapshot, 1); });
        st::testing::hook = {};
        CHECK(!mounted->replica().pending && mounted->conflictBackupCount() == 0);
        mounted.reset();

        mounted = checkpoint.mount(proof);
        CHECK(mounted->replica().pending && mounted->conflictBackupCount() == 1);
        CHECK(mounted->conflictBackup(0) == snapshot && mounted->generation() == 2);
        mounted->updateReplica(pending, snapshot, 2);
        CHECK(mounted->conflictBackupCount() == 1 && mounted->generation() == 2);
    }
    {
        Temp temp;
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        checkpoint.apply(proof, tip, snapshot);
        auto mounted = checkpoint.mount(proof);
        const tx::Snapshot edit{{{"text/plain", Bytes{'e', 'd', 'i', 't'}}}};
        auto pending = mounted->replica();
        pending.pending = SignedReplicaIntent{5, token(9)};
        st::testing::hook = [](st::testing::Point point) {
            if (point == st::testing::Point::Published) throw std::runtime_error("Interrupted publication");
        };
        rejects(st::ErrorCode::CommitUnconfirmed, [&] { mounted->updateReplica(pending, edit, 1); });
        st::testing::hook = {};
        CHECK(mounted->generation() == 1);
        CHECK(mounted->snapshot() == snapshot);
        CHECK(!mounted->replica().pending);
        const auto interrupted = disk(temp.directory);
        rejects(st::ErrorCode::CommitUnconfirmed, [&] { mounted->save(edit, 1); });
        CHECK(disk(temp.directory) == interrupted);
        mounted.reset();

        CHECK(checkpoint.read(proof) == snapshot);
        mounted = checkpoint.mount(proof);
        CHECK(mounted->generation() == 2);
        CHECK(mounted->snapshot() == edit);
        CHECK(mounted->replica().pending && mounted->replica().pending->sequence == 5 &&
              mounted->replica().pending->payload == token(9));
    }
    {
        Temp temp;
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        for (unsigned attempt = 0; attempt != 2; ++attempt) {
            st::testing::hook = [](st::testing::Point point) {
                if (point == st::testing::Point::Published) throw std::runtime_error("Interrupted publication");
            };
            rejects(st::ErrorCode::CommitUnconfirmed, [&] { checkpoint.apply(proof, tip, snapshot); });
            st::testing::hook = {};
            SignedJoinCheckpoint reopened(temp.directory, key, profile);
            reopened.apply(proof, tip, snapshot);
            CHECK(reopened.read(proof) == snapshot);
        }
    }
#endif
    std::cout << "Signed Join checkpoint tests passed\n";
#else
    std::cout << "Signed Join checkpoint filesystem fixtures require Linux\n";
#endif
}
