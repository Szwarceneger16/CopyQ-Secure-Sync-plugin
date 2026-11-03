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
