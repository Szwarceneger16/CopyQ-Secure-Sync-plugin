// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_join_checkpoint.h"
#include "packed_items.h"
#include "test_check.h"

#include <fstream>
#include <iostream>
#include <iterator>

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
        SignedJoinCheckpoint checkpoint(temp.directory, key, profile);
        const tx::Snapshot empty;
        checkpoint.apply(proof, event(proof, {}), empty);
        CHECK(checkpoint.read(proof).empty());
        const auto original = disk(temp.directory);
        SignedJoinCheckpoint foreign(temp.directory, Bytes(32, 0x33), profile);
        rejects(st::ErrorCode::AuthenticationFailed, [&] { foreign.apply(proof, event(proof, {}), empty); });
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
