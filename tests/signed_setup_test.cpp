// SPDX-License-Identifier: GPL-3.0-or-later
#include "signed_setup.h"
#include "device_key_envelope.h"
#include "storage.h"
#include "test_check.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#ifdef _WIN32
#include "windows_test_acl.h"
#endif
#if defined(__linux__) && defined(CQS_STATE_TESTING)
#include "state_hooks.h"
namespace cqs::state::testing { std::function<void(Point)> hook; }
#endif

namespace {
using namespace cqs;
using namespace cqs::trust;
const crypto::Bytes Password{'s','y','n','t','h','e','t','i','c','-','s','e','t','u','p','-','p','a','s','s','w','o','r','d'};
constexpr std::uint64_t Now = 100;

struct Temporary {
    std::filesystem::path root = SignedSetup::createPrivateRoot(std::filesystem::temp_directory_path());
    ~Temporary() { std::error_code ignored; std::filesystem::remove_all(root, ignored); }
    std::filesystem::path privateRoot() const { return SignedSetup::createPrivateRoot(root); }
    std::filesystem::path transport(const std::string &name) const {
        const auto path = root / name;
#ifdef _WIN32
        cqs::testing::directory(path);
#else
        CHECK(std::filesystem::create_directory(path));
        std::filesystem::permissions(path, std::filesystem::perms::owner_all);
#endif
        return path;
    }
};
template<class Action> void refused(Action action) {
    bool rejected = false;
    try { action(); } catch (const std::exception &) { rejected = true; }
    CHECK(rejected);
}
crypto::Bytes read(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    CHECK(input);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
JoinActivation checkHistory(SignedSetup &setup) {
    const auto credential = setup.journalCredential();
    state::FileStore store(setup.paths().journal, TrustJournal::binding(setup.genesis(), setup.member()), credential);
    TrustJournal journal(store, setup.genesis(), setup.member(), setup.founderKey());
    CHECK(journal.inspect().state.members == std::vector<Member>{setup.member()});
    const storage::Directory transport(setup.paths().transport);
    const auto history = journal.scanClipboardEvents(*setup.founderKey(), transport, Now);
    CHECK(history.events.size() == 1 && history.graph.tips().size() == 1);
    CHECK(history.events.front().items.empty() && history.events.front().revision.parents.empty());
    const auto activation = journal.preflightJoinActivation(setup.identity(), transport, "signed-setup-test", Now);
    CHECK(activation.member == setup.member().id && activation.tipId == history.graph.tips().front());
    return activation;
}
} // namespace

int main() {
    Temporary temporary;
    const auto root = temporary.privateRoot();
    const auto transport = temporary.transport("shared");
    auto founder = SignedSetup::createFounder(root, Password, transport, Now);
    CHECK(founder && founder->role() == SignedSetupRole::Founder && founder->founderKey());
    CHECK(founder->paths().root == root && founder->paths().transport == transport);
    CHECK(founder->identity().member() == founder->member());
    const auto activation = checkHistory(*founder);
    const auto invite = SignedSetup::invitation(founder->genesis());
    const auto genesis = SignedSetup::parseInvitation(invite);
    CHECK(SignedSetup::invitation(genesis) == invite);
    CHECK(SignedSetup::fingerprint(genesis) == SignedSetup::fingerprint(founder->genesis()));
    refused([&] { (void)SignedSetup::parseInvitation(invite + 'x'); });
    const auto before = read(root / state::FileStore::RecordName);
    const auto secret = founder->checkpointCredential();
    CHECK(secret.size() == 32 && secret != founder->journalCredential());
    CHECK(std::search(before.begin(), before.end(), secret.begin(), secret.end()) == before.end());
    refused([&] { (void)SignedSetup::createFounder(root, Password, transport, Now); });
    CHECK(read(root / state::FileStore::RecordName) == before);
    CHECK(SignedSetup::unlockCheckpoint(root, Password, activation) == secret);
    refused([&] { (void)SignedSetup::unlockCheckpoint(root, crypto::Bytes(20, 'x'), activation); });
    for (unsigned pin = 0; pin < 3; ++pin) {
        auto wrong = activation;
        (pin == 0 ? wrong.group : pin == 1 ? wrong.root : wrong.member).front() ^= 1;
        refused([&] { (void)SignedSetup::unlockCheckpoint(root, Password, wrong); });
    }
    CHECK(read(root / state::FileStore::RecordName) == before);
    refused([&] { (void)SignedSetup::open(root, crypto::Bytes(20, 'x'), Now); });
    CHECK(read(root / state::FileStore::RecordName) == before);
    // The setup manifest lease is released while unlocked credentials are held.
    auto reopened = SignedSetup::open(root, Password, Now);
    CHECK(reopened->member() == founder->member());
    CHECK(reopened->checkpointCredential() == secret);
    checkHistory(*reopened);
    const auto applicantRoot = temporary.privateRoot();
    refused([&] { (void)SignedSetup::createApplicant(applicantRoot, Password, transport, genesis, Token{}, Now); });
    CHECK(!std::filesystem::exists(applicantRoot / state::FileStore::RecordName));
    auto applicant = SignedSetup::createApplicant(applicantRoot, Password, transport, genesis,
        SignedSetup::fingerprint(genesis), Now);
    CHECK(applicant->role() == SignedSetupRole::Applicant && !applicant->founderKey());
    CHECK(applicant->member() != founder->member());
    const auto applicantCredential = applicant->journalCredential();
    state::FileStore journalStore(applicant->paths().journal, TrustJournal::binding(genesis, applicant->member()), applicantCredential);
    TrustJournal applicantJournal(journalStore, genesis, applicant->member());
    CHECK(applicantJournal.beginJoin(applicant->identity(), Now).applicant == applicant->member());
    const auto vault = root / "identity" / state::FileStore::RecordName;
    std::filesystem::rename(vault, temporary.root / "saved-identity");
    refused([&] { (void)SignedSetup::open(root, Password, Now); });
    CHECK(read(root / state::FileStore::RecordName) == before);
    std::filesystem::rename(temporary.root / "saved-identity", vault);
    // A ready profile never interprets missing remote history as permission to
    // create a second root or silently repair the transport.
    const Membership initialMembership(genesis.group, genesis.founder, genesis.recovery, genesis.initialKeyCommitment);
    const auto signedFolder = transport / storage::signedEventFolderName({genesis.group, initialMembership.current().root, 0});
    const auto seed = std::filesystem::directory_iterator(signedFolder)->path();
    const auto savedSeed = temporary.root / "saved-seed";
    std::filesystem::rename(seed, savedSeed);
    auto missingHistory = SignedSetup::open(root, Password, Now);
    CHECK(std::filesystem::is_empty(signedFolder));
    CHECK(read(root / state::FileStore::RecordName) == before);
    std::filesystem::rename(savedSeed, seed);
    checkHistory(*missingHistory);
    // Checkpoint unlock depends on the ready encrypted manifest, so a cloud
    // folder or private authority store being offline cannot hide local data.
    std::filesystem::rename(root / "identity", temporary.root / "offline-identity");
    std::filesystem::rename(root / "journal", temporary.root / "offline-journal");
    std::filesystem::rename(transport, temporary.root / "offline-transport");
    const auto entriesBeforeUnlock = std::distance(std::filesystem::directory_iterator(root),
                                                 std::filesystem::directory_iterator());
    CHECK(SignedSetup::unlockCheckpoint(root, Password, activation) == secret);
    CHECK(read(root / state::FileStore::RecordName) == before);
    CHECK(entriesBeforeUnlock == std::distance(std::filesystem::directory_iterator(root),
                                              std::filesystem::directory_iterator()));
    CHECK(!std::filesystem::exists(root / "identity") && !std::filesystem::exists(root / "journal") &&
          !std::filesystem::exists(transport));
    std::filesystem::rename(temporary.root / "offline-identity", root / "identity");
    std::filesystem::rename(temporary.root / "offline-journal", root / "journal");
    std::filesystem::rename(temporary.root / "offline-transport", transport);
    const auto savedLock = temporary.root / "saved-manifest-lock";
    std::filesystem::rename(root / state::FileStore::LockName, savedLock);
    refused([&] { (void)SignedSetup::unlockCheckpoint(root, Password, activation); });
    CHECK(!std::filesystem::exists(root / state::FileStore::LockName));
    CHECK(read(root / state::FileStore::RecordName) == before);
    std::filesystem::rename(savedLock, root / state::FileStore::LockName);
    const auto relocated = temporary.root / "relocated-profile";
    std::filesystem::rename(root, relocated);
    refused([&] { (void)SignedSetup::unlockCheckpoint(relocated, Password, activation); });
    CHECK(read(relocated / state::FileStore::RecordName) == before);
    std::filesystem::rename(relocated, root);
#ifdef __linux__
    const auto alias = temporary.root / "profile-alias";
    std::filesystem::create_directory_symlink(root, alias);
    refused([&] { (void)SignedSetup::open(alias, Password, Now); });
    const auto sharedAlias = temporary.root / "shared-alias";
    std::filesystem::create_directory_symlink(transport, sharedAlias);
    refused([&] { (void)SignedSetup::createFounder(temporary.privateRoot(), Password, sharedAlias, Now); });
#endif
#if defined(__linux__) && defined(CQS_STATE_TESTING)
    for (unsigned fault = 1; fault <= 8; ++fault) {
        const auto crashRoot = temporary.privateRoot();
        const auto crashTransport = temporary.transport("crash-" + std::to_string(fault));
        unsigned commits = 0;
        state::testing::hook = [&](state::testing::Point point) {
            if (point == state::testing::Point::DirectorySynced && ++commits == fault)
                throw state::Error(state::ErrorCode::Io, "Injected setup interruption");
        };
        refused([&] { (void)SignedSetup::createFounder(crashRoot, Password, crashTransport, Now); });
        state::testing::hook = {};
        CHECK(commits == fault);
        auto resumed = SignedSetup::open(crashRoot, Password, Now);
        checkHistory(*resumed);
        auto again = SignedSetup::open(crashRoot, Password, Now);
        CHECK(again->member() == resumed->member());
    }
#endif
    std::cout << "Signed setup create, unlock, independent keys, invitation, and resume checks passed\n";
}
