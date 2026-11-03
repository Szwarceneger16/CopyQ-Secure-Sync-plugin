// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_join.h"
#include "device_join_wizard.h"
#include "device_key_receipt.h"
#include "device_trust_journal.h"
#include "packed_items.h"
#include "storage.h"
#include "test_check.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <sstream>
#include <utility>
#ifdef __linux__
#include <unistd.h>
#endif

using namespace cqs::trust;
using cqs::crypto::Bytes;
namespace st = cqs::state;
namespace tx = cqs::transaction;
namespace storage = cqs::storage;

namespace {
constexpr std::uint64_t Now = 100;
constexpr std::uint64_t Expires = 200;
int cases = 0;

void test(const char *name, const std::function<void()> &action)
{
    action();
    ++cases;
    std::cout << "PASS " << name << '\n';
}

template<class Failure, class Code, class Fn>
void rejects(Code expected, Fn &&action)
{
    bool rejected = false;
    try {
        action();
    } catch (const Failure &error) {
        CHECK(error.code() == expected);
        rejected = true;
    }
    CHECK(rejected);
}

template<class Fn>
void refuses(Fn &&action)
{
    bool rejected = false;
    try {
        action();
    } catch (const JournalError &) {
        rejected = true;
    } catch (const Error &) {
        rejected = true;
    } catch (const st::Error &) {
        rejected = true;
    } catch (const storage::Error &) {
        rejected = true;
    } catch (const cqs::events::Error &) {
        rejected = true;
    } catch (const cqs::packed::Error &) {
        rejected = true;
    }
    CHECK(rejected);
}

Token token(unsigned value)
{
    Token result{};
    result.back() = static_cast<std::uint8_t>(value);
    return result;
}

std::string hex(const Token &digest, bool grouped = false, bool uppercase = false)
{
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < digest.size(); ++i) {
        if (grouped && i && i % 4 == 0) result.push_back('-');
        result.push_back(digits[digest[i] >> 4]);
        result.push_back(digits[digest[i] & 0xf]);
    }
    return result;
}

class MemoryStore final : public tx::Store {
public:
    enum class Fault { None, Before, After };
    explicit MemoryStore(tx::Record initial) : record(std::move(initial)) {}

    std::unique_ptr<Lease> lock() override
    {
        if (leased_) return {};
        auto lease = std::make_unique<Held>(leased_);
        leased_ = true;
        return lease;
    }

    tx::Record load() override
    {
        CHECK(leased_);
        return record;
    }

    void commit(const tx::Record &expected, const tx::Record &replacement) override
    {
        CHECK(leased_);
        CHECK(st::serialize(record) == st::serialize(expected));
        CHECK(replacement.generation == record.generation + 1);
        const auto fault = std::exchange(failure, Fault::None);
        if (fault == Fault::Before) throw st::Error(st::ErrorCode::Io, "Injected before commit");
        record = replacement;
        if (fault == Fault::After) throw st::Error(st::ErrorCode::CommitUnconfirmed, "Injected after commit");
    }

    tx::Record record;
    Fault failure = Fault::None;

private:
    struct Held final : Lease {
        explicit Held(bool &leased) : leased_(leased) {}
        ~Held() override { leased_ = false; }
        bool &leased_;
    };
    bool leased_ = false;
};

struct Fixture {
    std::unique_ptr<SyncKey> key = SyncKey::generate();
    std::array<std::unique_ptr<Identity>, 4> identities;
    Genesis genesis;
    std::array<std::unique_ptr<MemoryStore>, 4> stores;
    std::array<std::unique_ptr<TrustJournal>, 4> journals;

    Fixture()
    {
        for (auto &identity : identities) identity = Identity::generate();
        genesis = {token(1), member(0), token(2), key->commitment(token(1), 0)};
        for (std::size_t i = 0; i < journals.size(); ++i) {
            stores[i] = std::make_unique<MemoryStore>(TrustJournal::initialRecord(genesis, member(i), Now));
            reopen(i);
        }
    }

    const Member &member(std::size_t i) const { return identities[i]->member(); }
    TrustJournal &journal(std::size_t i) const { return *journals[i]; }
    MemoryStore &store(std::size_t i) const { return *stores[i]; }

    void reopen(std::size_t i)
    {
        journals[i] = std::make_unique<TrustJournal>(store(i), genesis, member(i));
    }

    JoinRequest request(std::size_t applicant)
    {
        return journal(applicant).beginJoin(*identities[applicant], Now);
    }

    Proposal proposal(const JoinRequest &request)
    {
        return journal(0).proposeJoin(request, Now, Expires);
    }

    Certificate certificate(const Proposal &proposal, std::initializer_list<std::size_t> signers)
    {
        Certificate result{proposal, {}};
        for (const auto signer : signers) {
            const auto review = journal(signer).reviewJoinApproval(proposal, Now);
            CHECK(review.approvers.size() == 1);
            CHECK(review.approvers.front().member == member(signer));
            result.approvals.push_back(journal(signer).approve(proposal, *identities[signer],
                                                              review.approvers.front().digest, Now));
        }
        return result;
    }

    Certificate enrollFirst()
    {
        const auto requested = proposal(request(1));
        const auto certificate = this->certificate(requested, {0});
        CHECK(journal(1).acceptJoin(certificate, confirmations(journal(1).reviewJoin(requested, {member(0).id}, Now)),
                                    Now) == ObserveResult::Applied);
        CHECK(journal(0).observe(certificate, Now) == ObserveResult::Applied);
        return certificate;
    }

    static std::vector<JoinConfirmation> confirmations(const JoinReview &review)
    {
        std::vector<JoinConfirmation> result;
        for (const auto &peer : review.approvers) result.push_back({peer.member.id, peer.digest});
        return result;
    }
};

#ifdef __linux__
class Transport final {
public:
    explicit Transport(const State &state)
    {
        char path[] = "/tmp/cqs-device-join-XXXXXX";
        const char *directory = ::mkdtemp(path);
        CHECK(directory);
        root = std::filesystem::path(directory) / "transport";
        std::filesystem::create_directories(root / "events");
        scope = {state.group, state.root, state.keyGeneration};
        signedFolder = root / storage::signedEventFolderName(scope);
        std::filesystem::create_directory(signedFolder);
        directory_ = std::make_unique<storage::Directory>(root);
    }

    ~Transport()
    {
        directory_.reset();
        std::error_code ignored;
        std::filesystem::remove_all(root.parent_path(), ignored);
    }

    const storage::Directory &directory() const { return *directory_; }

    std::filesystem::path root, signedFolder;
    storage::SignedEventScope scope;

private:
    std::unique_ptr<storage::Directory> directory_;
};

// One CopyQ 17 QDataStream text/plain MIME item with value "abc".
const std::vector<std::string> ValidItems{"/////gAAAAEAAAACADQAAAAAA2FiYw=="};
const std::string Binding = "detached-copyq-profile";

std::string seed(Fixture &f, const Transport &transport, const std::vector<std::string> &items = ValidItems)
{
    const auto prepared = f.journal(0).prepareClipboardEvent(*f.identities[0], *f.key, {}, items, Now);
    return f.journal(0).publishClipboardEvent(prepared.sequence, *f.key, transport.directory(), Now,
                                              ClipboardPublication::Seed);
}

Bytes install(Fixture &f)
{
    const auto package = f.journal(0).prepareDelivery(f.member(1).id, *f.identities[0], *f.key, Now);
    const auto receipt = f.journal(1).installDelivery(package, *f.identities[1], Now);
    CHECK(f.journal(0).recordReceipt(receipt, Now));
    return receipt;
}
#endif
} // namespace

int main()
{
    test("join challenges are per applicant, durable, and never returned before the commit barrier", [] {
        Fixture f;
        refuses([&] { f.journal(1).beginJoin(*f.identities[2], Now); });
        f.store(1).failure = MemoryStore::Fault::Before;
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.request(1); });
        CHECK(f.store(1).record.generation == 0);
        f.reopen(1);
        f.store(1).failure = MemoryStore::Fault::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.request(1); });
        CHECK(f.store(1).record.generation == 1);
        f.reopen(1);
        const auto one = f.request(1);
        CHECK(one.applicant == f.member(1) && one.request != Token{});
        f.reopen(1);
        CHECK(f.request(1).request == one.request);
        CHECK(f.request(2).request != one.request);
        CHECK(f.journal(1).inspect().state.epoch == 0);
    });
    test("both sides derive the same full digest from their pinned group and intended applicant", [] {
        Fixture f;
        const auto proposal = f.proposal(f.request(1));
        const auto applicant = f.journal(1).reviewJoin(proposal, {f.member(0).id}, Now);
        const auto founder = f.journal(0).reviewJoinApproval(proposal, Now);
        CHECK(applicant.group == f.genesis.group && applicant.root == f.journal(0).inspect().state.root);
        CHECK(applicant.applicant == f.member(1) && applicant.expires == Expires);
        CHECK(applicant.approvers.size() == 1 && founder.approvers.size() == 1);
        CHECK(applicant.approvers[0].member == f.member(0));
        CHECK(applicant.approvers[0].digest == founder.approvers[0].digest);
        CHECK(applicant.approvers[0].digest == verificationDigest(proposal, f.member(0)));
        for (unsigned part = 0; part < 4; ++part) {
            auto substituted = proposal;
            if (part == 0) substituted.request = token(91);
            if (part == 1) substituted.root[0] ^= 1;
            if (part == 2) substituted.subject.encryptionKey = f.member(2).encryptionKey;
            if (part == 3) substituted.parent[0] ^= 1;
            refuses([&] { f.journal(1).reviewJoin(substituted, {f.member(0).id}, Now); });
        }
        refuses([&] { f.journal(1).reviewJoin(proposal, {f.member(2).id}, Now); });
        refuses([&] { f.journal(1).reviewJoin(proposal, {f.member(0).id}, Expires); });
        CHECK(f.journal(1).inspect().state.epoch == 0);
    });
    test("acceptance requires the reviewed signatures and keeps an ambiguous exact retry idempotent", [] {
        Fixture f;
        const auto proposal = f.proposal(f.request(1));
        const auto proof = Fixture::confirmations(f.journal(1).reviewJoin(proposal, {f.member(0).id}, Now));
        const auto certificate = f.certificate(proposal, {0});
        auto altered = certificate;
        altered.approvals[0].signature[0] ^= 1;
        refuses([&] { f.journal(1).acceptJoin(altered, proof, Now); });
        refuses([&] { f.journal(1).observe(certificate, Now); });
        refuses([&] { f.journal(1).acceptJoin(certificate, {}, Now); });
        refuses([&] { f.journal(1).acceptJoin(certificate, proof, Expires); });
        CHECK(f.journal(1).inspect().state.epoch == 0);

        f.store(1).failure = MemoryStore::Fault::Before;
        rejects<st::Error>(st::ErrorCode::Io, [&] { f.journal(1).acceptJoin(certificate, proof, Now); });
        f.reopen(1);
        CHECK(f.journal(1).inspect().state.epoch == 0);
        f.store(1).failure = MemoryStore::Fault::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] { f.journal(1).acceptJoin(certificate, proof, Now); });
        f.reopen(1);
        CHECK(f.journal(1).acceptJoin(certificate, proof, Expires) == ObserveResult::AlreadyKnown);
        CHECK(f.journal(1).inspect().state.epoch == 1);
        CHECK(f.journal(1).inspect().verifiedJoin);
        CHECK(f.journal(1).inspect().certificates.size() == 1);
        refuses([&] { f.journal(1).acceptJoin(altered, proof, Expires); });
    });
    test("malformed enrollment metadata cannot turn an outstanding request into a verified Join", [] {
        Fixture f;
        f.request(1);
        const auto before = f.store(1).record;
        auto &log = f.store(1).record.local->front().begin()->second;
        CHECK(log.size() >= 2 * Token{}.size());
        log.back() ^= 1; // Nonzero admission intent without a matching accepted Add.
        rejects<JournalError>(JournalCode::Invalid, [&] { f.reopen(1); });
        f.store(1).record = before;
        f.reopen(1);
        CHECK(!f.journal(1).inspect().verifiedJoin);
    });
    test("a later Add matches every certificate signer against the applicant's observed chain", [] {
        Fixture f;
        const auto first = f.enrollFirst();
        CHECK(f.journal(2).observe(first, Now) == ObserveResult::Applied);
        const auto proposal = f.proposal(f.request(2));
        const std::vector<Token> approvers{f.member(0).id, f.member(1).id};
        auto proof = Fixture::confirmations(f.journal(2).reviewJoin(proposal, approvers, Now));
        CHECK(proof.size() == 2 && proof[0].digest != proof[1].digest);
        const auto certificate = f.certificate(proposal, {0, 1});
        refuses([&] { f.journal(2).reviewJoin(proposal, {f.member(0).id}, Now); });
        refuses([&] { f.journal(2).reviewJoin(proposal, {f.member(0).id, f.member(0).id}, Now); });
        refuses([&] { f.journal(2).reviewJoin(proposal, {f.member(0).id, f.member(3).id}, Now); });
        auto duplicate = proof;
        duplicate[1] = duplicate[0];
        refuses([&] { f.journal(2).acceptJoin(certificate, duplicate, Now); });
        auto swapped = proof;
        std::swap(swapped[0].digest, swapped[1].digest);
        refuses([&] { f.journal(2).acceptJoin(certificate, swapped, Now); });
        auto extra = proof;
        extra.push_back({f.member(3).id, token(90)});
        refuses([&] { f.journal(2).acceptJoin(certificate, extra, Now); });
        CHECK(f.journal(2).inspect().state.epoch == 1);
        CHECK(f.journal(2).acceptJoin(certificate, proof, Now) == ObserveResult::Applied);
        CHECK(f.journal(2).inspect().state.epoch == 2);
    });
    test("trusted terminal prompts require full independent values and recheck the clock", [] {
        Fixture f;
        const auto proposal = f.proposal(f.request(1));
        const auto expected = verificationDigest(proposal, f.member(0));
        const auto fixedTime = [] { return Now; };
        std::ostringstream screen;
        const auto applicantGeneration = f.store(1).record.generation;
        CHECK(showJoinApplicantReview(f.journal(1), proposal, {f.member(0).id}, screen, Now));
        CHECK(f.store(1).record.generation == applicantGeneration);
        CHECK(screen.str().find(hex(expected, true)) != std::string::npos);
        std::istringstream partial(hex(expected).substr(0, 63) + "\n");
        CHECK(!runJoinApprovalWizard(f.journal(0), *f.identities[0], proposal, partial, screen, fixedTime));
        CHECK(f.journal(0).inspect().reservations == 0);
        std::istringstream trailing(hex(expected) + "0\n");
        CHECK(!runJoinApprovalWizard(f.journal(0), *f.identities[0], proposal, trailing, screen, fixedTime));
        CHECK(f.journal(0).inspect().reservations == 0);
        std::istringstream answer(hex(expected, true, true) + "\r\n");
        const auto approval = runJoinApprovalWizard(f.journal(0), *f.identities[0], proposal, answer, screen, fixedTime);
        CHECK(approval);
        CHECK(screen.str().find(hex(f.genesis.group, true)) != std::string::npos);
        CHECK(screen.str().find("synchronized clipboard history") != std::string::npos);

        const Certificate certificate{proposal, {*approval}};
        std::istringstream wrong(hex(token(90)) + "\n");
        CHECK(!runJoinApplicantWizard(f.journal(1), certificate, wrong, screen, fixedTime));
        CHECK(f.journal(1).inspect().state.epoch == 0);
        unsigned calls = 0;
        std::istringstream expired(hex(expected) + "\n");
        refuses([&] {
            runJoinApplicantWizard(f.journal(1), certificate, expired, screen, [&] {
                return calls++ ? Expires : Now;
            });
        });
        CHECK(calls == 2 && f.journal(1).inspect().state.epoch == 0);
        std::istringstream confirmed(hex(expected) + "\n");
        const auto joined = runJoinApplicantWizard(f.journal(1), certificate, confirmed, screen, fixedTime);
        CHECK(joined && *joined == ObserveResult::Applied);
        f.reopen(1);
        std::istringstream empty;
        std::ostringstream noPrompt;
        const auto retried = runJoinApplicantWizard(f.journal(1), certificate, empty, noPrompt, [] { return Expires; });
        CHECK(retried && *retried == ObserveResult::AlreadyKnown && noPrompt.str().empty());
    });
#ifdef __linux__
    test("a reopened encrypted FileStore retains the verified enrollment and sealed key", [] {
        Fixture f;
        Transport transport(f.journal(0).inspect().state);
        const auto privateDirectory = transport.root.parent_path() / "private";
        CHECK(std::filesystem::create_directory(privateDirectory));
        std::filesystem::permissions(privateDirectory, std::filesystem::perms::owner_all);
        const auto binding = TrustJournal::binding(f.genesis, f.member(1));
        const Bytes credential(32, 0x24);
        Token initialChallenge{};
        {
            st::FileStore store(privateDirectory, binding, credential);
            TrustJournal::initialize(store, f.genesis, f.member(1), Now);
            TrustJournal applicant(store, f.genesis, f.member(1));
            initialChallenge = applicant.beginJoin(*f.identities[1], Now).request;
        }
        {
            st::FileStore store(privateDirectory, binding, credential);
            TrustJournal applicant(store, f.genesis, f.member(1));
            const auto request = applicant.beginJoin(*f.identities[1], Now);
            CHECK(request.request == initialChallenge);
            const auto proposal = f.proposal(request);
            const auto confirmed = Fixture::confirmations(applicant.reviewJoin(proposal, {f.member(0).id}, Now));
            const auto certificate = f.certificate(proposal, {0});
            CHECK(applicant.acceptJoin(certificate, confirmed, Now) == ObserveResult::Applied);
            CHECK(f.journal(0).observe(certificate, Now) == ObserveResult::Applied);
            const auto package = f.journal(0).prepareDelivery(f.member(1).id, *f.identities[0], *f.key, Now);
            CHECK(f.journal(0).recordReceipt(applicant.installDelivery(package, *f.identities[1], Now), Now));
        }
        const auto tip = seed(f, transport);
        st::FileStore store(privateDirectory, binding, credential);
        TrustJournal applicant(store, f.genesis, f.member(1));
        CHECK(applicant.inspect().verifiedJoin && applicant.inspect().installedKey);
        const auto result = applicant.preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
        CHECK(result.tipId == tip && result.member == f.member(1).id);
    });
    test("activation binds the verified signed tip after durable enrollment and key delivery", [] {
        Fixture f;
        f.enrollFirst();
        Transport transport(f.journal(0).inspect().state);
        const auto tip = seed(f, transport);
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(!install(f).empty());
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[2], transport.directory(), Binding, Now); });
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), "bad/binding", Now); });
        f.store(1).failure = MemoryStore::Fault::After;
        rejects<st::Error>(st::ErrorCode::CommitUnconfirmed, [&] {
            f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
        });
        f.reopen(1);
        const auto result = f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now);
        const auto state = f.journal(1).inspect().state;
        const auto files = transport.directory().scanSignedEvents(transport.scope);
        CHECK(files.size() == 1 && files.front().id == tip);
        CHECK(result.profileBinding == Binding && result.group == state.group && result.root == state.root);
        CHECK(result.head == state.digest && result.generation == state.keyGeneration && result.tipId == tip);
        CHECK(result.tipDigest == SignedEventCodec::digest(files.front().wire));
        CHECK(f.journal(1).inspect().eventWitnesses == 1);
        const auto onlyFile = std::filesystem::directory_iterator(transport.signedFolder);
        CHECK(onlyFile != std::filesystem::directory_iterator{});
        CHECK(std::filesystem::remove(onlyFile->path()));
        f.reopen(1);
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(f.journal(1).inspect().eventWitnesses == 1);
    });
    test("a low-level observed Add cannot authorize profile activation even with a valid package", [] {
        Fixture f;
        const auto proposal = f.proposal({f.member(1), token(20)});
        const auto certificate = f.certificate(proposal, {0});
        CHECK(f.journal(0).observe(certificate, Now) == ObserveResult::Applied);
        CHECK(f.journal(1).observe(certificate, Now) == ObserveResult::Applied);
        Transport transport(f.journal(0).inspect().state);
        CHECK(!seed(f, transport).empty() && !install(f).empty());
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(f.journal(1).inspect().eventWitnesses == 0);
    });
    test("activation refuses empty history, unsupported MIME, and a witnessed fork", [] {
        Fixture f;
        const auto sibling = f.proposal({f.member(3), token(20)});
        f.enrollFirst();
        Transport transport(f.journal(0).inspect().state);
        CHECK(!install(f).empty());
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(!seed(f, transport, {"YQ=="}).empty());
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(f.journal(1).inspect().eventWitnesses == 0);
        const Approval external{f.member(0).id, f.identities[0]->sign(approvalBytes(sibling, f.member(0)))};
        CHECK(f.journal(1).observe({sibling, {external}}, Now) == ObserveResult::ForkDetected);
        f.reopen(1);
        CHECK(f.journal(1).inspect().forked);
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
    });
    test("activation refuses multiple signed tips instead of selecting a branch", [] {
        Fixture f;
        f.enrollFirst();
        Transport transport(f.journal(0).inspect().state);
        CHECK(!install(f).empty());
        const auto tip = seed(f, transport);
        const auto files = transport.directory().scanSignedEvents(transport.scope);
        CHECK(files.size() == 1);
        const std::vector<SignedEventParent> parents{{tip, SignedEventCodec::digest(files[0].wire)}};
        for (unsigned i = 0; i < 2; ++i) {
            const auto prepared = f.journal(0).prepareClipboardEvent(*f.identities[0], *f.key, parents, ValidItems, Now);
            CHECK(!f.journal(0).publishClipboardEvent(prepared.sequence, *f.key, transport.directory(), Now).empty());
        }
        refuses([&] { f.journal(1).preflightJoinActivation(*f.identities[1], transport.directory(), Binding, Now); });
        CHECK(f.journal(1).inspect().eventWitnesses == 0);
    });
#endif
    std::cout << cases << " device Join test cases passed\n";
}
