// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_trust_journal.h"
#include "device_identity.h"
#include "test_check.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#ifdef __linux__
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace cqs::trust;
namespace tx = cqs::transaction;
namespace st = cqs::state;
using cqs::crypto::Bytes;
namespace {
int cases = 0;
void test(const char *name, const std::function<void()> &body)
{
    body(); ++cases;
    std::cout << "PASS " << name << '\n';
}
void rejects(const std::function<void()> &body)
{
    bool failed = false;
    try { body(); } catch (const std::exception &) { failed = true; }
    CHECK(failed);
}
void rejects(JournalCode code, const std::function<void()> &body)
{
    bool failed = false;
    try { body(); } catch (const JournalError &error) {
        failed = true; CHECK(error.code() == code);
    }
    CHECK(failed);
}
void rejects(ErrorCode code, const std::function<void()> &body)
{
    bool failed = false;
    try { body(); } catch (const Error &error) {
        failed = true; CHECK(error.code() == code);
    }
    CHECK(failed);
}
Token token(std::uint32_t value)
{
    Token result{}; result[0] = 0xa5;
    for (unsigned i = 0; i < 4; ++i)
        result[31 - i] = static_cast<std::uint8_t>(value >> (i * 8));
    return result;
}
bool equal(const tx::Record &a, const tx::Record &b)
{
    return st::serialize(a) == st::serialize(b);
}
// Public, disposable test-only store. It exercises the coordinator's required
// persistence ordering; it is NOT evidence of disk or hardware durability.
class MemoryStore final : public tx::Store {
public:
    explicit MemoryStore(tx::Record initial) : value(std::move(initial)) {}
    enum class Failure { None, BeforeCommit, AfterCommit };
    tx::Record value;
    Failure failure = Failure::None;
    bool busy = false, missing = false;
    std::size_t loads = 0, commits = 0, locks = 0;
    std::thread::id owner;
    struct Held final : Lease {
        explicit Held(MemoryStore &store) : store_(store) {}
        ~Held() override { store_.busy = false; store_.owner = {}; }
        MemoryStore &store_;
    };
    std::unique_ptr<Lease> lock() override
    {
        if (busy) return {};
        busy = true; owner = std::this_thread::get_id(); ++locks;
        return std::make_unique<Held>(*this);
    }
    tx::Record load() override
    {
        CHECK(busy); CHECK(owner == std::this_thread::get_id()); ++loads;
        if (missing) throw st::Error(st::ErrorCode::Missing, "Test record missing");
        return value;
    }
    void commit(const tx::Record &expected, const tx::Record &replacement) override
    {
        CHECK(busy); CHECK(owner == std::this_thread::get_id());
        CHECK(equal(expected, value));
        CHECK(replacement.generation == expected.generation + 1); ++commits;
        const auto fail = failure; failure = Failure::None;
        if (fail == Failure::BeforeCommit)
            throw st::Error(st::ErrorCode::Io, "Test commit failed before publication");
        value = replacement;
        if (fail == Failure::AfterCommit)
            throw st::Error(st::ErrorCode::CommitUnconfirmed, "Test commit acknowledgement lost");
    }
};
struct Fixture {
    std::vector<std::unique_ptr<Identity>> identities;
    Genesis genesis;
    std::unique_ptr<MemoryStore> store;
    std::unique_ptr<TrustJournal> journal;
    explicit Fixture(std::size_t count = 4)
    {
        for (std::size_t i = 0; i < count; ++i) identities.push_back(Identity::generate());
        genesis = {token(10000), identities[0]->member(), token(10001), token(10002)};
        store = std::make_unique<MemoryStore>(TrustJournal::initialRecord(genesis, local(), 100));
        reopen();
    }
    const Member &local() const { return identities[0]->member(); }
    const Member &member(std::size_t i) const { return identities[i]->member(); }
    void reopen() { journal = std::make_unique<TrustJournal>(*store, genesis, local()); }
    Proposal add(std::size_t i, std::uint32_t request = 1,
                 std::uint64_t created = 100, std::uint64_t expires = 1000)
    {
        return journal->propose(Operation::Add, member(i), token(20000 + request),
                                token(30000 + request), created, expires);
    }
    Approval approve(const Proposal &p, std::uint64_t now = 100)
    {
        return journal->approve(p, *identities[0], verificationDigest(p, local()), now);
    }
    Approval vote(const Proposal &p, std::size_t i) const
    {
        return {member(i).id, identities[i]->sign(approvalBytes(p, member(i)))};
    }
    Certificate certificate(const Proposal &p, std::initializer_list<std::size_t> signers) const
    {
        Certificate result{p, {}};
        for (const auto signer : signers) result.approvals.push_back(vote(p, signer));
        return result;
    }
    void admit(std::size_t count)
    {
        for (std::size_t i = 1; i < count; ++i) {
            const auto p = add(i, static_cast<std::uint32_t>(i));
            const auto cert = i == 1 ? certificate(p, {0}) : certificate(p, {0, 1});
            CHECK(journal->observe(cert, 100) == ObserveResult::Applied);
        }
    }
};
Bytes &payload(tx::Record &record)
{
    CHECK(record.local); CHECK(record.local->size() == 1);
    CHECK(record.local->front().size() == 1);
    return record.local->front().begin()->second;
}
void invalidRecord(Fixture &f)
{
    rejects([&] { f.reopen(); f.journal->inspect(); });
}
void sameStatus(const JournalStatus &a, const JournalStatus &b)
{
    CHECK(a.state.digest == b.state.digest); CHECK(a.forked == b.forked);
    CHECK(a.watermark == b.watermark); CHECK(a.operations == b.operations);
    CHECK(a.reservations == b.reservations); CHECK(a.certificates == b.certificates);
}
} // namespace

int main()
{
    test("fresh journal retains exact pinned genesis and no signing authority for outsiders", [] {
        Fixture f;
        const auto status = f.journal->inspect();
        CHECK(status.state.members == std::vector<Member>{f.local()});
        CHECK(status.state.group == f.genesis.group); CHECK(status.state.epoch == 0);
        CHECK(status.operations == 0); CHECK(status.reservations == 0);
        CHECK(status.watermark == 100); CHECK(!status.forked);
        CHECK(status.certificates.empty()); CHECK(!f.store->busy);
        const auto unknown = f.member(1);
        MemoryStore other(TrustJournal::initialRecord(f.genesis, unknown, 100));
        TrustJournal applicant(other, f.genesis, unknown);
        rejects(ErrorCode::NotMember, [&] {
            applicant.propose(Operation::Add, f.member(2), token(7), token(8), 100, 1000);
        });
        const auto p = f.add(2);
        rejects(ErrorCode::UnknownSigner, [&] {
            applicant.approve(p, *f.identities[1], verificationDigest(p, unknown), 100);
        });
    });
    test("bootstrap approval is durable before return and does not itself admit a member", [] {
        Fixture f;
        const auto p = f.add(1);
        const auto vote = f.approve(p);
        CHECK(vote.signer == f.local().id);
        CHECK(SodiumVerifier{}.verify(f.local().signingKey, approvalBytes(p, f.local()), vote.signature));
        CHECK(f.store->commits == 1); CHECK(f.store->value.generation == 1);
        const auto reserved = f.journal->inspect();
        CHECK(reserved.state.members.size() == 1); CHECK(reserved.reservations == 1);
        CHECK(reserved.operations == 1); CHECK(reserved.certificates.empty());
        f.reopen(); sameStatus(f.journal->inspect(), reserved);
        const Certificate cert{p, {vote}};
        CHECK(f.journal->observe(cert, 100) == ObserveResult::Applied);
        const auto accepted = f.journal->inspect();
        CHECK(accepted.state.members.size() == 2); CHECK(accepted.state.bootstrapConsumed);
        CHECK(accepted.operations == 2); CHECK(accepted.certificates == std::vector<Bytes>{encodeCertificate(cert)});
        f.reopen(); sameStatus(f.journal->inspect(), accepted);
    });
    test("third admission requires two real signatures on the same intent", [] {
        Fixture f; f.admit(2);
        const auto p = f.add(2);
        const auto vote = f.approve(p);
        rejects(ErrorCode::NoQuorum, [&] { f.journal->observe({p, {vote}}, 100); });
        CHECK(f.journal->inspect().state.members.size() == 2);
        CHECK(f.journal->observe({p, {vote, f.vote(p, 1)}}, 100) == ObserveResult::Applied);
        CHECK(f.journal->inspect().state.members.size() == 3);
    });
    test("cloned approval and applicant signatures do not manufacture quorum", [] {
        Fixture f; f.admit(2); const auto p = f.add(2);
        const auto a = f.vote(p, 0);
        rejects([&] { f.journal->observe({p, {a, a}}, 100); });
        rejects(ErrorCode::UnknownSigner, [&] {
            f.journal->observe({p, {a, f.vote(p, 2)}}, 100);
        });
        CHECK(f.journal->inspect().state.members.size() == 2);
    });
    test("approval requires exact local confirmation and matching full local identity", [] {
        Fixture f; const auto p = f.add(1); const auto before = f.store->value;
        rejects(JournalCode::Confirmation, [&] { f.journal->approve(p, *f.identities[0], token(55), 100); });
        rejects(JournalCode::WrongPins, [&] {
            f.journal->approve(p, *f.identities[1], verificationDigest(p, f.local()), 100);
        });
        for (unsigned field = 0; field < 5; ++field) {
            auto changed = p;
            if (field == 0) changed.nonce = token(56);
            if (field == 1) changed.request = token(57);
            if (field == 2) changed.subject = f.member(2);
            if (field == 3) changed.expires = 999;
            if (field == 4) changed.created = 99;
            rejects(JournalCode::Confirmation, [&] {
                f.journal->approve(changed, *f.identities[0], verificationDigest(p, f.local()), 100);
            });
        }
        CHECK(equal(before, f.store->value)); CHECK(f.store->commits == 0);
    });
    test("a second intent cannot reuse a reserved parent across reopen or expiry", [] {
        Fixture f; const auto p = f.add(1, 1, 100, 200);
        const auto other = f.add(2, 2, 100, 300);
        const auto a = f.approve(p); f.reopen();
        const auto retry = f.approve(p, 101);
        CHECK(a.signature == retry.signature); CHECK(a.signer == retry.signer);
        CHECK(f.journal->inspect().operations == 1); CHECK(f.journal->inspect().reservations == 1);
        rejects(ErrorCode::Blocked, [&] { f.approve(other, 101); });
        rejects(ErrorCode::Expired, [&] { f.approve(p, 200); });
        f.reopen(); rejects(ErrorCode::Blocked, [&] { f.approve(other, 201); });
    });
    test("signing enforces created inclusive and expires exclusive", [] {
        Fixture f; const auto p = f.add(1, 1, 101, 200);
        rejects(ErrorCode::Expired, [&] { f.approve(p, 100); });
        CHECK(f.journal->inspect().operations == 0);
        f.approve(p, 101); CHECK(f.journal->inspect().watermark == 101);
        rejects(ErrorCode::Expired, [&] { f.approve(p, 200); });
    });
    test("accepted certificates and prior reservations replay in original order", [] {
        Fixture f;
        const auto first = f.add(1, 1); const auto a = f.approve(first, 101);
        CHECK(f.journal->observe({first, {a}}, 102) == ObserveResult::Applied);
        const auto second = f.add(2, 2, 102, 1000); const auto b = f.approve(second, 103);
        CHECK(f.journal->observe({second, {b, f.vote(second, 1)}}, 104) == ObserveResult::Applied);
        const auto expected = f.journal->inspect();
        CHECK(expected.operations == 4); CHECK(expected.reservations == 2);
        CHECK(expected.watermark == 104); CHECK(expected.state.members.size() == 3);
        f.reopen(); sameStatus(f.journal->inspect(), expected);
    });
    test("stale verification cannot sign once a different head is accepted", [] {
        Fixture f; f.admit(2);
        const auto stale = f.add(2, 1); const auto accepted = f.add(3, 2);
        CHECK(f.journal->observe(f.certificate(accepted, {0, 1}), 100) == ObserveResult::Applied);
        const auto before = f.store->value;
        rejects(ErrorCode::Stale, [&] { f.approve(stale); });
        CHECK(equal(before, f.store->value));
    });
    test("clock watermark survives restart and invalid requests do not advance it", [] {
        Fixture f; const auto p = f.add(1); f.approve(p, 150);
        f.reopen(); CHECK(f.journal->inspect().watermark == 150);
        rejects(JournalCode::ClockRollback, [&] { f.approve(p, 149); });
        const auto before = f.store->value;
        rejects(JournalCode::Confirmation, [&] { f.journal->approve(p, *f.identities[0], token(99), 900); });
        CHECK(equal(before, f.store->value)); CHECK(f.journal->inspect().watermark == 150);
        f.approve(p, 151); CHECK(f.journal->inspect().watermark == 151);
    });
    test("fresh certificate with backwards clock refuses without losing valid evidence", [] {
        Fixture f; const auto p = f.add(1);
        const auto a = f.approve(p, 150); const auto before = f.store->value;
        rejects(JournalCode::ClockRollback, [&] { f.journal->observe({p, {a}}, 149); });
        CHECK(equal(before, f.store->value));
        CHECK(f.journal->observe({p, {a}}, 150) == ObserveResult::Applied);
    });
    test("expired deep fork is stored exactly and remains latched after reopen", [] {
        Fixture f; f.admit(2);
        const auto x = f.add(2, 2, 100, 200), y = f.add(3, 3, 100, 200);
        const auto first = f.certificate(x, {0, 1}), second = f.certificate(y, {0, 1});
        CHECK(f.journal->observe(first, 150) == ObserveResult::Applied);
        const auto next = f.add(3, 4, 150, 250);
        CHECK(f.journal->observe(f.certificate(next, {0, 1}), 151) == ObserveResult::Applied);
        const auto accepted = f.journal->inspect().state.digest;
        CHECK(f.journal->observe(second, 10000) == ObserveResult::ForkDetected);
        const auto status = f.journal->inspect();
        CHECK(status.forked); CHECK(status.state.digest == accepted);
        CHECK(status.certificates.size() == 4);
        CHECK(status.certificates[1] == encodeCertificate(first));
        CHECK(status.certificates.back() == encodeCertificate(second));
        f.reopen(); sameStatus(f.journal->inspect(), status);
        rejects(ErrorCode::Forked, [&] { f.approve(next, 10001); });
        rejects(ErrorCode::Forked, [&] { f.journal->observe(second, 10001); });
    });
    test("historical fork remains actionable despite a backwards local clock", [] {
        Fixture f; f.admit(2);
        const auto x = f.add(2, 2), y = f.add(3, 3);
        CHECK(f.journal->observe(f.certificate(x, {0, 1}), 200) == ObserveResult::Applied);
        CHECK(f.journal->observe(f.certificate(y, {0, 1}), 101) == ObserveResult::ForkDetected);
        CHECK(f.journal->inspect().watermark == 200);
        f.reopen(); CHECK(f.journal->inspect().forked);
    });
    test("known certificate retry neither appends evidence nor expands state", [] {
        Fixture f; const auto p = f.add(1); const auto cert = f.certificate(p, {0});
        CHECK(f.journal->observe(cert, 100) == ObserveResult::Applied);
        const auto before = f.store->value;
        for (unsigned i = 0; i < 100; ++i)
            CHECK(f.journal->observe(cert, 10000 + i) == ObserveResult::AlreadyKnown);
        CHECK(equal(before, f.store->value));
        CHECK(f.journal->inspect().operations == 1); CHECK(f.journal->inspect().certificates.size() == 1);
    });
    test("bad signatures and invalid extra signatures never mutate durable state", [] {
        Fixture f; f.admit(3); const auto p = f.add(3);
        const auto before = f.store->value;
        auto cert = f.certificate(p, {0, 1}); cert.approvals[0].signature[0] ^= 1;
        rejects(ErrorCode::BadSignature, [&] { f.journal->observe(cert, 100); });
        cert = f.certificate(p, {0, 1, 2}); cert.approvals.back().signature[20] ^= 1;
        rejects(ErrorCode::BadSignature, [&] { f.journal->observe(cert, 100); });
        cert = f.certificate(p, {0, 1}); cert.proposal.nonce = token(3);
        rejects(ErrorCode::BadSignature, [&] { f.journal->observe(cert, 100); });
        CHECK(equal(before, f.store->value));
    });
    test("invalid suite keys refuse even when structural model fields are nonzero", [] {
        Fixture f; auto invalid = f.member(1); invalid.signingKey = {};
        invalid.signingKey[0] = 1; // Ed25519 identity point, not an admitted key.
        rejects([&] { f.journal->propose(Operation::Add, invalid, token(2), token(3), 100, 200); });
        auto invalidP = f.add(1); invalidP.subject.encryptionKey = {};
        invalidP.subject.encryptionKey[0] = 1; // X25519 small-order point.
        const auto before = f.store->value;
        rejects([&] { f.approve(invalidP); });
        CHECK(equal(before, f.store->value));
    });
    test("founder removal is ordinary survivor approval and retires local signing", [] {
        Fixture f; f.admit(3);
        const auto remove = f.journal->propose(Operation::Remove, f.local(), token(4), token(5),
                                               100, 1000, token(6));
        rejects(ErrorCode::UnknownSigner, [&] { f.approve(remove); });
        CHECK(f.journal->observe(f.certificate(remove, {1, 2}), 100) == ObserveResult::Applied);
        const auto status = f.journal->inspect();
        CHECK(status.state.members.size() == 2); CHECK(status.state.retired == std::vector<Member>{f.local()});
        CHECK(status.state.keyGeneration == 1); CHECK(status.state.keyCommitment == token(6));
        f.reopen(); sameStatus(f.journal->inspect(), status);
        rejects(ErrorCode::NotMember, [&] { f.add(3, 9); });
        Membership peers(f.genesis.group, f.genesis.founder, f.genesis.recovery, f.genesis.initialKeyCommitment);
        for (const auto &wire : status.certificates)
            peers.observe(decodeCertificate(wire), 100, SodiumVerifier{});
        const auto next = peers.propose(Operation::Add, f.member(3), token(19), token(20), 100, 1000);
        rejects(ErrorCode::UnknownSigner, [&] { f.approve(next); });
        CHECK(f.journal->observe(f.certificate(next, {1, 2}), 100) == ObserveResult::Applied);
    });
    test("failure before commit returns no approval and requires reopening", [] {
        Fixture f; const auto p = f.add(1); const auto before = f.store->value;
        f.store->failure = MemoryStore::Failure::BeforeCommit;
        std::optional<Approval> result;
        rejects([&] { result = f.approve(p); }); CHECK(!result);
        CHECK(equal(before, f.store->value));
        rejects(JournalCode::Uncertain, [&] { f.journal->inspect(); });
        rejects(JournalCode::Uncertain, [&] { f.approve(p); });
        f.reopen(); CHECK(f.journal->inspect().reservations == 0);
        // No signature was returned, so reopening may reserve another intent.
        f.approve(f.add(2, 2)); CHECK(f.journal->inspect().reservations == 1);
    });
    test("lost commit acknowledgement retains reservation and cannot authorize a sibling", [] {
        Fixture f; const auto p = f.add(1); const auto sibling = f.add(2, 2);
        f.store->failure = MemoryStore::Failure::AfterCommit;
        std::optional<Approval> result;
        rejects([&] { result = f.approve(p); }); CHECK(!result);
        rejects(JournalCode::Uncertain, [&] { f.journal->inspect(); });
        f.reopen(); CHECK(f.journal->inspect().reservations == 1);
        rejects(ErrorCode::Blocked, [&] { f.approve(sibling); });
        const auto approval = f.approve(p);
        CHECK(SodiumVerifier{}.verify(f.local().signingKey, approvalBytes(p, f.local()), approval.signature));
    });
    test("ambiguous fork persistence poisons old instance and reload keeps conflict", [] {
        Fixture f; f.admit(2);
        const auto x = f.add(2, 2), y = f.add(3, 3);
        CHECK(f.journal->observe(f.certificate(x, {0, 1}), 100) == ObserveResult::Applied);
        f.store->failure = MemoryStore::Failure::AfterCommit;
        rejects([&] { f.journal->observe(f.certificate(y, {0, 1}), 100); });
        rejects(JournalCode::Uncertain, [&] { f.journal->inspect(); });
        f.reopen(); CHECK(f.journal->inspect().forked);
        CHECK(f.journal->inspect().certificates.back() == encodeCertificate(f.certificate(y, {0, 1})));
    });
    test("busy store fails promptly and never drops the competing lease", [] {
        Fixture f; const auto p = f.add(1); auto held = f.store->lock(); CHECK(held);
        rejects(JournalCode::Busy, [&] { f.journal->inspect(); });
        rejects(JournalCode::Busy, [&] { f.approve(p); });
        CHECK(f.store->busy); CHECK(f.store->commits == 0);
        held.reset(); f.approve(p); CHECK(!f.store->busy);
    });
    test("missing record is never recreated from a known genesis", [] {
        Fixture f; f.store->missing = true;
        rejects([&] { f.reopen(); f.journal->inspect(); });
        CHECK(f.store->commits == 0); f.store->missing = false;
        f.reopen(); CHECK(f.journal->inspect().operations == 0);
    });
    test("wrong external genesis or local pin refuses an otherwise authentic record", [] {
        Fixture f;
        for (unsigned field = 0; field < 5; ++field) {
            auto g = f.genesis; auto local = f.local();
            if (field == 0) g.group = token(50);
            if (field == 1) g.recovery = token(51);
            if (field == 2) g.initialKeyCommitment = token(52);
            if (field == 3) g.founder = f.member(1);
            if (field == 4) local = f.member(1);
            rejects([&] { TrustJournal wrong(*f.store, g, local); wrong.inspect(); });
        }
        CHECK(f.store->commits == 0);
    });
    test("journal rejects foreign record shape and schema without normalizing it", [] {
        Fixture f; const auto good = f.store->value;
        for (unsigned field = 0; field < 7; ++field) {
            f.store->value = good;
            if (field == 0) f.store->value.schema = 6;
            if (field == 1) f.store->value.local->push_back({});
            if (field == 2) f.store->value.local->front().emplace("text/plain", Bytes{1});
            if (field == 3) f.store->value.allocatedSequence = 1;
            if (field == 4) f.store->value.keyIdentity = std::string(64, '0');
            if (field == 5) f.store->value.binding = "foreign-binding";
            if (field == 6) f.store->value.local.reset();
            invalidRecord(f);
        }
        f.store->value = good; f.reopen(); CHECK(f.journal->inspect().operations == 0);
    });
    test("every initial payload truncation and trailing bytes fail closed", [] {
        Fixture f; const auto good = f.store->value; const auto bytes = payload(f.store->value);
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            f.store->value = good; payload(f.store->value).resize(n); invalidRecord(f);
        }
        f.store->value = good; payload(f.store->value).push_back(0); invalidRecord(f);
        f.store->value = good; payload(f.store->value).assign(TrustJournal::MaxJournalBytes + 1, 0); invalidRecord(f);
        CHECK(f.store->commits == 0);
    });
    test("one-bit payload mutations cannot replace pinned trust or silently lose events", [] {
        Fixture f; const auto p = f.add(1); f.approve(p);
        CHECK(f.journal->observe({p, {f.vote(p, 0)}}, 100) == ObserveResult::Applied);
        const auto good = f.store->value; const auto bytes = payload(f.store->value);
        std::size_t refused = 0, accepted = 0;
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            f.store->value = good; payload(f.store->value)[i] ^= 1;
            try {
                f.reopen(); const auto status = f.journal->inspect();
                // Some timestamp mutations may remain valid, but the trusted
                // roster, event counts and exact certificates must not change.
                CHECK(status.state.members.size() == 2); CHECK(status.operations == 2);
                CHECK(status.reservations == 1); CHECK(status.certificates == std::vector<Bytes>{encodeCertificate({p, {f.vote(p, 0)}})});
                ++accepted;
            } catch (const std::exception &) { ++refused; }
        }
        CHECK(refused > 100); CHECK(refused + accepted == bytes.size());
        std::cout << "  checked " << bytes.size() << " one-bit journal mutations\n";
        f.store->value = good; f.reopen(); CHECK(f.journal->inspect().state.members.size() == 2);
    });
    test("generation exhaustion refuses signing and leaves the reservation absent", [] {
        Fixture f; f.store->value.generation = std::numeric_limits<std::uint64_t>::max();
        f.reopen(); const auto p = f.add(1); const auto before = f.store->value;
        rejects([&] { f.approve(p); }); CHECK(equal(before, f.store->value));
    });
    test("live instance refuses restoring an older valid encrypted-record generation", [] {
        Fixture f; const auto p = f.add(1); const auto prior = f.store->value;
        f.approve(p); const auto current = f.store->value;
        f.store->value = prior;
        rejects(JournalCode::Rollback, [&] { f.journal->inspect(); });
        rejects(JournalCode::Rollback, [&] { f.approve(p); });
        CHECK(equal(f.store->value, prior));
        f.store->value = current; CHECK(f.journal->inspect().reservations == 1);
    });
    test("same-generation authenticated replacement cannot change live clock state", [] {
        Fixture f; const auto prior = f.store->value;
        f.store->value = TrustJournal::initialRecord(f.genesis, f.local(), 101);
        CHECK(f.store->value.generation == prior.generation);
        rejects(JournalCode::Rollback, [&] { f.journal->inspect(); });
        f.store->value = prior; CHECK(f.journal->inspect().watermark == 100);
    });
#ifdef __linux__
    test("real encrypted FileStore create-only provisioning, reopen, and no plaintext journal", [] {
        Fixture f;
        char pattern[] = "/tmp/cqs-trust-journal-XXXXXX";
        auto *made = ::mkdtemp(pattern); CHECK(made);
        const std::filesystem::path directory(made);
        struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code ec; std::filesystem::remove_all(path, ec); } } cleanup{directory};
        CHECK(::chmod(directory.c_str(), 0700) == 0);
        const Bytes localKey(32, 0x42); // PUBLIC TEST KEY, never user material.
        const auto binding = TrustJournal::binding(f.genesis, f.local());
        Bytes rawProposal;
        JournalStatus expected;
        {
            st::FileStore disk(directory, binding, localKey);
            TrustJournal::initialize(disk, f.genesis, f.local(), 100);
            rejects([&] { TrustJournal::initialize(disk, f.genesis, f.local(), 100); });
            TrustJournal journal(disk, f.genesis, f.local());
            const auto p = journal.propose(Operation::Add, f.member(1), token(61), token(62), 100, 200);
            rawProposal = encodeProposal(p);
            const auto vote = journal.approve(p, *f.identities[0], verificationDigest(p, f.local()), 100);
            CHECK(journal.observe({p, {vote}}, 100) == ObserveResult::Applied);
            expected = journal.inspect();
        }
        {
            st::FileStore disk(directory, binding, localKey);
            TrustJournal reopened(disk, f.genesis, f.local());
            sameStatus(reopened.inspect(), expected);
        }
        std::ifstream stream(directory / st::FileStore::RecordName, std::ios::binary);
        CHECK(stream.good()); const Bytes wire{std::istreambuf_iterator<char>(stream), {}};
        CHECK(std::search(wire.begin(), wire.end(), rawProposal.begin(), rawProposal.end()) == wire.end());
        auto wrong = localKey; wrong[0] ^= 1;
        rejects([&] { st::FileStore disk(directory, binding, wrong); TrustJournal journal(disk, f.genesis, f.local()); journal.inspect(); });
        std::filesystem::remove(directory / st::FileStore::RecordName);
        rejects([&] { st::FileStore disk(directory, binding, localKey); TrustJournal journal(disk, f.genesis, f.local()); journal.inspect(); });
        CHECK(!std::filesystem::exists(directory / st::FileStore::RecordName));
    });
#endif
    std::cout << cases << " device-trust journal test cases passed\n";
}
