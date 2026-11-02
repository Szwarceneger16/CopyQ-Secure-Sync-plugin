// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_trust.h"
#include "test_check.h"
#include "fixtures/device_trust_vectors.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <numeric>
#include <random>
#include <string>
#include <vector>

using namespace cqs::trust;
namespace {
int cases = 0;
void test(const char *name, const std::function<void()> &body)
{
    body();
    ++cases;
    std::cout << "PASS " << name << '\n';
}
void rejects(const std::function<void()> &body)
{
    bool failed = false;
    try { body(); }
    catch (const Error &) { failed = true; }
    CHECK(failed);
}
void rejects(ErrorCode code, const std::function<void()> &body)
{
    bool failed = false;
    try { body(); }
    catch (const Error &error) { failed = true; CHECK(error.code() == code); }
    CHECK(failed);
}
Token token(std::uint32_t value)
{
    Token result{};
    result[0] = 0xa5;
    for (unsigned i = 0; i < 4; ++i)
        result[31 - i] = static_cast<std::uint8_t>(value >> (i * 8));
    return result;
}
Token repeated(std::uint8_t byte)
{
    Token result{}; result.fill(byte); return result;
}
std::string hex(const cqs::crypto::Bytes &bytes)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : bytes) {
        result += digits[byte >> 4]; result += digits[byte & 15];
    }
    return result;
}
std::string hex(const Token &bytes)
{
    return hex(cqs::crypto::Bytes(bytes.begin(), bytes.end()));
}
Member member(std::uint32_t value)
{
    return {token(3 * value + 1), token(3 * value + 2), token(3 * value + 3)};
}

// PUBLIC TEST DOUBLE ONLY. Anyone can create these values without a private
// key. This exercises message/key selection and tampering, NOT real signature
// security. It is deliberately confined to this test translation unit.
Signature testSignature(const Token &key, const cqs::crypto::Bytes &message)
{
    cqs::crypto::Bytes input{'P','U','B','L','I','C','-','T','E','S','T','-','O','N','L','Y'};
    input.insert(input.end(), key.begin(), key.end());
    input.insert(input.end(), message.begin(), message.end());
    const auto first = cqs::crypto::sha256(input);
    input.push_back(1);
    const auto second = cqs::crypto::sha256(input);
    Signature result{};
    std::copy(first.begin(), first.end(), result.begin());
    std::copy(second.begin(), second.end(), result.begin() + 32);
    return result;
}
class TestVerifier final : public SignatureVerifier {
public:
    bool verify(const Token &key, const cqs::crypto::Bytes &message,
                const Signature &signature) const override
    {
        return signature == testSignature(key, message);
    }
};
const TestVerifier verifier;
Approval approval(const Proposal &p, const Member &signer)
{
    return {signer.id, testSignature(signer.signingKey, approvalBytes(p, signer))};
}
Certificate certificate(const Proposal &p, const std::vector<Member> &signers)
{
    Certificate result{p, {}};
    for (const auto &signer : signers)
        result.approvals.push_back(approval(p, signer));
    return result;
}
Membership genesis()
{
    return Membership(token(100000), member(1), token(100001), token(13));
}
Proposal add(const Membership &m, std::uint32_t who, std::uint32_t request = 1,
             std::uint64_t created = 100, std::uint64_t expires = 200)
{
    return m.propose(Operation::Add, member(who), token(200000 + request),
                     token(300000 + request), created, expires);
}
void apply(Membership &m, const Proposal &p, const std::vector<Member> &signers,
           std::uint64_t now = 100)
{
    CHECK(m.observe(certificate(p, signers), now, verifier) == ObserveResult::Applied);
}
Membership group(std::uint32_t count)
{
    auto m = genesis();
    for (std::uint32_t i = 2; i <= count; ++i)
        apply(m, add(m, i, i), i == 2 ? std::vector<Member>{member(1)}
                                    : std::vector<Member>{member(1), member(2)});
    return m;
}
void unchanged(const Membership &m, const State &prior, std::size_t count)
{
    CHECK(m.current().digest == prior.digest);
    CHECK(m.current().members == prior.members);
    CHECK(m.current().keyGeneration == prior.keyGeneration);
    CHECK(m.current().keyCommitment == prior.keyCommitment);
    CHECK(m.current().bootstrapConsumed == prior.bootstrapConsumed);
    CHECK(m.stateCount() == count);
    CHECK(!m.forked());
}
} // namespace

int main()
{
    test("genesis is deterministic, pinned and owns its inputs", [] {
        auto a = genesis(); auto b = genesis();
        CHECK(a.current().digest == b.current().digest);
        CHECK(a.current().root == b.current().root);
        CHECK(a.current().members == std::vector<Member>{member(1)});
        CHECK(!a.current().bootstrapConsumed);
        CHECK(a.current().epoch == 0);
        CHECK(a.stateCount() == 1);
        CHECK(a.reservationCount() == 0);
        auto otherGroup = Membership(token(100002), member(1), token(100001), token(13));
        auto otherRecovery = Membership(token(100000), member(1), token(100002), token(13));
        auto otherKey = Membership(token(100000), member(1), token(100001), token(14));
        CHECK(a.current().root != otherGroup.current().root);
        CHECK(a.current().root != otherRecovery.current().root);
        CHECK(a.current().root != otherKey.current().root);
    });
    test("invalid genesis identities and zero trust anchors fail closed", [] {
        rejects([] { Membership m({}, member(1), token(1), token(13)); });
        rejects([] { Membership m(token(1), member(1), {}, token(13)); });
        rejects([] { Membership m(token(1), member(1), token(2), {}); });
        auto bad = member(1); bad.id = {};
        rejects([&] { Membership m(token(1), bad, token(2), token(13)); });
        bad = member(1); bad.signingKey = {};
        rejects([&] { Membership m(token(1), bad, token(2), token(13)); });
        bad = member(1); bad.encryptionKey = {};
        rejects([&] { Membership m(token(1), bad, token(2), token(13)); });
    });
    test("only initial second-device bootstrap has one approval", [] {
        auto m = genesis(); const auto p = add(m, 2);
        rejects(ErrorCode::NoQuorum, [&] { m.observe(certificate(p, {}), 100, verifier); });
        apply(m, p, {member(1)});
        CHECK(m.current().bootstrapConsumed);
        CHECK(m.current().members.size() == 2);
        CHECK(m.current().epoch == 1);
        const auto next = add(m, 3, 2);
        const auto prior = m.current();
        rejects(ErrorCode::NoQuorum, [&] { m.observe(certificate(next, {member(1)}), 100, verifier); });
        unchanged(m, prior, 2);
        apply(m, next, {member(1), member(2)});
        CHECK(m.current().members.size() == 3);
    });
    test("two different identities and keys required; duplicate votes cannot add", [] {
        auto m = group(2); const auto p = add(m, 3);
        const auto prior = m.current();
        auto repeated = certificate(p, {member(1), member(1)});
        rejects(ErrorCode::DuplicateApproval, [&] { m.observe(repeated, 100, verifier); });
        unchanged(m, prior, 2);
        repeated.approvals[1].signer = member(2).id;
        rejects(ErrorCode::BadSignature, [&] { m.observe(repeated, 100, verifier); });
        unchanged(m, prior, 2);
    });
    test("applicant and unknown identities cannot vote, even as extra approvals", [] {
        auto m = group(2); const auto p = add(m, 3);
        const auto prior = m.current();
        for (const auto &signers : std::vector<std::vector<Member>>{
                {member(1), member(3)}, {member(3), member(2)},
                {member(1), member(2), member(4)}}) {
            rejects([&] { m.observe(certificate(p, signers), 100, verifier); });
            unchanged(m, prior, 2);
        }
    });
    test("bad extra signatures reject whole certificate without partial mutation", [] {
        auto m = group(3); const auto p = add(m, 4);
        auto cert = certificate(p, {member(1), member(2), member(3)});
        cert.approvals.back().signature[0] ^= 1;
        const auto prior = m.current();
        rejects(ErrorCode::BadSignature, [&] { m.observe(cert, 100, verifier); });
        unchanged(m, prior, 3);
        apply(m, p, {member(2), member(3)});
    });
    test("signature adapter exceptions fail closed without advancing membership", [] {
        class ThrowingVerifier final : public SignatureVerifier {
        public:
            bool verify(const Token &, const cqs::crypto::Bytes &, const Signature &) const override
            { throw std::runtime_error("PUBLIC TEST adapter failure"); }
        } throwing;
        auto m = group(2); const auto prior = m.current();
        const auto cert = certificate(add(m, 3), {member(1), member(2)});
        rejects(ErrorCode::BadSignature, [&] { m.observe(cert, 100, throwing); });
        unchanged(m, prior, 2);
    });
    test("active IDs, signing keys and encryption keys cannot be re-enrolled", [] {
        auto m = group(2);
        for (unsigned field = 0; field != 3; ++field) {
            auto duplicate = member(3);
            if (field == 0) duplicate.id = member(1).id;
            if (field == 1) duplicate.signingKey = member(1).signingKey;
            if (field == 2) duplicate.encryptionKey = member(1).encryptionKey;
            rejects([&] { m.propose(Operation::Add, duplicate, token(10), token(11), 100, 200); });
        }
    });
    test("founder removal is approved by survivors and changes key generation", [] {
        auto m = group(3); const auto old = m.current();
        const auto p = m.propose(Operation::Remove, member(1), token(10), token(11), 100, 200, token(600001));
        rejects([&] { m.observe(certificate(p, {member(1), member(2)}), 100, verifier); });
        unchanged(m, old, 3);
        apply(m, p, {member(2), member(3)});
        CHECK(m.current().members == std::vector<Member>({member(2), member(3)}));
        CHECK(m.current().retired == std::vector<Member>{member(1)});
        CHECK(m.current().keyGeneration == old.keyGeneration + 1);
        CHECK(m.current().keyCommitment == token(600001));
        CHECK(m.current().keyCommitment != old.keyCommitment);
        CHECK(m.current().bootstrapConsumed);
        apply(m, add(m, 4), {member(2), member(3)});
        CHECK(m.current().members.size() == 3);
    });
    test("key commitment is preserved on addition and removal needs new nonzero commitment", [] {
        auto m = group(3); const auto prior = m.current();
        rejects([&] { m.propose(Operation::Add, member(4), token(10), token(11), 100, 200, token(999)); });
        rejects([&] { m.propose(Operation::Remove, member(1), token(10), token(11), 100, 200); });
        rejects([&] { m.propose(Operation::Remove, member(1), token(10), token(11), 100, 200, prior.keyCommitment); });
        unchanged(m, prior, 3);
        const auto p = add(m, 4);
        CHECK(p.keyCommitment == prior.keyCommitment);
        apply(m, p, {member(1), member(2)});
        CHECK(m.current().keyCommitment == prior.keyCommitment);
    });
    test("changed rotated commitment cannot reuse approvals and different key intents fork", [] {
        auto m = group(3);
        const auto p = m.propose(Operation::Remove, member(1), token(10), token(11),
                                 100, 200, token(600001));
        const auto cert = certificate(p, {member(2), member(3)});
        auto changed = cert; changed.proposal.keyCommitment = token(600002);
        const auto before = m.current();
        rejects(ErrorCode::BadSignature, [&] { m.observe(changed, 100, verifier); });
        unchanged(m, before, 3);
        CHECK(m.observe(cert, 100, verifier) == ObserveResult::Applied);
        const auto accepted = m.current().digest;
        CHECK(m.observe(certificate(changed.proposal, {member(2), member(3)}), 100, verifier)
              == ObserveResult::ForkDetected);
        CHECK(m.current().digest == accepted); CHECK(m.forked());
    });
    test("retired identity and keys cannot masquerade as fresh enrollment", [] {
        auto m = group(3);
        apply(m, m.propose(Operation::Remove, member(1), token(10), token(11), 100, 200, token(600001)),
              {member(2), member(3)});
        for (unsigned field = 0; field != 3; ++field) {
            auto duplicate = member(4);
            if (field == 0) duplicate.id = member(1).id;
            if (field == 1) duplicate.signingKey = member(1).signingKey;
            if (field == 2) duplicate.encryptionKey = member(1).encryptionKey;
            rejects([&] { m.propose(Operation::Add, duplicate, token(20), token(21), 100, 200); });
        }
    });
    test("ordinary two-member removal never lowers threshold or restores bootstrap", [] {
        auto m = group(2); const auto prior = m.current();
        rejects([&] { m.propose(Operation::Remove, member(1), token(10), token(11), 100, 200, token(600001)); });
        unchanged(m, prior, 2);
        rejects([&] { m.propose(Operation::Remove, member(9), token(10), token(11), 100, 200, token(600001)); });
    });
    test("removal must identify exact admitted keys, not just matching member ID", [] {
        auto m = group(3); auto forged = member(1); forged.encryptionKey = member(9).encryptionKey;
        rejects([&] { m.propose(Operation::Remove, forged, token(10), token(11), 100, 200, token(600001)); });
    });
    test("canonical signed intent binds every proposal field", [] {
        auto m = group(2); const auto p = add(m, 3);
        const auto cert = certificate(p, {member(1), member(2)});
        const auto digest = proposalDigest(p);
        const std::vector<std::function<void(Proposal &)>> changes{
            [](auto &v) { v.version += 1; }, [](auto &v) { v.group = token(42); },
            [](auto &v) { v.root = token(42); }, [](auto &v) { v.parent = token(42); },
            [](auto &v) { v.parentEpoch += 1; }, [](auto &v) { v.keyGeneration += 1; },
            [](auto &v) { v.keyCommitment = token(42); },
            [](auto &v) { v.operation = Operation::Remove; }, [](auto &v) { v.subject.id = token(42); },
            [](auto &v) { v.subject.signingKey = token(42); }, [](auto &v) { v.subject.encryptionKey = token(42); },
            [](auto &v) { v.request = token(42); }, [](auto &v) { v.nonce = token(42); },
            [](auto &v) { v.created -= 1; }, [](auto &v) { v.expires += 1; }};
        for (const auto &change : changes) {
            auto bad = cert; change(bad.proposal);
            const auto prior = m.current();
            rejects([&] { m.observe(bad, 100, verifier); });
            unchanged(m, prior, 2);
            if (bad.proposal.version == Version)
                CHECK(proposalDigest(bad.proposal) != digest);
        }
    });
    test("approver-specific verification and signature bytes bind endpoint keys", [] {
        const auto m = group(2); const auto p = add(m, 3);
        CHECK(verificationDigest(p, member(1)) != verificationDigest(p, member(2)));
        CHECK(approvalBytes(p, member(1)) != approvalBytes(p, member(2)));
        CHECK(approvalBytes(p, member(1)) != encodeProposal(p));
        auto changed = member(1); changed.encryptionKey = token(42);
        CHECK(verificationDigest(p, changed) != verificationDigest(p, member(1)));
        changed = member(1); changed.signingKey = token(42);
        CHECK(verificationDigest(p, changed) != verificationDigest(p, member(1)));
    });
    test("unknown group, root and missing parent cannot become an accepted head", [] {
        auto m = group(2); const auto prior = m.current();
        auto cert = certificate(add(m, 3), {member(1), member(2)});
        cert.proposal.group = token(777);
        rejects(ErrorCode::WrongGroup, [&] { m.observe(cert, 100, verifier); });
        cert.proposal = add(m, 3); cert.proposal.root = token(777);
        rejects(ErrorCode::WrongGroup, [&] { m.observe(cert, 100, verifier); });
        cert.proposal = add(m, 3); cert.proposal.parent = token(777);
        rejects(ErrorCode::MissingParent, [&] { m.observe(cert, 100, verifier); });
        unchanged(m, prior, 2);
    });
    test("clock window is inclusive at creation and exclusive at expiry", [] {
        for (const std::uint64_t now : {std::uint64_t{99}, std::uint64_t{200}, std::uint64_t{201}}) {
            auto m = group(2); const auto prior = m.current();
            rejects([&] { m.observe(certificate(add(m, 3), {member(1), member(2)}), now, verifier); });
            unchanged(m, prior, 2);
        }
        auto m = group(2); apply(m, add(m, 3), {member(1), member(2)}, 100);
    });
    test("invalid lifetimes, empty request material and unsupported protocol reject", [] {
        const auto m = group(2);
        for (const auto &times : std::vector<std::pair<std::uint64_t, std::uint64_t>>{
                {100, 100}, {101, 100}, {0, MaxLifetime + 1},
                {1, std::numeric_limits<std::uint64_t>::max()}})
            rejects([&] { add(m, 3, 1, times.first, times.second); });
        rejects([&] { m.propose(Operation::Add, member(3), {}, token(1), 100, 200); });
        rejects([&] { m.propose(Operation::Add, member(3), token(1), {}, 100, 200); });
        rejects([&] { m.propose(static_cast<Operation>(255), member(3), token(1), token(2), 100, 200); });
        auto p = add(m, 3); p.version = Version + 1;
        rejects([&] { encodeProposal(p); });
    });
    test("upper uint64 timestamps do not wrap or extend lifetime", [] {
        auto m = group(2);
        const auto end = std::numeric_limits<std::uint64_t>::max();
        const auto p = add(m, 3, 1, end - 10, end);
        apply(m, p, {member(1), member(2)}, end - 1);
        CHECK(m.current().members.size() == 3);
    });
    test("accepted exact intent retry is idempotent even after expiry", [] {
        auto m = group(2); const auto p = add(m, 3);
        auto cert = certificate(p, {member(1), member(2)});
        CHECK(m.observe(cert, 100, verifier) == ObserveResult::Applied);
        const auto prior = m.current(); const auto count = m.stateCount();
        std::reverse(cert.approvals.begin(), cert.approvals.end());
        CHECK(m.observe(cert, 10000, verifier) == ObserveResult::AlreadyKnown);
        unchanged(m, prior, count);
    });
    test("an invalid historical sibling cannot create a fork or mutate witnesses", [] {
        auto m = group(3); const auto x = add(m, 4, 10), y = add(m, 5, 11);
        apply(m, x, {member(1), member(2)});
        const auto prior = m.current(); auto cert = certificate(y, {member(1), member(2)});
        cert.approvals.front().signature[0] ^= 1;
        rejects(ErrorCode::BadSignature, [&] { m.observe(cert, 10000, verifier); });
        unchanged(m, prior, 4);
        CHECK(m.forkEvidence().empty());
    });
    test("deep delayed expired fork latches and never selects a winner", [] {
        auto m = group(3); const auto old = m.current();
        const auto x = add(m, 4, 10), sibling = add(m, 5, 11);
        apply(m, x, {member(1), member(2)});
        apply(m, add(m, 6, 12), {member(2), member(3)});
        const auto latest = m.current();
        CHECK(m.observe(certificate(sibling, {member(2), member(3)}), 10000, verifier)
              == ObserveResult::ForkDetected);
        CHECK(m.forked()); CHECK(m.forkEvidence().size() >= 2);
        CHECK(m.current().digest == latest.digest);
        CHECK(m.current().digest != old.digest);
        rejects(ErrorCode::Forked, [&] { add(m, 7, 13); });
        rejects(ErrorCode::Forked, [&] { m.reserve(x, member(1).id, 100); });
    });
    test("reservation is immutable per signer and parent across timeout and model copy", [] {
        auto m = group(2); const auto x = add(m, 3, 10), y = add(m, 4, 11);
        CHECK(m.reserve(x, member(1).id, 100) == ReserveResult::Reserved);
        CHECK(m.reserve(x, member(1).id, 100) == ReserveResult::AlreadyReserved);
        CHECK(m.reservationCount() == 1);
        rejects(ErrorCode::Blocked, [&] { m.reserve(y, member(1).id, 100); });
        auto copied = m; // In-memory ownership test only; not disk recovery evidence.
        rejects([&] { copied.reserve(y, member(1).id, 10000); });
        CHECK(copied.reservationCount() == 1);
        CHECK(m.reservationCount() == 1);
        rejects([&] { m.reserve(x, member(3).id, 100); });
    });
    test("split partial votes cannot be silently moved to another request", [] {
        auto m = group(2); const auto x = add(m, 3, 10), y = add(m, 4, 11);
        CHECK(m.reserve(x, member(1).id, 100) == ReserveResult::Reserved);
        CHECK(m.reserve(y, member(2).id, 100) == ReserveResult::Reserved);
        rejects(ErrorCode::Blocked, [&] { m.reserve(y, member(1).id, 100); });
        rejects(ErrorCode::Blocked, [&] { m.reserve(x, member(2).id, 100); });
        rejects(ErrorCode::NoQuorum, [&] { m.observe(certificate(x, {member(1)}), 100, verifier); });
        rejects(ErrorCode::NoQuorum, [&] { m.observe(certificate(y, {member(2)}), 100, verifier); });
        CHECK(m.reservationCount() == 2); CHECK(m.current().members.size() == 2);
    });
    test("reservation against a historical parent cannot sign after head advances", [] {
        auto m = group(2); const auto stale = add(m, 3, 10);
        apply(m, add(m, 4, 11), {member(1), member(2)});
        rejects(ErrorCode::Stale, [&] { m.reserve(stale, member(1).id, 100); });
    });
    test("exact proposal codec rejects every truncation and trailing bytes", [] {
        const auto m = group(2); const auto p = add(m, 3);
        const auto encoded = encodeProposal(p);
        CHECK(encodeProposal(decodeProposal(encoded)) == encoded);
        for (std::size_t size = 0; size < encoded.size(); ++size)
            rejects([&] { decodeProposal(cqs::crypto::Bytes(encoded.begin(), encoded.begin() + size)); });
        auto extra = encoded; extra.push_back(0);
        rejects([&] { decodeProposal(extra); });
        rejects([&] { decodeProposal(cqs::crypto::Bytes(100000, 0)); });
    });
    test("proposal decoder rejects unknown versions, operations and zero identities", [] {
        const auto m = group(2); const auto encoded = encodeProposal(add(m, 3));
        constexpr auto versionOffset = sizeof("CopyQ-Secure-Sync-membership-intent-model-v1");
        auto bad = encoded; bad[versionOffset + 3] = 2;
        rejects([&] { decodeProposal(bad); });
        constexpr auto operationOffset = versionOffset + 4 + 4 * 32 + 2 * 8;
        bad = encoded; bad[operationOffset] = 255;
        rejects([&] { decodeProposal(bad); });
        bad = encoded;
        std::fill_n(bad.begin() + static_cast<std::ptrdiff_t>(operationOffset + 1), 32, 0);
        rejects([&] { decodeProposal(bad); });
        bad = encoded; bad[0] ^= 1;
        rejects([&] { decodeProposal(bad); });
    });
    test("independent Python fixed-width and SHA256 vectors agree exactly", [] {
        using namespace cqs::trust::fixtures;
        Proposal p;
        p.group = repeated(1); p.root = repeated(2); p.parent = repeated(3);
        p.parentEpoch = 7; p.keyGeneration = 3; p.keyCommitment = repeated(13);
        p.subject = {repeated(4), repeated(5), repeated(6)};
        p.request = repeated(7); p.nonce = repeated(8);
        p.created = 100; p.expires = 1000;
        const Member signer{repeated(9), repeated(10), repeated(11)};
        CHECK(hex(encodeProposal(p)) == ProposalHex);
        CHECK(hex(proposalDigest(p)) == ProposalDigestHex);
        CHECK(hex(verificationDigest(p, signer)) == VerificationHex);
        CHECK(hex(approvalBytes(p, signer)) == ApprovalHex);
        Signature a{}, b{}; a.fill(0xa1); b.fill(0xb2);
        const Certificate cert{p, {{repeated(9), a}, {repeated(12), b}}};
        CHECK(hex(encodeCertificate(cert)) == CertificateHex);
    });
    test("exact certificate codec roundtrip and malformed bounds", [] {
        const auto m = group(2); auto cert = certificate(add(m, 3), {member(1), member(2)});
        const auto encoded = encodeCertificate(cert);
        CHECK(encodeCertificate(decodeCertificate(encoded)) == encoded);
        for (std::size_t size = 0; size < encoded.size(); ++size)
            rejects([&] { decodeCertificate(cqs::crypto::Bytes(encoded.begin(), encoded.begin() + size)); });
        auto extra = encoded; extra.push_back(0);
        rejects([&] { decodeCertificate(extra); });
        rejects([&] { decodeCertificate(cqs::crypto::Bytes(100000, 0)); });
        cert.approvals.resize(MaxMembers + 1);
        rejects([&] { encodeCertificate(cert); });
    });
    test("certificate decoder rejects noncanonical order and attacker-controlled counts", [] {
        const auto m = group(2); const auto p = add(m, 3);
        const auto cert = certificate(p, {member(1), member(2)});
        const auto encoded = encodeCertificate(cert);
        constexpr std::size_t entrySize = 32 + 64;
        const auto countOffset = sizeof("CopyQ-Secure-Sync-membership-certificate-model-v1") + encodeProposal(p).size();
        const auto entriesOffset = countOffset + 4;
        CHECK(encoded.size() == entriesOffset + 2 * entrySize);
        auto bad = encoded;
        std::swap_ranges(bad.begin() + static_cast<std::ptrdiff_t>(entriesOffset),
                         bad.begin() + static_cast<std::ptrdiff_t>(entriesOffset + entrySize),
                         bad.begin() + static_cast<std::ptrdiff_t>(entriesOffset + entrySize));
        rejects([&] { decodeCertificate(bad); });
        for (const std::uint8_t countByte : {std::uint8_t{0}, std::uint8_t{33}, std::uint8_t{255}}) {
            bad = encoded;
            std::fill_n(bad.begin() + static_cast<std::ptrdiff_t>(countOffset), 4, countByte);
            rejects([&] { decodeCertificate(bad); });
        }
        bad = encoded;
        std::fill_n(bad.begin() + static_cast<std::ptrdiff_t>(entriesOffset), 32, 0);
        rejects([&] { decodeCertificate(bad); });
        bad = encoded;
        std::fill_n(bad.begin() + static_cast<std::ptrdiff_t>(entriesOffset + 32), 64, 0);
        rejects([&] { decodeCertificate(bad); });
    });
    test("deterministic malformed-input corpus has exact canonical roundtrip or refusal", [] {
        const auto m = group(2); const auto p = add(m, 3);
        const auto proposalBytes = encodeProposal(p);
        const auto certificateBytes = encodeCertificate(certificate(p, {member(1), member(2)}));
        std::mt19937 random(0x43515432U);
        std::size_t accepted = 0, refused = 0;
        for (unsigned trial = 0; trial < 1200; ++trial) {
            const bool isProposal = trial % 2 == 0;
            auto bytes = isProposal ? proposalBytes : certificateBytes;
            for (unsigned edits = 1 + random() % 4; edits; --edits) {
                const auto position = static_cast<std::size_t>(random()) % (bytes.size() + 1);
                switch (random() % 4) {
                case 0:
                    if (position < bytes.size()) bytes[position] ^= static_cast<std::uint8_t>(1U << (random() % 8));
                    break;
                case 1:
                    bytes.insert(bytes.begin() + static_cast<std::ptrdiff_t>(position),
                                 static_cast<std::uint8_t>(random()));
                    break;
                case 2:
                    if (position < bytes.size()) bytes.erase(bytes.begin() + static_cast<std::ptrdiff_t>(position));
                    break;
                default:
                    if (position < bytes.size()) bytes[position] = static_cast<std::uint8_t>(random());
                    break;
                }
            }
            try {
                if (isProposal) CHECK(encodeProposal(decodeProposal(bytes)) == bytes);
                else CHECK(encodeCertificate(decodeCertificate(bytes)) == bytes);
                ++accepted;
            } catch (const Error &) { ++refused; }
        }
        CHECK(accepted > 100); CHECK(refused > 500); CHECK(accepted + refused == 1200);
        std::cout << "  parsed " << accepted << " canonical mutated inputs; refused " << refused << '\n';
    });
    test("bounded membership never silently evicts identities", [] {
        auto m = group(static_cast<std::uint32_t>(MaxMembers));
        CHECK(m.current().members.size() == MaxMembers);
        const auto prior = m.current();
        rejects(ErrorCode::Limit, [&] { add(m, static_cast<std::uint32_t>(MaxMembers + 1)); });
        unchanged(m, prior, MaxMembers);
    });
    test("retained state capacity refuses growth but preserves retry and deep fork evidence", [] {
        auto m = group(3);
        const auto historicalSibling = add(m, 10000, 10000);
        Certificate last;
        std::uint32_t next = 4;
        while (m.stateCount() < MaxStates) {
            Proposal p;
            std::vector<Member> signers;
            if (m.current().members.size() == 2) {
                p = add(m, next, 1000 + next);
                ++next;
                signers = m.current().members;
            } else {
                const auto target = m.current().members.front();
                p = m.propose(Operation::Remove, target, token(400000 + next),
                              token(500000 + next), 100, 200, token(static_cast<std::uint32_t>(600001 + m.current().keyGeneration)));
                for (const auto &signer : m.current().members)
                    if (signer.id != target.id) signers.push_back(signer);
            }
            last = certificate(p, signers);
            CHECK(m.observe(last, 100, verifier) == ObserveResult::Applied);
        }
        CHECK(m.stateCount() == MaxStates);
        const auto prior = m.current();
        rejects(ErrorCode::Limit, [&] { add(m, 20000, 20000); });
        CHECK(m.observe(last, 10000, verifier) == ObserveResult::AlreadyKnown);
        unchanged(m, prior, MaxStates);
        CHECK(m.observe(certificate(historicalSibling, {member(1), member(2)}), 10000, verifier)
              == ObserveResult::ForkDetected);
        CHECK(m.forked()); CHECK(m.stateCount() == MaxStates);
    });
    test("all small quorum subsets follow independent cardinality oracle", [] {
        std::size_t schedules = 0;
        for (std::uint32_t n = 1; n <= 4; ++n) {
            for (unsigned mask = 0; mask < (1U << n); ++mask) {
                auto m = group(n); const auto p = add(m, n + 1, 50 + mask);
                std::vector<Member> votes;
                for (std::uint32_t i = 0; i < n; ++i)
                    if (mask & (1U << i)) votes.push_back(member(i + 1));
                const bool authorized = votes.size() >= (n == 1 ? 1U : 2U);
                do {
                    auto copy = m;
                    const auto cert = certificate(p, votes);
                    if (authorized) CHECK(copy.observe(cert, 100, verifier) == ObserveResult::Applied);
                    else rejects(ErrorCode::NoQuorum, [&] { copy.observe(cert, 100, verifier); });
                    ++schedules;
                } while (std::next_permutation(votes.begin(), votes.end(),
                             [](const Member &a, const Member &b) { return a.id < b.id; }));
            }
        }
        CHECK(schedules > 80);
        std::cout << "  explored " << schedules << " quorum subset/order schedules\n";
    });
    test("all two-vote pairs expose fixed-threshold fork limitation in either order", [] {
        std::size_t schedules = 0;
        for (std::uint32_t n = 2; n <= 4; ++n) {
            const auto base = group(n);
            const auto x = add(base, 10, 100), y = add(base, 11, 101);
            for (std::uint32_t a = 1; a <= n; ++a)
                for (std::uint32_t b = a + 1; b <= n; ++b)
                    for (std::uint32_t c = 1; c <= n; ++c)
                        for (std::uint32_t d = c + 1; d <= n; ++d)
                            for (bool reverse : {false, true}) {
                                auto m = base;
                                const auto first = certificate(reverse ? y : x, {member(a), member(b)});
                                const auto second = certificate(reverse ? x : y, {member(c), member(d)});
                                CHECK(m.observe(first, 100, verifier) == ObserveResult::Applied);
                                const auto prior = m.current().digest;
                                CHECK(m.observe(second, 100, verifier) == ObserveResult::ForkDetected);
                                CHECK(m.forked()); CHECK(m.current().digest == prior);
                                ++schedules;
                            }
        }
        CHECK(schedules == 92);
        std::cout << "  explored " << schedules << " competing certificate schedules\n";
    });
    std::cout << cases << " device-trust policy/model test cases passed\n";
}
