// SPDX-License-Identifier: GPL-3.0-or-later
#include "history.h"
#include "test_check.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace cqs::history;
namespace {
int cases = 0;
void test(const char *name, const std::function<void()> &body)
{
    body();
    ++cases;
    std::cout << "PASS " << name << '\n';
}
void rejects(ErrorCode expected, const std::function<void()> &body)
{
    bool failed = false;
    try { body(); }
    catch (const Error &error) { failed = true; CHECK(error.code() == expected); }
    CHECK(failed);
}
Revision rev(const std::string &device, std::uint64_t sequence,
             std::vector<std::string> parents = {})
{
    std::sort(parents.begin(), parents.end());
    return {makeId(device, sequence), device, sequence, std::move(parents)};
}
} // namespace

int main()
{
    const auto a = rev("mint-lab", 1);
    const auto b = rev("win-lab", 1, {a.id});
    const auto c = rev("mint-lab", 2, {a.id});
    const auto merge = rev("mint-lab", 3, {b.id, c.id});

    test("empty history", [&] {
        Graph g({}); CHECK(g.size() == 0); CHECK(g.tips().empty());
        CHECK(!g.hasConflict()); CHECK(g.nextSequence("mint-lab") == 1);
        CHECK(!g.isAncestor(a.id, a.id));
    });
    test("one root", [&] {
        Graph g({a}); CHECK(g.contains(a.id)); CHECK(g.isAncestor(a.id, a.id));
        CHECK(g.tips() == std::vector<std::string>{a.id}); CHECK(g.nextSequence(a.device) == 2);
    });
    test("two-device fast-forward", [&] {
        Graph g({a, b}); CHECK(g.isAncestor(a.id, b.id)); CHECK(!g.isAncestor(b.id, a.id));
        CHECK(g.tips() == std::vector<std::string>{b.id}); CHECK(!g.hasConflict());
    });
    test("parallel changes preserve both tips", [&] {
        Graph g({a, b, c}); CHECK(g.hasConflict());
        CHECK(g.tips() == std::vector<std::string>({c.id, b.id}));
        CHECK(!g.isAncestor(b.id, c.id)); CHECK(!g.isAncestor(c.id, b.id));
    });
    test("explicit two-parent merge", [&] {
        Graph g({a, b, c, merge}); CHECK(!g.hasConflict());
        CHECK(g.tips() == std::vector<std::string>{merge.id});
        CHECK(g.isAncestor(b.id, merge.id)); CHECK(g.isAncestor(c.id, merge.id));
        CHECK(g.nextSequence("mint-lab") == 4); CHECK(g.nextSequence("win-lab") == 2);
    });
    test("independent seeds are a conflict, not a winner", [&] {
        Graph g({a, rev("win-lab", 1)}); CHECK(g.hasConflict()); CHECK(g.tips().size() == 2);
    });
    test("more than two tips remain visible", [&] {
        Graph g({a, b, c, rev("third-pc", 1, {a.id})}); CHECK(g.tips().size() == 3);
    });
    test("arbitrary input ordering", [&] {
        Graph g({merge, c, b, a}); CHECK(g.isAncestor(a.id, merge.id));
        CHECK(g.tips() == Graph({a, b, c, merge}).tips());
    });
    test("missing direct parent defers", [&] {
        rejects(ErrorCode::MissingParent, [&] { Graph g({b}); });
    });
    test("missing transitive parent defers", [&] {
        rejects(ErrorCode::MissingParent, [&] { Graph g({b, rev("win-lab", 2, {b.id})}); });
    });
    test("malformed metadata is not hidden by missing parent", [&] {
        auto bad = c; bad.sequence = 0;
        rejects(ErrorCode::InvalidIdentity, [&] { Graph g({b, bad}); });
    });
    test("duplicate identical revision rejected", [&] {
        rejects(ErrorCode::DuplicateRevision, [&] { Graph g({a, a}); });
    });
    test("duplicate identity with different parents rejected", [&] {
        auto fork = b; fork.parents.clear();
        rejects(ErrorCode::DuplicateRevision, [&] { Graph g({a, b, fork}); });
    });
    test("ID must agree with header", [&] {
        auto bad = a; bad.id = b.id;
        rejects(ErrorCode::InvalidIdentity, [&] { Graph g({bad}); });
    });
    test("zero and out-of-range sequence", [&] {
        for (auto n : {std::uint64_t{0}, MaxSequence + 1})
            rejects(ErrorCode::InvalidIdentity, [&] { makeId("mint-lab", n); });
    });
    test("strict portable device identity", [&] {
        const std::vector<std::string> bad{"", "ab", "Abc", "1pc", "a_b", "../pc", "pc/x", "a\\b",
            "abc\n", "abc ", std::string(33, 'a'), std::string("ab\0c", 4), "\xc3\xa9-pc"};
        for (const auto &name : bad)
            rejects(ErrorCode::InvalidIdentity, [&] { makeId(name, 1); });
        CHECK(makeId("abc", 1) == "abc/000000000001");
        CHECK(makeId(std::string(32, 'a'), MaxSequence).size() == 45);
    });
    test("strict parent identity", [&] {
        const std::vector<std::string> bad{"", "mint-lab/1", "mint-lab/000000000000", "mint-lab/00000000000x",
            "mint-lab/000000000001\n", "../mint/000000000001", "mint-lab\\000000000001", std::string(4096, 'x')};
        for (const auto &id : bad) {
            auto child = b; child.parents = {id};
            rejects(ErrorCode::InvalidIdentity, [&] { Graph g({child}); });
        }
    });
    test("too many parents", [&] {
        auto child = merge; child.parents = {a.id, b.id, c.id};
        rejects(ErrorCode::InvalidParents, [&] { Graph g({child}); });
    });
    test("duplicate parents", [&] {
        auto child = b; child.parents = {a.id, a.id};
        rejects(ErrorCode::InvalidParents, [&] { Graph g({child}); });
    });
    test("unsorted parents", [&] {
        auto child = merge; std::reverse(child.parents.begin(), child.parents.end());
        rejects(ErrorCode::InvalidParents, [&] { Graph g({child}); });
    });
    test("self reference", [&] {
        auto child = a; child.parents = {a.id};
        rejects(ErrorCode::InvalidParents, [&] { Graph g({child}); });
    });
    test("same device cannot reference its future", [&] {
        auto child = a; child.parents = {c.id}; auto future = c; future.parents.clear();
        rejects(ErrorCode::NonmonotonicParent, [&] { Graph g({child, future}); });
        rejects(ErrorCode::NonmonotonicParent, [&] { Graph g({child}); });
    });
    test("cross-device cycle", [&] {
        auto root = a; root.parents = {b.id};
        rejects(ErrorCode::Cycle, [&] { Graph g({root, b}); });
    });
    test("disconnected cycle is still rejected", [&] {
        auto root = a; root.parents = {b.id};
        rejects(ErrorCode::Cycle, [&] { Graph g({rev("third-pc", 1), root, b}); });
    });
    test("known cycle takes priority over missing files", [&] {
        auto root = a; root.parents = {b.id};
        const auto orphan = rev("third-pc", 1, {makeId("missing-pc", 1)});
        rejects(ErrorCode::Cycle, [&] { Graph g({orphan, root, b}); });
    });
    test("maximum chain is iterative", [&] {
        std::vector<Revision> chain;
        for (std::size_t i = 1; i <= MaxEvents; ++i)
            chain.push_back(rev("mint-lab", i, i == 1 ? std::vector<std::string>{} : std::vector<std::string>{chain.back().id}));
        Graph g(chain); CHECK(g.size() == MaxEvents); CHECK(g.isAncestor(chain.front().id, chain.back().id));
        CHECK(g.tips() == std::vector<std::string>{chain.back().id}); CHECK(g.nextSequence("mint-lab") == MaxEvents + 1);
        chain.push_back(rev("mint-lab", MaxEvents + 1, {chain.back().id}));
        rejects(ErrorCode::LimitExceeded, [&] { Graph tooMany(chain); });
    });
    test("unknown ancestry never authorizes an import", [&] {
        Graph g({a, b}); const auto missing = makeId("missing-pc", 1);
        CHECK(!g.isAncestor(missing, missing)); CHECK(!g.isAncestor(missing, b.id));
        CHECK(!g.isAncestor(a.id, missing)); CHECK(!g.contains(missing));
    });
    test("sequence exhaustion fails closed", [&] {
        Graph g({rev("mint-lab", MaxSequence)});
        rejects(ErrorCode::SequenceExhausted, [&] { g.nextSequence("mint-lab"); });
        CHECK(g.nextSequence("win-lab") == 1);
        rejects(ErrorCode::InvalidIdentity, [&] { g.nextSequence("bad/name"); });
    });
    test("graph owns its metadata", [&] {
        std::vector<Revision> source{a, b}; Graph g(source); source.clear();
        CHECK(g.size() == 2); CHECK(g.isAncestor(a.id, b.id));
    });
    test("random DAGs match independent reachability oracle", [&] {
        std::mt19937 rng(0x43515331U);
        for (int trial = 0; trial < 100; ++trial) {
            const int n = 2 + static_cast<int>(rng() % 30);
            std::vector<Revision> nodes;
            std::vector<std::vector<bool>> reachable(n, std::vector<bool>(n));
            std::set<std::string> expectedTips;
            for (int i = 0; i < n; ++i) {
                std::vector<std::string> parents;
                for (int j = 0, count = i == 0 ? 0 : static_cast<int>(rng() % 3); j < count; ++j) {
                    const int p = static_cast<int>(rng() % static_cast<unsigned>(i));
                    if (std::find(parents.begin(), parents.end(), nodes[p].id) == parents.end()) {
                        parents.push_back(nodes[p].id); reachable[p][i] = true; expectedTips.erase(nodes[p].id);
                    }
                }
                nodes.push_back(rev(i % 2 ? "win-lab" : "mint-lab", static_cast<std::uint64_t>(i + 1), parents));
                expectedTips.insert(nodes.back().id); reachable[i][i] = true;
            }
            for (int k = 0; k < n; ++k)
                for (int i = 0; i < n; ++i)
                    for (int j = 0; j < n; ++j)
                        reachable[i][j] = reachable[i][j] || (reachable[i][k] && reachable[k][j]);
            auto shuffled = nodes; std::shuffle(shuffled.begin(), shuffled.end(), rng);
            Graph g(shuffled);
            CHECK(g.tips() == std::vector<std::string>(expectedTips.begin(), expectedTips.end()));
            for (int i = 0; i < n; ++i)
                for (int j = 0; j < n; ++j)
                    CHECK(g.isAncestor(nodes[i].id, nodes[j].id) == reachable[i][j]);
        }
    });
    std::cout << cases << " history test cases passed\n";
}
