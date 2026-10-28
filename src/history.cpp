// SPDX-License-Identifier: GPL-3.0-or-later
#include "history.h"

#include <algorithm>
#include <set>
#include <utility>

namespace cqs::history {
namespace {
bool validDevice(const std::string &device)
{
    if (device.size() < 3 || device.size() > 32 || device[0] < 'a' || device[0] > 'z')
        return false;
    return std::all_of(device.begin(), device.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    });
}

std::pair<std::string, std::uint64_t> parseId(const std::string &id)
{
    // Bound length before searching/copying; neither regex nor locale is needed.
    if (id.size() < 16 || id.size() > 45)
        throw Error(ErrorCode::InvalidIdentity, "Invalid revision ID length");
    const auto slash = id.size() - 13;
    const auto device = id.substr(0, slash);
    if (id[slash] != '/' || !validDevice(device))
        throw Error(ErrorCode::InvalidIdentity, "Invalid revision device");
    std::uint64_t sequence = 0;
    for (auto i = slash + 1; i < id.size(); ++i) {
        const auto c = id[i];
        if (c < '0' || c > '9')
            throw Error(ErrorCode::InvalidIdentity, "Invalid revision sequence");
        sequence = sequence * 10 + static_cast<unsigned>(c - '0');
    }
    if (sequence == 0)
        throw Error(ErrorCode::InvalidIdentity, "Revision sequence cannot be zero");
    return {device, sequence};
}

} // namespace

void validateRevision(const Revision &revision)
{
    if (revision.id != makeId(revision.device, revision.sequence))
        throw Error(ErrorCode::InvalidIdentity, "Revision ID disagrees with its header");
    if (revision.parents.size() > 2 ||
        !std::is_sorted(revision.parents.begin(), revision.parents.end()) ||
        std::adjacent_find(revision.parents.begin(), revision.parents.end()) != revision.parents.end())
        throw Error(ErrorCode::InvalidParents, "Parents must be unique, sorted and at most two");
    for (const auto &parent : revision.parents) {
        const auto identity = parseId(parent);
        if (parent == revision.id)
            throw Error(ErrorCode::InvalidParents, "A revision cannot be its own parent");
        if (identity.first == revision.device && identity.second >= revision.sequence)
            throw Error(ErrorCode::NonmonotonicParent, "A revision refers to its device's future");
    }
}

std::string makeId(const std::string &device, std::uint64_t sequence)
{
    if (!validDevice(device) || sequence == 0 || sequence > MaxSequence)
        throw Error(ErrorCode::InvalidIdentity, "Invalid device or sequence");
    const auto number = std::to_string(sequence);
    return device + '/' + std::string(12 - number.size(), '0') + number;
}

Graph::Graph(const std::vector<Revision> &revisions)
{
    if (revisions.size() > MaxEvents)
        throw Error(ErrorCode::LimitExceeded, "Revision history exceeds the event limit");
    // Validate all metadata before classifying missing files as a deferred sync.
    for (const auto &revision : revisions) {
        validateRevision(revision);
        if (!revisions_.emplace(revision.id, revision).second)
            throw Error(ErrorCode::DuplicateRevision, "Duplicate revision ID");
    }

    std::map<std::string, std::size_t> indegree;
    std::map<std::string, std::vector<std::string>> children;
    std::set<std::string> referenced;
    bool missing = false;
    for (const auto &entry : revisions_) {
        const auto &revision = entry.second;
        auto &degree = indegree[revision.id];
        for (const auto &parent : revision.parents) {
            if (!contains(parent)) {
                missing = true;
                continue;
            }
            ++degree;
            children[parent].push_back(revision.id);
            referenced.insert(parent);
        }
    }

    // Kahn's algorithm, not recursive DFS: even a maximum-length chain cannot
    // exhaust the process stack. Check known cycles even if other files lack parents.
    std::vector<std::string> ready;
    ready.reserve(revisions_.size());
    for (const auto &entry : indegree)
        if (entry.second == 0)
            ready.push_back(entry.first);
    for (std::size_t i = 0; i < ready.size(); ++i) {
        const auto found = children.find(ready[i]);
        if (found == children.end())
            continue;
        for (const auto &child : found->second)
            if (--indegree.at(child) == 0)
                ready.push_back(child);
    }
    if (ready.size() != revisions_.size())
        throw Error(ErrorCode::Cycle, "Cyclic revision history");
    if (missing)
        throw Error(ErrorCode::MissingParent, "Waiting for referenced revision files");

    // std::map order makes the result stable across filesystems and platforms.
    for (const auto &entry : revisions_)
        if (referenced.find(entry.first) == referenced.end())
            tips_.push_back(entry.first);
}

bool Graph::isAncestor(const std::string &older, const std::string &newer) const
{
    if (!contains(older) || !contains(newer))
        return false;
    std::vector<std::string> pending{newer};
    std::set<std::string> seen;
    while (!pending.empty()) {
        const auto current = std::move(pending.back());
        pending.pop_back();
        if (current == older)
            return true;
        if (!seen.insert(current).second)
            continue;
        const auto &parents = revisions_.at(current).parents;
        pending.insert(pending.end(), parents.begin(), parents.end());
    }
    return false;
}

std::uint64_t Graph::nextSequence(const std::string &device) const
{
    if (!validDevice(device))
        throw Error(ErrorCode::InvalidIdentity, "Invalid local device");
    std::uint64_t maximum = 0;
    for (const auto &entry : revisions_)
        if (entry.second.device == device)
            maximum = std::max(maximum, entry.second.sequence);
    if (maximum == MaxSequence)
        throw Error(ErrorCode::SequenceExhausted, "Device revision sequence exhausted");
    return maximum + 1;
}
} // namespace cqs::history
