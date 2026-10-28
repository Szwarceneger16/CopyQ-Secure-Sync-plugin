// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace cqs::history {

inline constexpr std::size_t MaxEvents = 1000;
inline constexpr std::uint64_t MaxSequence = 999999999999ULL;

// Metadata only. A caller must authenticate/decrypt each .cqs envelope first.
// No ciphertext, CopyQ item data or encryption key is stored in this graph.
struct Revision {
    std::string id;
    std::string device;
    std::uint64_t sequence = 0;
    std::vector<std::string> parents;
};

enum class ErrorCode {
    LimitExceeded,
    InvalidIdentity,
    InvalidParents,
    DuplicateRevision,
    NonmonotonicParent,
    Cycle,
    MissingParent,
    SequenceExhausted,
};

class Error final : public std::runtime_error {
public:
    Error(ErrorCode code, const char *message) : std::runtime_error(message), code_(code) {}
    ErrorCode code() const noexcept { return code_; }
private:
    ErrorCode code_;
};

// Portable v1 ID: [a-z][a-z0-9-]{2,31}/[0-9]{12}, sequence > 0.
std::string makeId(const std::string &device, std::uint64_t sequence);

// Validate one revision without requiring its parents to be present.
// Structural validation only: this does not authenticate an event.
void validateRevision(const Revision &revision);

// An immutable, validated snapshot of the available history. MissingParent is
// distinct from corruption: Nextcloud may deliver children before their parents.
// Construction never repairs history, chooses a winning branch or writes files.
class Graph final {
public:
    explicit Graph(const std::vector<Revision> &revisions);
    std::size_t size() const noexcept { return revisions_.size(); }
    bool contains(const std::string &id) const { return revisions_.find(id) != revisions_.end(); }
    const std::vector<std::string> &tips() const noexcept { return tips_; }
    bool hasConflict() const noexcept { return tips_.size() > 1; }
    // Reflexive only for an existing ID. Unknown IDs always return false.
    bool isAncestor(const std::string &older, const std::string &newer) const;
    // Does not reserve or publish an ID. Storage must enforce no-overwrite.
    std::uint64_t nextSequence(const std::string &device) const;
private:
    std::map<std::string, Revision> revisions_;
    std::vector<std::string> tips_;
};

} // namespace cqs::history
