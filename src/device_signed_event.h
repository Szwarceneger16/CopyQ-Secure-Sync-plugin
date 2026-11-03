// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_key_envelope.h"
#include "events.h"

namespace cqs::trust {
struct SignedEventContext {
    Token group{}, root{}, head{}, commitment{}, author{};
    std::uint64_t generation = 0;
};

struct SignedEventParent {
    std::string id;
    Token digest{};
};

struct SignedEventHeader {
    SignedEventContext context;
    history::Revision revision;
    std::vector<SignedEventParent> parents;
};

// The coordinator supplies independently pinned membership and file identity.
// Each parent commits to a full signed wire packet, not a semantic fingerprint.
class SignedEventCodec final {
public:
    static void validateLimits(events::Limits limits);
    static std::string deviceName(const Token &author);
    static Token digest(std::string_view wire);

    // Bounded public metadata. Use verify() or open() to authenticate it.
    static SignedEventHeader inspect(std::string_view wire, events::Limits limits = {});

    static crypto::Bytes seal(const SignedEventContext &context, const Identity &author, const SyncKey &key,
                              std::uint64_t sequence, const std::vector<SignedEventParent> &parents,
                              const std::vector<std::string> &packedItems, events::Limits limits = {});
    // Authenticate the exact packet without opening its clipboard payload.
    static void verify(const events::Envelope &envelope, const SignedEventContext &expected,
                       const Member &author, events::Limits limits = {});
    static events::Event open(const events::Envelope &envelope, const SignedEventContext &expected,
                              const Member &author, const SyncKey &key, events::Limits limits = {});
};
} // namespace cqs::trust
