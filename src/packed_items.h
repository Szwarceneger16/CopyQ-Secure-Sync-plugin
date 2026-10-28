// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "import_transaction.h"

namespace cqs::packed {
class Error final : public std::runtime_error {
public:
    Error() : std::runtime_error("Invalid or unsupported CopyQ MIME data") {}
};
void validateLimits(transaction::Limits limits);
void validateSnapshot(const transaction::Snapshot &snapshot, transaction::Limits limits);
// CopyQ 17 pack(): base64 of one big-endian QDataStream per item. In-memory
// decoding only; FILE: references and DEK-encrypted streams are never opened.
transaction::Snapshot decode(const std::vector<std::string> &items, transaction::Limits limits = {});
} // namespace cqs::packed
