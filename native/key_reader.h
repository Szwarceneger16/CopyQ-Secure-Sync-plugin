// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "crypto.h"
#include <filesystem>

namespace cqs::native {
// Platform backends pin all path components, open only a private regular file,
// and return exactly 32 bytes. Windows requires a fixed local NTFS volume and
// user-owned protected DACLs on the key and its immediate parent.
// Caller must wipe returned bytes after use.
// No key generation, export, chmod, CopyQ DEK access or fallback path following.
crypto::Bytes readKeyStrict(const std::filesystem::path &absoluteFile);
} // namespace cqs::native
