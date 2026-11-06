// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QIODevice>

namespace cqs::native {
inline constexpr auto SignedTabName = "signed_sync";
inline const QByteArray SignedTabPreamble("\0\0\0\1\xff\xff\xff\xfc", 8);
// Claim the reserved preamble even when the rest was truncated. CopyQ stops
// at the first loader that recognizes the file, even if it then refuses it.
inline bool recognizesSignedTabMarker(QIODevice *file) {
    return file && file->peek(SignedTabPreamble.size()) == SignedTabPreamble;
}
} // namespace cqs::native
