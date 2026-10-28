#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Portable coordinator tests on Linux; Store/Clipboard are fault-injected models.
# No real CopyQ process, K-SYNC, state file or transport directory is touched.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CXX="${CXX:-c++}"
FLAGS=(-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    FLAGS+=(-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
fi
"$CXX" "${FLAGS[@]}" -I"$ROOT/src" \
    "$ROOT/src/import_transaction.cpp" "$ROOT/src/events.cpp" "$ROOT/src/history.cpp" \
    "$ROOT/src/crypto.cpp" "$ROOT/src/compression.cpp" \
    "$ROOT/tests/transaction_test.cpp" -lcrypto -lz -o "$TMP/transaction-test"
"$TMP/transaction-test"
