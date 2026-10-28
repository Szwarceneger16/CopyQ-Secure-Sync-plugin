#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Only disposable Linux files + the repository's public encrypted fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CXX="${CXX:-c++}"
FLAGS=(-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    FLAGS+=(-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
fi
"$CXX" "${FLAGS[@]}" -DCQS_STORAGE_TESTING -I"$ROOT/src" \
    "$ROOT/src/storage_linux.cpp" "$ROOT/src/events.cpp" "$ROOT/src/history.cpp" \
    "$ROOT/src/crypto.cpp" "$ROOT/src/compression.cpp" \
    "$ROOT/tests/storage_test.cpp" -lcrypto -lz -o "$TMP/storage-test"
timeout 90 "$TMP/storage-test" "$ROOT/tests/fixtures"
# Also compile the release backend WITHOUT instrumentation.
"$CXX" "${FLAGS[@]}" -I"$ROOT/src" -c "$ROOT/src/storage_linux.cpp" -o "$TMP/storage.o"
