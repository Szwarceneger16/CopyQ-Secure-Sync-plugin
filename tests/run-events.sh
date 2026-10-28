#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Offline Linux tests. No Qt, CopyQ, Python, key file or sync folder is accessed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CXX="${CXX:-c++}"
FLAGS=(-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    FLAGS+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer)
fi
"$CXX" "${FLAGS[@]}" -I"$ROOT/src" \
    "$ROOT/src/events.cpp" "$ROOT/src/history.cpp" \
    "$ROOT/src/crypto.cpp" "$ROOT/src/compression.cpp" \
    "$ROOT/tests/events_test.cpp" -lcrypto -lz -o "$TMP/events-test"
"$TMP/events-test" "$ROOT/tests/fixtures"
