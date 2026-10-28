#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FLAGS=(-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    FLAGS+=(-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
fi
"${CXX:-c++}" "${FLAGS[@]}" -I"$ROOT/src" \
    "$ROOT/src/packed_items.cpp" "$ROOT/src/compression.cpp" \
    "$ROOT/tests/packed_items_test.cpp" -lz -o "$TMP/packed-items-test"
timeout 45 "$TMP/packed-items-test"
