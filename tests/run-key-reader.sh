#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FLAGS=(-std=c++17 -O2 -DNDEBUG -DCQS_KEY_READER_TESTING -Wall -Wextra -Werror -pedantic)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    FLAGS+=(-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
fi
"${CXX:-c++}" "${FLAGS[@]}" -I"$ROOT/src" -I"$ROOT/native" \
    "$ROOT/native/key_reader_linux.cpp" "$ROOT/src/crypto.cpp" \
    "$ROOT/tests/key_reader_test.cpp" -lcrypto -o "$TMP/key-reader-test"
timeout 45 "$TMP/key-reader-test"
