#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Offline Linux entry point. The C++ test itself is portable, including Windows.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CXX="${CXX:-c++}"
FLAGS=(-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    FLAGS+=(-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer)
fi
"$CXX" "${FLAGS[@]}" -I"$ROOT/src" \
    "$ROOT/src/state_record.cpp" "$ROOT/src/history.cpp" "$ROOT/src/crypto.cpp" \
    "$ROOT/tests/state_codec_test.cpp" -lcrypto -o "$TMP/state-codec-test"
"$TMP/state-codec-test"
