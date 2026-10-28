#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Pure Windows path policy checks runnable on Linux. NOT a Win32 backend test.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FLAGS=(-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    FLAGS+=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer)
fi
"${CXX:-c++}" "${FLAGS[@]}" -I"$ROOT/src" "$ROOT/tests/windows_state_path_test.cpp" -o "$TMP/path-test"
"$TMP/path-test"
