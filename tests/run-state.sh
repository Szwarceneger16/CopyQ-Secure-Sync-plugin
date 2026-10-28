#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Real Linux disk/lease tests with public test keys in disposable directories.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CXX="${CXX:-c++}"
FLAGS=(-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic -pthread)
if [[ "${SANITIZE:-0}" == 1 ]]; then
  FLAGS+=(-O0 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
fi
SOURCES=(src/state_record.cpp src/state_store_linux.cpp src/import_transaction.cpp src/history.cpp src/crypto.cpp)
for i in "${!SOURCES[@]}"; do SOURCES[$i]="$ROOT/${SOURCES[$i]}"; done
"$CXX" "${FLAGS[@]}" -DCQS_STATE_TESTING -I"$ROOT/src" \
  "${SOURCES[@]}" "$ROOT/tests/state_test.cpp" -lcrypto -o "$TMP/state-test"
timeout 90 "$TMP/state-test"
"$CXX" "${FLAGS[@]}" -I"$ROOT/src" -c "$ROOT/src/state_store_linux.cpp" -o "$TMP/state-release.o"
