#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Offline C++17 history tests; no Qt, CopyQ, Python or user profile is needed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CXX="${CXX:-c++}"
"$CXX" -std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic \
    -I"$ROOT/src" "$ROOT/src/history.cpp" "$ROOT/tests/history_test.cpp" \
    -o "$TMP/history-test"
"$TMP/history-test"
