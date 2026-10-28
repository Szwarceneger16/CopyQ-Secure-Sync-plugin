#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Standalone Linux core checks. This does not build Qt or test the Windows backend.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CXX="${CXX:-c++}"
for name in crypto interop; do
    "$CXX" -std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror \
        -I"$ROOT/src" \
        "$ROOT/src/crypto.cpp" "$ROOT/src/compression.cpp" \
        "$ROOT/tests/${name}_test.cpp" -lcrypto -lz -o "$TMP/$name-test"
    "$TMP/$name-test"
done
