#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Offline membership-policy laboratory; public fixtures, no profile or real keys.
set -euo pipefail
cqs_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cqs_tmp="$(mktemp -d)"
trap 'rm -rf "$cqs_tmp"' EXIT
cqs_cxx="${CXX:-c++}"
"$cqs_cxx" -std=c++17 -O2 -DNDEBUG -Wall -Wextra -Werror -pedantic \
    -I"$cqs_root/src" "$cqs_root/src/device_trust.cpp" \
    "$cqs_root/src/crypto.cpp" "$cqs_root/tests/device_trust_test.cpp" \
    -lcrypto -lz -o "$cqs_tmp/device-trust-test"
"$cqs_tmp/device-trust-test"
