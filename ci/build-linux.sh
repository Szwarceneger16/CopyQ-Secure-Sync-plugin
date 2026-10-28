#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COPYQ="${1:?provide a pinned clean CopyQ checkout}"
OUT="${2:?provide a disposable output directory}"
mkdir -p "$OUT/reports" "$OUT/stage"
exec > >(tee "$OUT/reports/build.log") 2>&1
export HOME=/tmp/cqs-home XDG_RUNTIME_DIR=/tmp/cqs-runtime QT_QPA_PLATFORM=offscreen
mkdir -p "$HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$HOME" "$XDG_RUNTIME_DIR"
if [[ "$(id -u)" == 0 ]]; then echo 'Tests must run unprivileged' >&2; exit 1; fi
cmp "$SOURCE/ci/toolchain.json" /opt/cqs-toolchain.json
cmake --version
c++ --version
/opt/qt/bin/qmake -query QT_VERSION
getconf GNU_LIBC_VERSION
stat -f -c 'test filesystem: %T' /tmp
cmake -S "$SOURCE" -B "$OUT/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DCQS_BUILD_NATIVE_PLUGIN=ON \
    -DCQS_BUILD_STANDALONE_LAB=ON -DCQS_BUILD_UI_TEST_PLUGIN=ON \
    -DCQS_TEST_LEGACY_HOST_BRIDGE=ON \
    -DCOPYQ_SOURCE_DIR="$COPYQ" "-DCMAKE_PREFIX_PATH=/opt/qt;/opt/qca" \
    -DCMAKE_INSTALL_PREFIX="$OUT/stage" -DCMAKE_INSTALL_RPATH=
cmake --build "$OUT/build" --parallel 2
python3 "$SOURCE/ci/check-tests.py" "$OUT/build" linux --inventory-only
ctest --test-dir "$OUT/build" --parallel 2 --output-on-failure \
    --output-junit "$OUT/reports/ctest.xml"
python3 "$SOURCE/ci/check-tests.py" "$OUT/build" linux --junit "$OUT/reports/ctest.xml"
cmake --install "$OUT/build"
# Load the exact installed .so, not just the in-tree copy from the build step.
"$OUT/build/cqs-loader-test" "$OUT/stage/copyq/plugins/libsecuresync.so"
ldd "$OUT/stage/copyq/plugins/libsecuresync.so" | tee "$OUT/reports/dependencies.txt"
if grep -q 'not found' "$OUT/reports/dependencies.txt"; then exit 1; fi
python3 "$SOURCE/ci/package.py" --platform linux-ubuntu24.04-x86_64 \
    --source "$SOURCE" --copyq "$COPYQ" --out "$OUT"
