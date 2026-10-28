#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Disposable GitHub VM only. Stock host builds are acceptance fixtures, never
# shipped in our plugin package or required on an end user's machine.
set -euo pipefail
cqs_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cqs_out="$cqs_source/out/installations"
mkdir -p "$cqs_out/reports" "$cqs_out/host-stage"
test "$(git -C "$cqs_source/.ci-deps/copyq" rev-parse HEAD)" = d0c179f75c04974bfe801289ea6e58a1a49535fc
test -z "$(git -C "$cqs_source/.ci-deps/copyq" status --porcelain -- src)"
cmake -S "$cqs_source" -B "$cqs_out/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCQS_BUILD_NATIVE_PLUGIN=ON -DBUILD_TESTING=ON -DCQS_BUILD_UI_TEST_PLUGIN=ON \
  -DCOPYQ_SOURCE_DIR="$cqs_source/.ci-deps/copyq" -DCMAKE_INSTALL_PREFIX="$cqs_out/stage"
cmake --build "$cqs_out/build" --target securesync cqs-unified-state-test cqs-ui-driver --parallel 2
cmake --install "$cqs_out/build"
python3 "$cqs_source/ci/package.py" --platform linux-system-qt6.4-x86_64 \
  --source "$cqs_source" --copyq "$cqs_source/.ci-deps/copyq" --out "$cqs_out"
# One normal, unmodified stock build, installed by two separate mechanisms.
# Snap exposes this compiled prefix with its declared read-only layout.
cmake -S "$cqs_source/.ci-deps/copyq" -B "$cqs_out/host-build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/cqs-copyq17-fixture \
  -DWITH_APPIMAGE=OFF -DWITH_NATIVE_NOTIFICATIONS=OFF -DWITH_KEYCHAIN=OFF \
  -DWITH_AUDIO=OFF -DWITH_GNOME_CLIPBOARD_EXTENSION=OFF
cmake --build "$cqs_out/host-build" --parallel 2
DESTDIR="$cqs_out/host-stage" cmake --install "$cqs_out/host-build"
sudo cmake --install "$cqs_out/host-build"
mkdir -p "$cqs_out/host-stage/DEBIAN"
cat > "$cqs_out/host-stage/DEBIAN/control" <<'EOF'
Package: cqs-copyq17-fixture
Version: 17.0.0
Architecture: amd64
Maintainer: Secure Sync test fixture <nobody@example.invalid>
Description: Disposable unmodified CopyQ acceptance host, not a distributed application
EOF
dpkg-deb --root-owner-group --build "$cqs_out/host-stage" "$cqs_out/copyq17-fixture.deb"
git -C "$cqs_source/.ci-deps/copyq" diff --exit-code -- src
