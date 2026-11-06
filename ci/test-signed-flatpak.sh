#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
cqs_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cqs_out="$cqs_source/out/signed-flatpak"
mkdir -p "$cqs_out/reports" "$cqs_out/stage"
cqs_sodium_commit=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["libsodium_commit"])' "$cqs_source/ci/signed-toolchain.json")
test "$(git -C "$cqs_source/.ci-deps/sodium" rev-parse HEAD)" = "$cqs_sodium_commit"
flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
flatpak install --user --noninteractive flathub com.github.hluk.copyq org.kde.Sdk//6.10
flatpak info --user com.github.hluk.copyq > "$cqs_out/reports/application.txt"
flatpak info --user org.kde.Sdk//6.10 > "$cqs_out/reports/sdk.txt"
test "$(flatpak info --user --show-runtime com.github.hluk.copyq)" = org.kde.Platform/x86_64/6.10
flatpak run --user --command=copyq --env=QT_QPA_PLATFORM=offscreen com.github.hluk.copyq --version > "$cqs_out/reports/version.txt"
rg '^CopyQ Clipboard Manager 17\.0\.0' "$cqs_out/reports/version.txt"
# Build and test inside the matching SDK with network disabled. Candidate
# sources are read-only; only the disposable output and SDK temp dirs are writable.
flatpak run --user --unshare=network --filesystem="$cqs_source:ro" --filesystem="$cqs_out" \
    --command=bash org.kde.Sdk//6.10 -c '
  set -euo pipefail
  source_root="$1"
  output_root="$2"
  export QT_QPA_PLATFORM=offscreen
  mkdir -p "$output_root/sodium-build"
  cd "$output_root/sodium-build"
  "$source_root/.ci-deps/sodium/configure" --prefix="$output_root/sodium" --disable-shared --enable-static --with-pic
  make -j2
  make check
  make install
  cp "$source_root/.ci-deps/sodium/LICENSE" "$output_root/stage/libsodium-LICENSE"
  cmake -S "$source_root" -B "$output_root/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DCQS_BUILD_NATIVE_PLUGIN=ON \
    -DCQS_TEST_DEVICE_CRYPTO=ON -DCQS_BUILD_SIGNED_JOIN=ON \
    -DCQS_SODIUM_INCLUDE_DIR="$output_root/sodium/include" \
    -DCQS_SODIUM_LIBRARY="$output_root/sodium/lib/libsodium.a" \
    -DCOPYQ_SOURCE_DIR="$source_root/.ci-deps/copyq" -DCMAKE_INSTALL_PREFIX="$output_root/stage"
  cmake --build "$output_root/build" --parallel 2
  python3 "$source_root/ci/check-tests.py" "$output_root/build" flatpak --signed --inventory-only
  ctest --test-dir "$output_root/build" --parallel 2 --output-on-failure \
    --output-junit "$output_root/reports/ctest.xml"
  python3 "$source_root/ci/check-tests.py" "$output_root/build" flatpak --signed --junit "$output_root/reports/ctest.xml"
  cmake --install "$output_root/build"
  "$output_root/build/cqs-loader-test" "$output_root/stage/copyq/plugins/libsecuresync.so"
' bash "$cqs_source" "$cqs_out" > "$cqs_out/reports/build.log" 2>&1
export CQS_SIGNED_BINARY_ROOT="$cqs_out"
export CQS_FLATPAK_HOST_RUNTIME="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
test -d "$CQS_FLATPAK_HOST_RUNTIME" && test -w "$CQS_FLATPAK_HOST_RUNTIME"
xvfb-run -a dbus-run-session -- python3 "$cqs_source/tests/run-copyq-signed-two-device.py" \
    --copyq "$cqs_source/ci/signed-flatpak-copyq-fixture.sh" \
    --plugin "$cqs_out/stage/copyq/plugins/libsecuresync.so" \
    --fixture-tool "$cqs_source/ci/signed-flatpak-state-fixture.sh" \
    --out "$cqs_out/reports/two-device"
python3 "$cqs_source/ci/check-signed-process.py" "$cqs_out/reports/two-device/result.json"
