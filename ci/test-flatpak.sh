#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# GitHub-hosted disposable runner: compile our module, never rebuild CopyQ.
set -euo pipefail
cqs_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cqs_out="$cqs_source/out/flatpak"
mkdir -p "$cqs_out/reports" "$cqs_out/stage"
flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
flatpak install --user --noninteractive flathub com.github.hluk.copyq org.kde.Sdk//6.10
flatpak info --user com.github.hluk.copyq > "$cqs_out/reports/application.txt"
flatpak info --user org.kde.Sdk//6.10 > "$cqs_out/reports/sdk.txt"
cqs_runtime="$(flatpak info --user --show-runtime com.github.hluk.copyq)"
test "$cqs_runtime" = org.kde.Platform/x86_64/6.10
flatpak run --user --command=copyq --env=QT_QPA_PLATFORM=offscreen com.github.hluk.copyq --version > "$cqs_out/reports/version.txt"
rg '^CopyQ Clipboard Manager 17\.0\.0' "$cqs_out/reports/version.txt"
flatpak run --user --filesystem="$cqs_source" --command=bash org.kde.Sdk//6.10 -c '
  set -euo pipefail
  qmake6 -query QT_VERSION
  cmake -S "$1" -B "$2/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
    -DCQS_BUILD_NATIVE_PLUGIN=ON -DCQS_BUILD_UI_TEST_PLUGIN=ON \
    -DCOPYQ_SOURCE_DIR="$1/.ci-deps/copyq" -DCMAKE_INSTALL_PREFIX="$2/stage"
  cmake --build "$2/build" --target securesync cqs-unified-state-test cqs-ui-driver --parallel 2
  cmake --install "$2/build"
' bash "$cqs_source" "$cqs_out" > "$cqs_out/reports/build.log" 2>&1
cp "$cqs_out/build/libcqs-ui-driver.so" "$cqs_out/stage/copyq/plugins/"
export CQS_TEST_OUTPUT="$cqs_out/reports" CQS_PLUGIN_DIRECTORY="$cqs_out/stage/copyq/plugins"
export CQS_FLATPAK_HOST_RUNTIME="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
test -d "$CQS_FLATPAK_HOST_RUNTIME" && test -w "$CQS_FLATPAK_HOST_RUNTIME"
python3 "$cqs_source/ci/package.py" --platform linux-flatpak-kde6.10-x86_64 \
  --source "$cqs_source" --copyq "$cqs_source/.ci-deps/copyq" --out "$cqs_out"
cqs_packages=("$cqs_out"/securesync-*.zip)
test "${#cqs_packages[@]}" = 1
xvfb-run -a dbus-run-session -- python3 "$cqs_source/tests/run-flatpak-installation.py" \
  --package "${cqs_packages[0]}" --out "$cqs_out/reports/default-installation"
xvfb-run -a dbus-run-session -- python3 "$cqs_source/tests/run-copyq-gui-platform.py" \
  --copyq "$cqs_source/ci/flatpak-copyq-fixture.sh" \
  --plugin "$cqs_out/stage/copyq/plugins/libsecuresync.so" \
  --fixture-tool "$cqs_source/ci/flatpak-state-fixture.sh" --ui-driver "$cqs_out/stage/copyq/plugins/libcqs-ui-driver.so" \
  --bundled-renderers --installation-kind flatpak --package "${cqs_packages[0]}" --out "$cqs_out/reports/official-gui"
