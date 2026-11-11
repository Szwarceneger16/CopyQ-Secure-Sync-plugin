#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
cqs_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cqs_build="$(realpath "${1:?provide the signed build output directory}")"
cqs_fixture="$cqs_build/copyq-process-fixture"
cqs_reports="$cqs_build/reports/two-device"
mkdir -p "$cqs_fixture" "$cqs_reports"
curl --fail --location --retry 3 'https://github.com/hluk/CopyQ/releases/download/v17.0.0/CopyQ-17.0.0-x86_64.AppImage' -o "$cqs_fixture/copyq.AppImage"
echo "b63fb78eed3300af61ce2db7bf537bf12160ef86c7122147fc1c3cceb826c0d1  $cqs_fixture/copyq.AppImage" | sha256sum --check
chmod +x "$cqs_fixture/copyq.AppImage"
(cd "$cqs_fixture" && ./copyq.AppImage --appimage-extract > extract.log)
docker build --tag cqs-signed-process:local --file "$cqs_source/ci/Containerfile.nextcloud" "$cqs_fixture" > "$cqs_reports/container-build.log" 2>&1
docker image inspect cqs-signed-process:local > "$cqs_reports/container-image.json"
docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 512 --memory 3g --cpus 2 --ulimit memlock=67108864:67108864 \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,size=1g \
    --env QT_QPA_PLATFORM=offscreen --env APPDIR=/opt/copyq17 \
    --env LD_LIBRARY_PATH=/opt/copyq17/usr/lib \
    --mount "type=bind,src=$cqs_source,dst=/source,readonly" \
    --mount "type=bind,src=$cqs_build,dst=/build,readonly" \
    --mount "type=bind,src=$cqs_reports,dst=/reports" \
    cqs-signed-process:local python3 /source/tests/run-copyq-signed-two-device.py \
    --copyq /opt/copyq17/AppRun --plugin /build/stage/copyq/plugins/libsecuresync.so \
    --fixture-tool /build/build/cqs-signed-two-device-test --out /reports
python3 "$cqs_source/ci/check-signed-process.py" "$cqs_reports/result.json"
