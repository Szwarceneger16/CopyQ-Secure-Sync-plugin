#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
export DISPLAY=:98 QT_QPA_PLATFORM=xcb LD_LIBRARY_PATH=/opt/copyq17/usr/lib APPDIR=/opt/copyq17
Xvfb :98 -screen 0 1280x1024x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
cqs_xvfb_pid=$!
openbox >/tmp/openbox.log 2>&1 &
cqs_openbox_pid=$!
trap 'kill "$cqs_xvfb_pid" "$cqs_openbox_pid" 2>/dev/null || true' EXIT
sleep 1
python3 /source/tests/run-copyq-gui-platform.py --copyq /opt/copyq17/AppRun \
  --plugin /build/stage/copyq/plugins/libsecuresync.so \
  --fixture-tool /build/build/cqs-unified-state-test --ui-driver /build/build/libcqs-ui-driver.so \
  --bundled-renderers --installation-kind appimage --nextcloud-fixture --out /reports
