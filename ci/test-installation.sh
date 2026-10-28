#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
cqs_kind="${1:?source, deb or snap}"
cqs_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cqs_out="$cqs_source/out/installations"
cqs_packages=("$cqs_out"/securesync-*.zip)
test "${#cqs_packages[@]}" = 1
cqs_options=()
cqs_bus=(dbus-run-session --)
cqs_display=()
case "$cqs_kind" in
  source|deb) cqs_copyq=/opt/cqs-copyq17-fixture/bin/copyq ;;
  snap)
    cqs_copyq="$cqs_source/ci/snap-copyq-fixture.sh"
    # snap run needs the real user systemd bus to create its confined cgroup.
    # A private dbus-run-session bus has no user manager. The app receives
    # snapd's own scoped runtime; do not feed snap run the CopyQ fixture runtime.
    export CQS_SNAP_HOST_RUNTIME="${XDG_RUNTIME_DIR:?real user runtime required}"
    test -d "$CQS_SNAP_HOST_RUNTIME" && test -w "$CQS_SNAP_HOST_RUNTIME"
    cqs_bus=()
    cqs_display=(bash "$cqs_source/ci/prepare-snap-display.sh")
    # Ask snapd's application environment, never infer ~/snap or a revision.
    cqs_common="$(snap run --shell cqs-cq.copyq -c 'printf %s "$SNAP_USER_COMMON"')"
    test -d "$cqs_common"
    cqs_real_home="$(snap run --shell cqs-cq.copyq -c 'printf %s "$SNAP_REAL_HOME"')"
    test -d "$cqs_real_home"
    cqs_transport="$(mktemp -d "$cqs_real_home/cqs-snap-transport-XXXXXX")"
    trap 'rm -rf "$cqs_transport"' EXIT
    cqs_options+=(--private-parent "$cqs_common" --transport-parent "$cqs_transport")
    snap debug confinement > "$cqs_out/reports/snap-confinement.txt"
    test "$(cat "$cqs_out/reports/snap-confinement.txt")" = strict
    snap connections cqs-cq > "$cqs_out/reports/snap-connections.txt"
    ;;
  *) exit 2 ;;
esac
unset APPDIR APPIMAGE
xvfb-run -a "${cqs_bus[@]}" "${cqs_display[@]}" python3 "$cqs_source/tests/run-copyq-gui-platform.py" \
  --copyq "$cqs_copyq" --plugin "$cqs_out/stage/copyq/plugins/libsecuresync.so" \
  --fixture-tool "$cqs_out/build/cqs-unified-state-test" --ui-driver "$cqs_out/build/libcqs-ui-driver.so" \
  --bundled-renderers --package "${cqs_packages[0]}" --installation-kind "$cqs_kind" \
  --out "$cqs_out/reports/$cqs_kind" "${cqs_options[@]}"
