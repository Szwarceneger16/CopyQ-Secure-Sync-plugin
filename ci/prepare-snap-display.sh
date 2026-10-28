#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
test "$#" -gt 0
: "${CQS_SNAP_HOST_RUNTIME:?real user runtime required}"
: "${XAUTHORITY:?xvfb-run authority required}"
cqs_original_authority="$XAUTHORITY"
cqs_expected_authority="$CQS_SNAP_HOST_RUNTIME/.Xauthority"
test -f "$cqs_original_authority"

# Migrate xvfb-run's /tmp cookie once before the server and polling CLI start
# concurrently. Later snap run calls receive the canonical, shared cookie path
# and do not race to create snapd's per-user .Xauthority file.
cqs_authority="$(XDG_RUNTIME_DIR="$CQS_SNAP_HOST_RUNTIME" \
  snap run --shell cqs-cq.copyq -c 'printf %s "$XAUTHORITY"')"
if test "$cqs_authority" != "$cqs_expected_authority" \
    || test ! -f "$cqs_authority" || test -L "$cqs_authority" \
    || ! test -O "$cqs_authority" \
    || ! cmp -s -- "$cqs_original_authority" "$cqs_authority"; then
  echo 'Snap did not provide the expected authenticated X11 display cookie' >&2
  exit 1
fi
export XAUTHORITY="$cqs_authority"
exec "$@"
