#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
case "${CQS_TEST_PRIVATE_ROOT:?}" in /tmp/cqs-signed-*) ;; *) exit 2 ;; esac
cqs_options=()
for cqs_name in CQS_TEST_PRIVATE_ROOT COPYQ_SESSION_NAME COPYQ_SETTINGS_PATH; do
    cqs_options+=("--env=$cqs_name=${!cqs_name-}")
done
export XDG_RUNTIME_DIR="${CQS_FLATPAK_HOST_RUNTIME:?}"
exec flatpak run --user --no-documents-portal --filesystem="$CQS_TEST_PRIVATE_ROOT" \
    --filesystem="${CQS_SIGNED_BINARY_ROOT:?}:ro" "${cqs_options[@]}" \
    --command="$CQS_SIGNED_BINARY_ROOT/build/cqs-signed-two-device-test" org.kde.Sdk//6.10 "$@"
