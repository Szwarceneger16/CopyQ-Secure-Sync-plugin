#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
case "${CQS_TEST_PRIVATE_ROOT:?}" in /tmp/cqs-signed-*) ;; *) exit 2 ;; esac
case "${COPYQ_SETTINGS_PATH:?}" in "$CQS_TEST_PRIVATE_ROOT"/*) ;; *) exit 2 ;; esac
case "${COPYQ_SESSION_NAME:?}" in cqs-signed-*) ;; *) exit 2 ;; esac
cqs_options=()
for cqs_name in COPYQ_SESSION_NAME COPYQ_SETTINGS_PATH COPYQ_STATE_PATH COPYQ_ITEM_DATA_PATH COPYQ_PLUGINS COPYQ_ALLOW_PLUGINS COPYQ_PASSWORD XDG_RUNTIME_DIR XDG_CACHE_HOME; do
    cqs_options+=("--env=$cqs_name=${!cqs_name-}")
done
export XDG_RUNTIME_DIR="${CQS_FLATPAK_HOST_RUNTIME:?}"
exec flatpak run --user --no-documents-portal --filesystem="$CQS_TEST_PRIVATE_ROOT" \
    --filesystem="${CQS_SIGNED_BINARY_ROOT:?}:ro" "${cqs_options[@]}" com.github.hluk.copyq "$@"
