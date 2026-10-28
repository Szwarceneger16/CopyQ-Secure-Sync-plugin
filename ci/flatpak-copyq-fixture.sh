#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
# Only the short, private synthetic profile is granted access. Deep report
# paths exceed the AF_UNIX socket-name limit of the stock CopyQ server.
case "${CQS_TEST_PRIVATE_ROOT:?}" in /tmp/cqs-standalone-*) ;; *) exit 2;; esac
case "${COPYQ_SETTINGS_PATH:?}" in "$CQS_TEST_PRIVATE_ROOT"/gui-*/settings) ;; *) exit 2;; esac
cqs_options=()
for cqs_name in COPYQ_SESSION_NAME COPYQ_SETTINGS_PATH COPYQ_STATE_PATH COPYQ_ITEM_DATA_PATH COPYQ_PLUGINS COPYQ_ALLOW_PLUGINS COPYQ_DEFAULT_ICON XDG_RUNTIME_DIR XDG_CACHE_HOME CQS_GUI_PUBLIC_PASSWORDS; do
    cqs_options+=("--env=$cqs_name=${!cqs_name-}")
done
# Flatpak's host-side DBus proxy needs the real host runtime directory. Only
# the application receives the disposable CopyQ runtime through --env above.
export XDG_RUNTIME_DIR="${CQS_FLATPAK_HOST_RUNTIME:?}"
exec flatpak run --user --no-documents-portal --filesystem="$CQS_TEST_PRIVATE_ROOT" --filesystem="$CQS_PLUGIN_DIRECTORY:ro" \
    "${cqs_options[@]}" com.github.hluk.copyq "$@"
