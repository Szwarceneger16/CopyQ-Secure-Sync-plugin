#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
# The fixture binary was built in this SDK too. Never execute it against the
# host runner's older Qt/glibc. Grant only synthetic data and read-only binaries.
case "${CQS_TEST_PRIVATE_ROOT:?}" in /tmp/cqs-standalone-*) ;; *) exit 2;; esac
case "${COPYQ_SESSION_NAME:?}" in cqslab-*) ;; *) exit 2;; esac
cqs_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cqs_binary_root="$cqs_source/out/flatpak"
cqs_options=()
for cqs_name in CQS_TEST_PRIVATE_ROOT COPYQ_SESSION_NAME COPYQ_SETTINGS_PATH; do
    cqs_options+=("--env=$cqs_name=${!cqs_name-}")
done
export XDG_RUNTIME_DIR="${CQS_FLATPAK_HOST_RUNTIME:?}"
exec flatpak run --user --no-documents-portal --filesystem="$CQS_TEST_PRIVATE_ROOT" \
    --filesystem="$cqs_binary_root:ro" "${cqs_options[@]}" \
    --command="$cqs_binary_root/build/cqs-unified-state-test" org.kde.Sdk//6.10 "$@"
