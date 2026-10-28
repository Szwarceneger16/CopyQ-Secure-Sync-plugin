#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Fixture launcher for run-standalone-copyq.py, not a user-profile installer.
set -euo pipefail
CQS_FIXTURE_ROOT="$(dirname "${CQS_LAB_STATE_DIR:?run the standalone test harness}")"
case "$(basename "$CQS_FIXTURE_ROOT")" in
    cqs-standalone-*) ;;
    *) echo 'This launcher accepts only a disposable standalone test fixture.' >&2; exit 2 ;;
esac
case "${COPYQ_PLUGINS:?provide one prototype module}" in
    *';'*) echo 'Provide exactly one prototype module.' >&2; exit 2 ;;
esac
exec flatpak run --command=copyq \
    --filesystem="$CQS_FIXTURE_ROOT:rw" \
    --filesystem="$(dirname "$COPYQ_PLUGINS"):ro" \
    --env="COPYQ_SESSION_NAME=$COPYQ_SESSION_NAME" \
    --env="COPYQ_SETTINGS_PATH=$COPYQ_SETTINGS_PATH" \
    --env="COPYQ_STATE_PATH=$COPYQ_STATE_PATH" \
    --env="COPYQ_ITEM_DATA_PATH=$COPYQ_ITEM_DATA_PATH" \
    --env="COPYQ_PLUGINS=$COPYQ_PLUGINS" \
    --env="COPYQ_ALLOW_PLUGINS=$COPYQ_ALLOW_PLUGINS" \
    --env="COPYQ_DEFAULT_ICON=$COPYQ_DEFAULT_ICON" \
    --env="COPYQ_LOG_LEVEL=$COPYQ_LOG_LEVEL" \
    --env="CQS_STANDALONE_LAB=$CQS_STANDALONE_LAB" \
    --env="CQS_LAB_CREATE=$CQS_LAB_CREATE" \
    --env="CQS_LAB_STATE_DIR=$CQS_LAB_STATE_DIR" \
    --env="CQS_LAB_KEY_FILE=$CQS_LAB_KEY_FILE" \
    com.github.hluk.copyq "$@"
