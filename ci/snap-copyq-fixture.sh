#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
# No devmode/classic invocation; snapd supplies the namespace and environment.
export XDG_RUNTIME_DIR="${CQS_SNAP_HOST_RUNTIME:?}"
exec snap run cqs-cq.copyq "$@"
