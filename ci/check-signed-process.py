#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Require an executed two-profile CopyQ acceptance report."""
import argparse
import json
from pathlib import Path

REQUIRED = {
    "isolated_profiles", "encrypted_marker_cache", "two_way_sync", "restart_recovery",
    "conflict_preservation", "signed_resolution_backup", "incomplete_delivery_refused",
    "complete_delivery_recovered", "tampered_history_refused", "no_plaintext_transport",
}


def check_report(report):
    if report.get("status") != "passed":
        raise ValueError("Signed CopyQ process acceptance did not pass")
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks or not all(isinstance(check, str) for check in checks):
        raise ValueError("Signed CopyQ process checks are missing or invalid")
    if len(checks) != len(set(checks)) or not REQUIRED <= set(checks):
        raise ValueError("Signed CopyQ process checks are missing or duplicated")
    if report.get("skipped") or any(not isinstance(check, str) or not check for check in checks):
        raise ValueError("Signed CopyQ process acceptance contains a skipped or invalid check")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    check_report(json.loads(args.report.read_text(encoding="utf-8")))
    print("REQUIRED_SIGNED_PROCESS_ACCEPTANCE_VERIFIED")


if __name__ == "__main__":
    main()
