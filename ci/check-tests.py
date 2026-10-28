#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Require the native library tests AND OS tests; no empty/partial green suite."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

COMMON = {"native-history-transition", "native-unified-state", "password-state", "native-key-vault", "crypto", "history", "events", "interop", "transaction", "state-codec",
          "windows-state-path", "packed-items", "native-settings", "native-loader", "native-model-clipboard", "native-inspector", "native-host-persistence", "native-standalone-lab", "native-standalone-storage"}


def expected(platform):
    return COMMON | ({"storage", "state", "key-reader"} if platform == "linux" else {"state-windows", "key-reader-windows", "storage-windows"})


def check_inventory(data, required):
    tests = data.get("tests", [])
    names = [t["name"] for t in tests]
    if len(names) != len(set(names)) or not required <= set(names):
        raise ValueError("Missing/duplicate required tests: " + str(sorted(required - set(names))))
    for test in tests:
        if test["name"] in required:
            if not test.get("command"):
                raise ValueError("Test has no executable command")
            for prop in test.get("properties", []):
                if prop["name"] == "DISABLED" and str(prop["value"]).lower() not in {"false", "off", "0"}:
                    raise ValueError("A required test is disabled")


def check_result(root, required, text):
    cases = list(root.iter("testcase"))
    names = [case.attrib.get("name") for case in cases]
    if len(names) != len(set(names)) or not required <= set(names):
        raise ValueError("JUnit does not contain all required test results")
    for case in cases:
        if any(case.find(kind) is not None for kind in ("failure", "error", "skipped")):
            raise ValueError("Failed or skipped test in JUnit")
        if case.attrib.get("status", "run").lower() not in {"run", "passed", "pass"}:
            raise ValueError("Test did not execute successfully")
    # The NTFS executable may otherwise return 0 after skipping reparse tests.
    if re.search(r"(?m)^\s*(?:\d+:\s*)?SKIP\b", text):
        raise ValueError("A native sub-scenario was skipped; not a release-quality test run")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("platform", choices=("linux", "windows"))
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--junit", type=Path)
    args = parser.parse_args()
    result = subprocess.run(["ctest", "--test-dir", str(args.build), "-C", "Release",
                             "--show-only=json-v1"], check=True, capture_output=True, text=True)
    data = json.loads(result.stdout)
    check_inventory(data, expected(args.platform))
    if not args.inventory_only:
        if not args.junit:
            parser.error("--junit is required after running tests")
        log = (args.build / "Testing/Temporary/LastTest.log").read_text(encoding="utf-8", errors="replace")
        check_result(ET.parse(args.junit).getroot(), expected(args.platform), log)
    print("REQUIRED_NATIVE_TESTS_VERIFIED", args.platform)


if __name__ == "__main__":
    main()
