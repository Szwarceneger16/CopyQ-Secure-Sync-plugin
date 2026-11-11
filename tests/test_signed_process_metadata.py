# SPDX-License-Identifier: GPL-3.0-or-later
"""Conservative source metadata must not prevent real process qualification."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


RUNNER = Path(__file__).with_name("run-copyq-signed-two-device.py")
SPEC = importlib.util.spec_from_file_location("signed_process_runner", RUNNER)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
COMMIT = "0123456789abcdef0123456789abcdef01234567"
UNKNOWN = {"source_commit": "unavailable", "source_dirty": True}


def completed(output="", code=0):
    return subprocess.CompletedProcess([], code, output, "")


class SourceMetadataTest(unittest.TestCase):
    def probe(self, responses):
        with mock.patch.object(runner.subprocess, "run", side_effect=responses) as run:
            result = runner.source_metadata(RUNNER.parent)
            for call in run.call_args_list:
                self.assertEqual(call.kwargs["timeout"], 5)
            return result

    def test_missing_git_and_other_os_failure_are_unknown(self):
        for error in (FileNotFoundError("git"), PermissionError("git")):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(self.probe([error]), UNKNOWN)

    def test_timeout_on_either_probe_is_unknown(self):
        timeout = subprocess.TimeoutExpired(["git"], 5)
        self.assertEqual(self.probe([timeout]), UNKNOWN)
        self.assertEqual(self.probe([completed(COMMIT + "\n"), timeout]), UNKNOWN)

    def test_non_repository_is_unknown(self):
        self.assertEqual(self.probe([completed(code=128)]), UNKNOWN)

    def test_failed_status_never_claims_clean(self):
        self.assertEqual(self.probe([completed(COMMIT + "\n"), completed(code=128)]),
                         {"source_commit": COMMIT, "source_dirty": True})

    def test_clean_and_dirty_repository(self):
        for status, dirty in (("", False), (" M example.cpp\n", True), ("\n", True)):
            with self.subTest(dirty=dirty, status=repr(status)):
                self.assertEqual(self.probe([completed(COMMIT + "\n"), completed(status)]),
                                 {"source_commit": COMMIT, "source_dirty": dirty})

    def test_malformed_commit_is_unknown(self):
        for output in ("", "HEAD\n", COMMIT[:-1], COMMIT + "extra", COMMIT.upper(), COMMIT + "\nextra"):
            with self.subTest(output=output):
                self.assertEqual(self.probe([completed(output)]), UNKNOWN)

    def test_missing_git_still_writes_failed_acceptance_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = os.environ.copy()
            environment["PATH"] = directory
            result = subprocess.run([sys.executable, str(RUNNER), "--copyq", str(root / "missing-copyq"),
                                     "--fixture-tool", str(root / "missing-fixture"), "--plugin", str(root / "missing-plugin"),
                                     "--out", str(root / "out")], env=environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 1)
            report = json.loads((root / "out/result.json").read_text())
            self.assertEqual({key: report[key] for key in UNKNOWN}, UNKNOWN)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["checks"], [])
            self.assertEqual(report["error"], "Qualification input is missing")


if __name__ == "__main__":
    unittest.main()
