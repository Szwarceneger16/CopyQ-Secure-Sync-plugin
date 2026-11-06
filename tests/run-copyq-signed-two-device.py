#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Two disposable CopyQ processes plus the production detached coordinator.

CopyQ edits, saves and reopens the actual signed tab through its public API.
The fixture tool performs authenticated detached synchronization after unload.
This does not certify the native setup wizard or actual cloud delivery.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--copyq", type=Path, required=True)
    parser.add_argument("--fixture-tool", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "checks": [], "boundary": "CopyQ public editing and production detached coordinator"}
    source = Path(__file__).resolve().parents[1]
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source, capture_output=True, text=True)
    report["source_commit"] = commit.stdout.strip() if commit.returncode == 0 else "unavailable"
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=source, capture_output=True, text=True)
    report["source_dirty"] = dirty.returncode != 0 or bool(dirty.stdout.strip())
    spec = importlib.util.spec_from_file_location("cqs_gui_process", source / "tests/run-copyq-gui-platform.py")
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    parent = os.environ.get("CQS_TEST_TEMP_PARENT")
    root = Path(tempfile.mkdtemp(prefix="cqs-signed-", dir=parent)).resolve()
    common = os.environ.copy()
    common["CQS_TEST_PRIVATE_ROOT"] = str(root)
    servers = []
    fixture = str(args.fixture_tool.resolve())
    copyq = str(args.copyq.resolve())

    def tool(action, *extra, refused=False):
        result = subprocess.run([fixture, action, str(root), *extra], env=common, capture_output=True,
                                text=True, encoding="utf-8", timeout=60)
        if refused:
            require(result.returncode != 0, "Invalid signed history was accepted")
        else:
            require(result.returncode == 0, "Signed fixture operation failed")
        return result.stdout.strip()

    class Server:
        def __init__(self, name):
            self.name = name
            self.folder = root / ("profile-" + name)
            self.folder.mkdir(mode=0o700)
            for child in ("settings", "state", "data", "runtime", "cache"):
                (self.folder / child).mkdir(mode=0o700)
            self.session = "cqs-signed-" + name + "-" + uuid.uuid4().hex[:5]
            self.application = "copyq-" + self.session
            self.settings = self.folder / "settings" / self.application / (self.application + ".ini")
            self.marker = self.folder / "data" / (self.application + "_tab_" + base64.b64encode(b"signed_sync").decode() + ".dat")
            self.env = common.copy()
            self.env.update({"COPYQ_SESSION_NAME": self.session,
                             "COPYQ_SETTINGS_PATH": str(self.folder / "settings"),
                             "COPYQ_STATE_PATH": str(self.folder / "state"),
                             "COPYQ_ITEM_DATA_PATH": str(self.folder / "data" / "items"),
                             "XDG_RUNTIME_DIR": str(self.folder / "runtime"),
                             "XDG_CACHE_HOME": str(self.folder / "cache"),
                             "COPYQ_PLUGINS": str(args.plugin.resolve()),
                             "COPYQ_ALLOW_PLUGINS": "__no_bundled_plugin__",
                             "COPYQ_PASSWORD": "public-signed-qualification-password",
                             "QT_QPA_PLATFORM": "windows" if os.name == "nt" else "offscreen"})
            self.process = None
            self.group = None
            self.log = None
            servers.append(self)

        def command(self, *command):
            result = subprocess.run([copyq, *command], env=self.env, capture_output=True, text=True,
                                    encoding="utf-8", timeout=30)
            require(result.returncode == 0, "CopyQ public command failed")
            return result.stdout.strip()

        def start(self):
            self.log = (self.folder / "copyq-private-test.log").open("a", encoding="utf-8")
            self.process = subprocess.Popen([copyq], env=self.env, stdout=self.log, stderr=self.log, start_new_session=True)
            self.group = helpers.FixtureGroup(self.process)
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                require(self.process.poll() is None, "CopyQ server could not start in the isolated profile")
                try:
                    configured = self.command("info", "config")
                    if Path(configured).resolve() == self.settings.resolve():
                        return
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                time.sleep(0.1)
            raise RuntimeError("CopyQ IPC startup timed out")

        def stop(self):
            if self.process is None:
                return
            try:
                if self.process.poll() is None:
                    self.command("exit")
                    self.process.wait(timeout=20)
            finally:
                self.group.close()
                self.process = None
                self.group = None
                self.log.close()
                self.log = None

        def access(self, expected, edit=None):
            script = 'show("signed_sync"); tab("signed_sync"); '
            if edit is not None:
                script += 'change(0,"text/plain",' + json.dumps("CQS_SIGNED_QUALIFICATION_" + edit) + '); '
            script += 'var value=str(read("text/plain",0)); setCurrentTab("clipboard"); hide(); '
            script += 'if(unload("signed_sync").indexOf("signed_sync")<0) throw "Fixture unload refused"; print(value);'
            value = self.command("eval", script)
            require(value == "CQS_SIGNED_QUALIFICATION_" + expected, "CopyQ content did not match the expected signed snapshot")
            require(self.marker.exists(), "CopyQ signed cache marker is missing")
            marker = self.marker.read_bytes()
            require(len(marker) == 56 and marker[:16] == bytes.fromhex("00000001fffffffc") + b"CQSSGN01",
                    "CopyQ did not write the signed routing marker")
            require(b"CQS_SIGNED_QUALIFICATION_" not in marker, "CopyQ cache contained plaintext fixture content")

    try:
        require(args.copyq.is_file() and args.fixture_tool.is_file() and args.plugin.is_file(), "Qualification input is missing")
        first, second = Server("a"), Server("b")
        tool("seed", str(first.settings), str(second.settings))
        first.start()
        second.start()
        report["checks"].append("isolated_profiles")
        first.access("SEED")
        second.access("SEED")
        report["checks"].append("encrypted_marker_cache")
        first.access("A", edit="A")
        require(tool("sync", "a") == "Published", "First device did not publish its edit")
        tool("deliver")
        require(tool("sync", "b") == "Pulled", "Second device did not receive the signed edit")
        second.access("A")
        second.access("B", edit="B")
        require(tool("sync", "b") == "Published", "Second device did not publish its edit")
        tool("deliver")
        require(tool("sync", "a") == "Pulled", "First device did not receive the signed edit")
        first.access("B")
        report["checks"].append("two_way_sync")
        for server in servers:
            server.stop()
            server.start()
            server.access("B")
        report["checks"].append("restart_recovery")
        first.access("CONFLICT_A", edit="CONFLICT_A")
        second.access("CONFLICT_B", edit="CONFLICT_B")
        require(tool("sync", "a") == "Published" and tool("sync", "b") == "Published", "Parallel local edits were not published")
        tool("deliver")
        require(tool("sync", "a") == "Conflict" and tool("sync", "b") == "Conflict", "Signed divergence was not reported")
        tool("verify", "a", "CONFLICT_A")
        tool("verify", "b", "CONFLICT_B")
        report["checks"].append("conflict_preservation")
        tool("resolve", "a")
        tool("deliver")
        require(tool("sync", "b") == "Pulled", "Resolved signed history was not received")
        first.access("CONFLICT_B")
        second.access("CONFLICT_B")
        report["checks"].append("signed_resolution_backup")
        first.access("GAP_1", edit="GAP_1")
        require(tool("sync", "a") == "Published", "Intermediate signed version was not published")
        first.access("GAP_2", edit="GAP_2")
        require(tool("sync", "a") == "Published", "Final signed version was not published")
        tool("deliver-latest-only")
        tool("sync", "b", refused=True)
        tool("verify", "b", "CONFLICT_B")
        report["checks"].append("incomplete_delivery_refused")
        tool("deliver")
        require(tool("sync", "b") == "Pulled", "Complete signed delivery did not recover")
        second.access("GAP_2")
        report["checks"].append("complete_delivery_recovered")
        tool("tamper", "b")
        tool("sync", "b", refused=True)
        tool("verify", "b", "GAP_2")
        report["checks"].append("tampered_history_refused")
        for name in ("a", "b"):
            for file in (root / name / "transport").rglob("*"):
                if file.is_file():
                    require(b"CQS_SIGNED_QUALIFICATION_" not in file.read_bytes(), "Transport contained plaintext fixture content")
        report["checks"].append("no_plaintext_transport")
        report["status"] = "passed"
    except Exception as error:
        # Exception text is limited to fixed test messages, never command output.
        report["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        for server in reversed(servers):
            try:
                server.stop()
            except Exception:
                report["status"] = "failed"
                report["error"] = "CopyQ cleanup failed"
        (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        shutil.rmtree(root, ignore_errors=True)
    print("Signed two-device qualification " + report["status"])
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
