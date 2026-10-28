# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real Git patch discovery without Qt or downloaded CopyQ sources."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "host_prepare", Path(__file__).resolve().parents[1] / "host" / "prepare.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class HostExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cqs host export ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "upstream"
        self.extension = self.root / "extension"
        self.source.mkdir()
        self.extension.mkdir()
        host.git_at(self.source, "init", "--quiet")
        host.git_at(self.source, "config", "core.autocrlf", "false")
        for name in ("src/item/serialize.h", "src/CMakeLists.txt"):
            file = self.source / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("original\n", newline="\n")
        host.git_at(self.source, "add", "src")
        host.git_at(self.source, "-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture")
        self.pin = host.git_at(self.source, "rev-parse", "HEAD").strip()
        pin = patch.object(host, "PIN", self.pin)
        pin.start()
        self.addCleanup(pin.stop)
        self.patch_file = self.extension / "copyq-17.patch"
        self.patch_file.write_text("".join(
            f"diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n"
            "@@ -1 +1 @@\n-original\n+adapted\n"
            for name in ("src/item/serialize.h", "src/CMakeLists.txt")), newline="\n")
        for name in ("tab_bridge.h", "tab_persistence.h", "tab_persistence.cpp", "verified_save_file.h"):
            (self.extension / name).write_text(f"extension {name}\n", newline="\n")

    def assert_export(self, out):
        for name in ("src/item/serialize.h", "src/CMakeLists.txt"):
            self.assertEqual((out / name).read_text(), "adapted\n")
            self.assertEqual((self.source / name).read_text(), "original\n")
        self.assertEqual((out / "src/item/tab_bridge.h").read_text(), "extension tab_bridge.h\n")
        self.assertEqual((out / ".cqs-host-export").read_text(), self.pin)
        self.assertFalse((out / ".git").exists())
        self.assertEqual(host.git_at(self.source, "status", "--porcelain"), "")

    def test_export_outside_repository_and_repeat(self):
        out = self.root / "export"
        host.prepare(self.source, out, self.extension)
        self.assert_export(out)
        (out / "stale-file").write_text("previous build\n")
        host.prepare(self.source, out, self.extension)
        self.assert_export(out)
        self.assertFalse((out / "stale-file").exists())

    def test_export_under_enclosing_repository_applies_every_hunk(self):
        # Windows puts the CMake export under GITHUB_WORKSPACE/out/windows.
        # git apply used to return 0 here while skipping ALL src/ hunks.
        outer = self.root / "plugin checkout"
        outer.mkdir()
        host.git_at(outer, "init", "--quiet")
        sentinel = outer / "src/item/serialize.h"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text("do not patch the plugin\n")
        out = outer / "out/windows/build/copyq-host"
        host.prepare(self.source, out, self.extension)
        self.assert_export(out)
        self.assertEqual(sentinel.read_text(), "do not patch the plugin\n")

    def test_inherited_git_repository_selectors_do_not_redirect_export(self):
        out = self.root / "export"
        with patch.dict(os.environ, {"GIT_DIR": str(self.source / ".git"),
                                     "GIT_WORK_TREE": str(self.source),
                                     "GIT_INDEX_FILE": str(self.source / ".git/index")}):
            host.prepare(self.source, out, self.extension)
        self.assert_export(out)

    def test_clean_crlf_checkout_exports_committed_lf_bytes(self):
        source = self.root / "Windows checkout"
        host.git_at(self.root, "clone", "--quiet", "--config", "core.autocrlf=true",
                    str(self.source), str(source))
        self.assertEqual((source / "src/item/serialize.h").read_bytes(), b"original\r\n")
        self.assertEqual(host.git_at(source, "status", "--porcelain"), "")
        out = self.root / "export"
        host.prepare(source, out, self.extension)
        self.assert_export(out)
        self.assertEqual((out / "src/item/serialize.h").read_bytes(), b"adapted\n")
        self.assertEqual((source / "src/item/serialize.h").read_bytes(), b"original\r\n")
        self.assertEqual(host.git_at(source, "status", "--porcelain"), "")

    def test_untracked_local_files_are_not_copied_into_export(self):
        (self.source / "local-profile").write_text("local only\n")
        out = self.root / "export"
        host.prepare(self.source, out, self.extension)
        self.assertFalse((out / "local-profile").exists())
        self.assertEqual((self.source / "local-profile").read_text(), "local only\n")

    def test_global_crlf_policy_does_not_rewrite_applied_hunks(self):
        config = self.root / "global-git-config"
        config.write_text("[core]\n\tautocrlf = true\n\teol = crlf\n", newline="\n")
        out = self.root / "export"
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config)}):
            host.prepare(self.source, out, self.extension)
        self.assertEqual((out / "src/item/serialize.h").read_bytes(), b"adapted\n")

    def test_inapplicable_patch_is_not_reported_as_prepared(self):
        self.patch_file.write_text(self.patch_file.read_text().replace("-original", "-wrong context"), newline="\n")
        with self.assertRaises(subprocess.CalledProcessError):
            host.prepare(self.source, self.root / "export", self.extension)
        self.assertEqual(host.git_at(self.source, "status", "--porcelain"), "")

    def test_dirty_upstream_is_preserved_and_refused(self):
        file = self.source / "src/item/serialize.h"
        file.write_text("local work\n")
        out = self.root / "export"
        with self.assertRaises(ValueError):
            host.prepare(self.source, out, self.extension)
        self.assertEqual(file.read_text(), "local work\n")
        self.assertFalse(out.exists())

    def test_wrong_revision_is_refused(self):
        with patch.object(host, "PIN", "0" * 40), self.assertRaises(ValueError):
            host.prepare(self.source, self.root / "export", self.extension)
        self.assertFalse((self.root / "export").exists())

    def test_existing_unmarked_output_is_preserved(self):
        out = self.root / "export"
        out.mkdir()
        sentinel = out / "user-file"
        sentinel.write_text("keep\n")
        with self.assertRaises(ValueError):
            host.prepare(self.source, out, self.extension)
        self.assertEqual(sentinel.read_text(), "keep\n")

    def test_overlapping_output_is_refused(self):
        for out in (self.source, self.source / "export", self.root,
                    self.extension, self.extension / "export"):
            with self.subTest(out=out), self.assertRaises(ValueError):
                host.prepare(self.source, out, self.extension)
        self.assertEqual(host.git_at(self.source, "status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
