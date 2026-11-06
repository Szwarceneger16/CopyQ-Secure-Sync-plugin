# SPDX-License-Identifier: GPL-3.0-or-later
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from check_tests_loader import gate


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sources = load("signed_sources", "signed-sources.py")
process = load("signed_process", "check-signed-process.py")


class SignedQualificationTests(unittest.TestCase):
    def test_pre_feature_tree_is_not_claimed_as_signed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "CMakeLists.txt").write_text("project(PreFeature)\n", encoding="utf-8")
            self.assertFalse(sources.signed_sources(root))

    def test_partial_signed_tree_cannot_skip_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "CMakeLists.txt").write_text("option(CQS_BUILD_SIGNED_JOIN OFF)\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                sources.signed_sources(root)
            for path in sources.SOURCES:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("// synthetic fixture\n", encoding="utf-8")
            self.assertTrue(sources.signed_sources(root))

    def test_signed_flags_are_not_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "CMakeCache.txt"
            flags = {"BUILD_TESTING", "CQS_BUILD_NATIVE_PLUGIN", "CQS_TEST_DEVICE_CRYPTO", "CQS_BUILD_SIGNED_JOIN"}
            cache.write_text("\n".join(flag + ":BOOL=ON" for flag in sorted(flags)), encoding="utf-8")
            gate.check_signed_cache(cache)
            for flag in flags:
                cache.write_text("\n".join(name + ":BOOL=" + ("OFF" if name == flag else "ON") for name in sorted(flags)), encoding="utf-8")
                with self.subTest(flag=flag), self.assertRaises(ValueError):
                    gate.check_signed_cache(cache)

    def test_each_platform_requires_signed_and_two_profile_suites(self):
        for platform in ("linux", "windows", "flatpak"):
            required = gate.expected(platform, signed=True)
            self.assertTrue(gate.SIGNED <= required)
            self.assertIn("native-signed-two-device", required)
        self.assertNotIn("native-host-persistence", gate.expected("flatpak", signed=True))
        self.assertIn("storage-windows", gate.expected("windows", signed=True))
        self.assertIn("storage", gate.expected("flatpak", signed=True))

    def test_process_report_requires_all_scenarios(self):
        passed = {"status": "passed", "checks": sorted(process.REQUIRED)}
        process.check_report(passed)
        for invalid in (
            {"status": "skipped", "checks": passed["checks"]},
            {"status": "passed", "checks": passed["checks"][:-1]},
            {"status": "passed", "checks": passed["checks"] + [passed["checks"][0]]},
            {**passed, "skipped": True},
        ):
            with self.subTest(report=invalid), self.assertRaises(ValueError):
                process.check_report(invalid)

    def test_sodium_pin_is_the_same_for_each_platform(self):
        root = Path(__file__).resolve().parents[1]
        pin = json.loads((root / "ci/signed-toolchain.json").read_text(encoding="utf-8"))["libsodium_commit"]
        self.assertRegex(pin, r"^[0-9a-f]{40}$")
        for path in ("ci/Containerfile.signed", ".github/workflows/signed-ci.yml"):
            self.assertIn(pin, (root / path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
