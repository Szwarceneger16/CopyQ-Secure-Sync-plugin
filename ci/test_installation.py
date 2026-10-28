# SPDX-License-Identifier: GPL-3.0-or-later
"""Admission tests; actual installations are separate GUI acceptance jobs."""
import copy
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("cqs_install", Path(__file__).resolve().parents[1] / "tools/install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.probe = {"schema":1,"platform":"linux","version":"CopyQ Clipboard Manager 17.0.0","qt":"6.10.3",
            "arch":"x86_64-little_endian-lp64","compiler":"GCC","encryption_compiled":True,"plugins_directory_readable":True,
            "paths":{n:"/explicit/"+n for n in ("exe","plugins","config","state","data")},"runtime":{}}
        self.meta = {"target":"linux-ubuntu24.04-x86_64", "abi":{"schema":1,"copyq":"17.0.0",
            "qt":"6.10.3","pointer_size":8,"processor":"x86_64","compiler":"GNU"},
            "binary_sha256":hashlib.sha256(b"public module").hexdigest()}

    def check(self):
        return installer.check_compatibility(self.probe,self.meta)

    def test_native_uses_only_copyq_paths(self):
        p=self.check()
        self.assertEqual(p["module_root"],"/explicit/state/securesync/modules")
        self.assertEqual(p["copyq"],self.probe["paths"])
        self.assertFalse(p["automatic_activation"])

    def test_other_sessions_get_other_private_folders(self):
        before=self.check(); self.probe["paths"]["config"]+="-other"
        after=self.check()
        self.assertNotEqual(before["suggested_vault"],after["suggested_vault"])
        self.assertEqual(before["module_root"],after["module_root"])

    def test_old_deb_and_new_host_are_refused(self):
        for version in ("13.0.0","17.0.1","18.0.0","117.0.0"):
            with self.subTest(version=version),self.assertRaises(ValueError):
                self.probe["version"]="CopyQ Clipboard Manager "+version; self.check()

    def test_qt_and_architecture_mismatch(self):
        original=copy.deepcopy(self.probe)
        for values in ({"qt":"6.4.2"},{"qt":"6.12.0"},{"qt":"5.15.13"},{"arch":"arm64-little_endian-lp64"}):
            self.probe={**original,**values}
            with self.subTest(values=values),self.assertRaises(ValueError): self.check()

    def test_flatpak_requires_own_sdk_and_metadata(self):
        self.probe["runtime"]={"FLATPAK_ID":"com.github.hluk.copyq","XDG_DATA_HOME":"/provided/persistent/app-data","flatpak_runtime":"org.kde.Platform/x86_64/6.10"}
        with self.assertRaises(ValueError): self.check()
        self.meta["target"]="linux-flatpak-kde6.10-x86_64"
        self.assertEqual(self.check()["environment"],"flatpak")
        self.assertEqual(self.check()["module_root"],"/provided/persistent/app-data/securesync/modules")
        self.assertTrue(self.check()["suggested_state"].startswith("/provided/persistent/app-data/"))
        self.assertTrue(self.check()["suggested_vault"].startswith("/provided/persistent/app-data/"))
        self.probe["runtime"]["flatpak_runtime"]="org.kde.Platform/x86_64/6.11"
        with self.assertRaises(ValueError): self.check()

    def test_flatpak_does_not_fall_back_to_ephemeral_state(self):
        self.probe["runtime"]={"FLATPAK_ID":"com.github.hluk.copyq","flatpak_runtime":"org.kde.Platform/x86_64/6.10"}
        self.meta["target"]="linux-flatpak-kde6.10-x86_64"
        with self.assertRaises(ValueError): self.check()

    def test_sdk_package_cannot_escape_to_native(self):
        self.meta["target"]="linux-flatpak-kde6.10-x86_64"
        with self.assertRaises(ValueError): self.check()

    def test_snap_uses_revision_independent_metadata(self):
        self.probe["runtime"]={"SNAP":"/snap/copyq/37","SNAP_NAME":"copyq","SNAP_USER_COMMON":"/home/example/snap/copyq/common","snap_base":"core24"}
        self.meta["target"]="linux-system-qt6.4-x86_64"; self.meta["abi"]["qt"]="6.4.2"
        self.assertTrue(self.check()["module_root"].startswith("/home/example/snap/copyq/common/"))
        self.probe["runtime"].pop("SNAP_USER_COMMON")
        with self.assertRaises(ValueError): self.check()

    def test_snap_refuses_wrong_base_package(self):
        self.probe["runtime"]={"SNAP":"/snap/copyq/37","SNAP_USER_COMMON":"/home/example/snap/copyq/common","snap_base":"core24"}
        with self.assertRaises(ValueError): self.check()
        self.meta["target"]="linux-system-qt6.4-x86_64";self.meta["abi"]["qt"]="6.4.2"
        self.probe["runtime"]["snap_base"]="core22"
        with self.assertRaises(ValueError): self.check()

    def test_portable_windows_paths_and_compiler(self):
        self.probe["paths"]={n:"D:/Portable CopyQ/"+n for n in self.probe["paths"]}
        self.probe["arch"]="x86_64-little_endian-llp64";self.probe["compiler"]="MSVC"
        self.probe["platform"]="windows"
        self.meta["target"]="windows-x86_64";self.meta["abi"]["compiler"]="MSVC"
        self.assertTrue(self.check()["module_root"].startswith("D:/Portable CopyQ/state/"))
        self.probe["compiler"]="MinGW"
        with self.assertRaises(ValueError): self.check()

    def test_paths_cannot_inject_another_module(self):
        for path in ("relative", "/x;unwanted.so", "/x\n", ""):
            with self.subTest(path=path),self.assertRaises(ValueError):
                self.probe["paths"]["state"]=path; self.check()

    def test_missing_build_metadata(self):
        self.meta.pop("abi")
        with self.assertRaises(ValueError): self.check()

    def test_lp64_alone_does_not_establish_linux(self):
        self.probe["platform"]="unsupported"
        with self.assertRaises(ValueError): self.check()
        self.probe["platform"]="windows"
        with self.assertRaises(ValueError): self.check()

    def test_missing_stock_plugin_directory_refuses_before_staging(self):
        self.probe["plugins_directory_readable"]=False
        with self.assertRaises(ValueError): self.check()

    def test_cli_transport_preserves_windows_paths_and_regexes(self):
        script = 'var path="D:\\\\Portable CopyQ\\\\plugin"; /\\r?\\n/.test(path)'
        encoded=installer.encode_script(script)
        self.assertNotIn("\\",encoded)
        payload=encoded.split("'")[1]
        self.assertEqual(base64.b64decode(payload).decode("utf-8"),script)

    def test_stage_never_reuses_directory_or_embeds_payload(self):
        a=installer.stage_script(self.probe,self.meta,"libsecuresync.so",b"public module")
        b=installer.stage_script(self.probe,self.meta,"libsecuresync.so",b"public module")
        self.assertNotEqual(a,b)
        self.assertNotIn("public module",a)
        with self.assertRaises(ValueError): installer.stage_script(self.probe,self.meta,"libsecuresync.so",b"changed")

    def test_package_checks_both_hashes_and_duplicate_members(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"module.zip"
            with zipfile.ZipFile(p,"w") as z:
                z.writestr("BUILD-INFO.json",json.dumps(self.meta))
                z.writestr("copyq/plugins/libsecuresync.so",b"public module")
            digest=hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertEqual(installer.read_package(p,digest)[2],b"public module")
            with self.assertRaises(ValueError): installer.read_package(p,"0"*64)
            self.meta["binary_sha256"]="0"*64
            with zipfile.ZipFile(p,"w") as z:
                z.writestr("BUILD-INFO.json",json.dumps(self.meta));z.writestr("copyq/plugins/libsecuresync.so",b"public module")
            with self.assertRaises(ValueError): installer.read_package(p,hashlib.sha256(p.read_bytes()).hexdigest())


if __name__ == "__main__": unittest.main()
