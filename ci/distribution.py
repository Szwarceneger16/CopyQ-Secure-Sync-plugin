# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared package contract; release validation never trusts ZIP extraction."""
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile

VERSION_RE = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?"
DOCS = (
    "STANDALONE-STORAGE.md", "KEY-LIFECYCLE.md", "NATIVE-SETTINGS.md", "INSTALLATION.md",
    "UNIFIED-STATE.md", "DEVICE-SETUP.md", "AUTOMATIC-SYNC.md", "CONFLICTS-AND-HISTORY.md",
    "HISTORY-TRANSITIONS.md", "NEXTCLOUD.md", "NATIVE-DATA-AND-PROTECTION.md", "RELEASING.md",
)
COMMON = {"LICENSE", "COPYQ-LICENSE", "THIRD-PARTY-NOTICES.md", "CHANGELOG.md", "VERSION",
          "COMPATIBILITY.json", "BUILD-INFO.json", "READ-ME-FIRST.txt", "PACKAGE-SHA256SUMS",
          "tools/install.py", "tools/installation.js", *("docs/" + n for n in DOCS)}
TARGET_ARTIFACTS = {
    "linux-ubuntu24.04-x86_64": "linux-native-plugin",
    "windows-x86_64": "windows-native-plugin",
    "linux-flatpak-kde6.10-x86_64": "flatpak-native-plugin",
    "linux-system-qt6.4-x86_64": "linux-system-qt-native-plugin",
}


def version(source):
    value = (source / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(VERSION_RE, value):
        raise ValueError("Unsupported release version")
    return value


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def package_name(value, target, commit):
    return f"securesync-{value}-{target}-{commit[:12]}.zip"


def checksums(files):
    return "".join(f"{sha256(raw)}  {name}\n" for name, raw in sorted(files.items()))


def read_zip(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 48 * 1024 * 1024:
        raise ValueError("Unsafe or oversized package file")
    with zipfile.ZipFile(path) as z:
        if len(z.infolist()) > 64 or sum(i.file_size for i in z.infolist()) > 48 * 1024 * 1024:
            raise ValueError("Oversized package")
        files = {}
        for i in z.infolist():
            name = i.filename
            if (name in files or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", name)
                    or any(p in ("", ".", "..") for p in name.split("/"))
                    or stat.S_ISLNK(i.external_attr >> 16) or i.is_dir() or i.flag_bits & 1):
                raise ValueError("Unsafe or duplicate ZIP entry")
            files[name] = z.read(i)
        return files


def validate_package(path, source, commit, target):
    files = read_zip(path)
    value = version(source)
    windows = target == "windows-x86_64"
    module = "copyq/plugins/" + ("securesync.dll" if windows else "libsecuresync.so")
    expected = COMMON | {module} | ({"ZLIB-NOTICE.txt"} if windows else set())
    if set(files) != expected:
        raise ValueError("Package inventory differs: no host patches, fixtures, extra modules or executables are allowed")
    metadata = json.loads(files["BUILD-INFO.json"])
    compatibility = json.loads((source / "release/compatibility.json").read_text())
    abi = metadata.get("abi", {})
    rule = compatibility["targets"][target]
    qt = abi.get("qt", "")
    if (metadata.get("schema") != 1 or metadata.get("version") != value
            or metadata.get("commit") != commit or metadata.get("target") != target
            or metadata.get("channel") != ("candidate" if "-rc." in value else "stable")
            or metadata.get("binary_sha256") != sha256(files[module])
            or metadata.get("toolchain") != json.loads((source / "ci/toolchain.json").read_text())
            or abi.get("schema") != 1 or abi.get("copyq") != compatibility["copyq"]
            or abi.get("pointer_size") != 8 or abi.get("processor", "").lower() not in ("amd64", "x86_64")
            or not re.fullmatch(r"6\." + str(rule["qt_minor"]) + r"\.\d+", qt)
            or abi.get("compiler") not in rule["compiler"]):
        raise ValueError("Package version, commit, dependency, ABI or module hash differs")
    if not 0 < len(files[module]) <= 32 * 1024 * 1024 or value.encode() not in files[module] or not files[module].startswith(b"MZ" if windows else b"\x7fELF"):
        raise ValueError("Incorrect module format")
    for name in expected - {module, "COPYQ-LICENSE", "ZLIB-NOTICE.txt", "BUILD-INFO.json", "READ-ME-FIRST.txt", "PACKAGE-SHA256SUMS"}:
        original = "release/compatibility.json" if name == "COMPATIBILITY.json" else name
        if files[name] != (source / original).read_bytes():
            raise ValueError("Package documentation/installer differs from tested source: " + name)
    hashed = {n: raw for n, raw in files.items() if n != "PACKAGE-SHA256SUMS"}
    if files["PACKAGE-SHA256SUMS"] != checksums(hashed).encode():
        raise ValueError("Package member checksums differ")
    if path.name != package_name(value, target, commit):
        raise ValueError("Unversioned or mislabeled package filename")
    if not files["COPYQ-LICENSE"].strip() or (windows and not files["ZLIB-NOTICE.txt"].strip()):
        raise ValueError("Dependency license missing")
    return metadata
