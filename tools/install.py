#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installation-time helper; CopyQ itself probes and stages inside its sandbox.

probe -- <exact CopyQ command and optional --session NAME>
stage --package ZIP --sha256 SHA256 -- <exact CopyQ command>
Neither command edits settings, overrides, launchers, existing modules or data.
The returned COPYQ_PLUGINS value takes effect only on the next server start.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile

PROBE = Path(__file__).with_name("installation.js").read_text(encoding="utf-8")
MAX_MODULE = 32 * 1024 * 1024
TARGETS = {"linux-ubuntu24.04-x86_64", "linux-system-qt6.4-x86_64",
           "linux-flatpak-kde6.10-x86_64", "windows-x86_64"}


def qt_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"6\.\d+\.\d+", value):
        raise ValueError("Unsupported Qt version")
    return tuple(map(int, value.split(".")))


def environment(probe):
    if probe.get("schema") != 1:
        raise ValueError("Unsupported installation probe")
    runtime = probe["runtime"]
    if runtime.get("FLATPAK_ID"):
        return "flatpak"
    if runtime.get("SNAP"):
        return "snap"
    return "appimage" if runtime.get("APPIMAGE") or runtime.get("APPDIR") else "native"


def plan(probe):
    kind = environment(probe)
    if probe.get("platform") not in {"linux", "windows"}:
        raise ValueError("Only Linux and Windows installations are supported")
    if probe.get("plugins_directory_readable") is not True:
        raise ValueError("CopyQ did not report a readable plugins directory; on split installations, install the matching CopyQ plugins package first")
    paths = probe["paths"]
    if not re.search(r"(?:^|\s)17\.0\.0$", probe["version"]):
        raise ValueError("Requires stock CopyQ 17.0.0; the package format alone does not establish compatibility")
    qt_version(probe["qt"])
    if not re.fullmatch(r"x86_64-little_endian-(?:lp64|llp64)", probe["arch"]):
        raise ValueError("Only the tested x86_64 ABI is supported")
    for name in ("exe", "plugins", "config", "data", "state"):
        value = paths.get(name)
        if not isinstance(value, str) or not value or any(c in value for c in "\x00\n\r;"):
            raise ValueError("CopyQ did not report a usable " + name + " path")
        if not (value.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", value)):
            raise ValueError("CopyQ reported a relative path")
    base = paths["state"].replace("\\", "/").rstrip("/") + "/securesync"
    if kind == "flatpak":
        # Older Flatpak releases do not persist the default XDG state location.
        # The runtime explicitly supplies persistent XDG_DATA_HOME; never infer
        # ~/.var/app or trust a writable ephemeral state path across instances.
        data = probe["runtime"].get("XDG_DATA_HOME", "")
        if not data.startswith("/") or any(c in data for c in "\x00\r\n;"):
            raise ValueError("Flatpak did not provide persistent XDG_DATA_HOME")
        base = data.rstrip("/") + "/securesync"
    if kind == "snap":
        common = probe["runtime"].get("SNAP_USER_COMMON", "")
        if not common.startswith("/") or any(c in common for c in "\x00\r\n;"):
            raise ValueError("Snap did not provide SNAP_USER_COMMON")
        base = common.rstrip("/") + "/securesync"
    profile = base + "/profiles/" + hashlib.sha256(paths["config"].encode("utf-8")).hexdigest()[:16]
    return {"schema": 1, "environment": kind, "copyq": paths,
            "module_root": base + "/modules", "suggested_state": profile + "/state",
            "suggested_vault": profile + "/vault", "encryption_compiled": probe["encryption_compiled"],
            "restart_required": True, "automatic_activation": False}


def check_compatibility(probe, metadata):
    result = plan(probe)
    target = metadata.get("target")
    if target not in TARGETS:
        raise ValueError("Unknown package target")
    abi = metadata.get("abi", {})
    if abi.get("schema") != 1 or abi.get("copyq") != "17.0.0" or abi.get("pointer_size") != 8 or abi.get("processor", "").lower() not in {"amd64", "x86_64"}:
        raise ValueError("Package is missing supported build ABI metadata")
    built, host = qt_version(abi.get("qt")), qt_version(probe["qt"])
    if host[:2] < built[:2] or host[1] > 11:
        raise ValueError("Package requires a newer Qt minor or this Qt minor is not validated")
    windows = "llp64" in probe["arch"]
    if windows != (probe["platform"] == "windows"):
        raise ValueError("CopyQ operating system and pointer ABI differ")
    if windows != (target == "windows-x86_64"):
        raise ValueError("Package operating system differs from CopyQ")
    if windows and (abi.get("compiler") != "MSVC" or probe["compiler"] != "MSVC"):
        raise ValueError("Windows requires the tested MSVC ABI")
    if result["environment"] == "flatpak":
        if target != "linux-flatpak-kde6.10-x86_64" or probe["runtime"].get("flatpak_runtime") != "org.kde.Platform/x86_64/6.10":
            raise ValueError("Flatpak requires its matching KDE SDK package and runtime")
    elif "flatpak" in target:
        raise ValueError("A Flatpak SDK package cannot be installed into this application")
    # Strict Snap must use the native package compiled for its base, never the
    # newer-glibc AppImage SDK. Actual loading remains the acceptance check.
    if result["environment"] == "snap" and (target != "linux-system-qt6.4-x86_64" or probe["runtime"].get("snap_base") != "core24"):
        raise ValueError("Snap requires the separately tested core24 base and system-Qt package")
    return result


def read_package(path, expected_sha):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise ValueError("Provide the package's SHA256SUMS value")
    if path.stat().st_size > 48 * 1024 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha:
        raise ValueError("Package SHA256 mismatch or size limit exceeded")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)) or z.getinfo("BUILD-INFO.json").file_size > 65536:
            raise ValueError("Duplicate ZIP members or oversized metadata")
        metadata = json.loads(z.read("BUILD-INFO.json"))
        name = "securesync.dll" if metadata.get("target") == "windows-x86_64" else "libsecuresync.so"
        entry = z.getinfo("copyq/plugins/" + name)
        if not 0 < entry.file_size <= MAX_MODULE:
            raise ValueError("Module size limit exceeded")
        raw = z.read(entry)
    if hashlib.sha256(raw).hexdigest() != metadata.get("binary_sha256"):
        raise ValueError("Module SHA256 mismatch")
    return metadata, name, raw


def stage_script(probe, metadata, name, raw):
    result = check_compatibility(probe, metadata)
    if name != ("securesync.dll" if metadata["target"] == "windows-x86_64" else "libsecuresync.so") or not 0 < len(raw) <= MAX_MODULE:
        raise ValueError("Invalid module")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != metadata["binary_sha256"]:
        raise ValueError("Module hash mismatch")
    # New immutable directory on every attempt. Never overwrite a mapped SO/DLL
    # or reuse an incomplete stage. Failure cannot activate the partial file.
    settings = {"root": result["module_root"], "leaf": uuid.uuid4().hex,
                "name": name, "sha256": digest, "size": len(raw),
                "probe": probe}
    script = "var cqsStage=" + json.dumps(settings, ensure_ascii=True) + ";\n"
    script += "var cqsCurrent=" + PROBE + ";\n"
    script += r"""
(function () {
    var before = cqsStage.probe, now = JSON.parse(cqsCurrent);
    if (JSON.stringify(before) !== JSON.stringify(now)) throw new Error("CopyQ environment changed; probe again");
    var payload = input();
    if (payload.length !== cqsStage.size || str(sha256sum(payload)) !== cqsStage.sha256)
        throw new Error("Module input mismatch");
    var root = new Dir(cqsStage.root);
    if (!root.mkpath(".")) throw new Error("Module root is not writable inside CopyQ");
    if (!root.mkdir(cqsStage.leaf)) throw new Error("Stage already exists or cannot be created");
    var destination = root.absoluteFilePath(cqsStage.leaf + "/" + cqsStage.name);
    var file = new File(destination);
    if (file.exists() || !file.openWriteOnly()) throw new Error("Stage is not empty or writable");
    if (file.write(payload) !== cqsStage.size || !file.flush()) { file.close(); throw new Error("Stage write failed"); }
    file.close();
    if (!file.openReadOnly()) throw new Error("Stage verification failed");
    var verified = file.read(cqsStage.size + 1); file.close();
    if (verified.length !== cqsStage.size || str(sha256sum(verified)) !== cqsStage.sha256)
        throw new Error("Stage verification failed");
    var custom = before.runtime.COPYQ_PLUGINS;
    // Refuse ambiguous replacement. Explicitly remove the old securesync entry
    // from the launch configuration before using the returned value on restart.
    return JSON.stringify({schema:1, staged_module:str(destination), sha256:cqsStage.sha256,
        previous_custom_plugins:custom, restart_required:true, activated:false});
})()
"""
    return script


def call(command, script, payload=None):
    result = subprocess.run([*command, "eval", encode_script(script)], input=payload, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError("Selected CopyQ refused the request; check its running session and sandbox permissions")
    if len(result.stdout) > 65536:
        raise ValueError("Oversized CopyQ reply")
    return json.loads(result.stdout.decode("utf-8"))


def encode_script(script):
    # CopyQ's CLI unescapes command arguments even without a shell. Transport
    # reviewed code as base64 so regexes, Windows paths and JSON stay exact.
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return "eval(str(fromBase64('" + encoded + "')))"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("probe", "stage"))
    p.add_argument("--package", type=Path)
    p.add_argument("--sha256")
    # Split explicitly: argparse REMAINDER would swallow stage options.
    args = sys.argv[1:]
    if "--" not in args and ("--help" in args or "-h" in args):
        p.print_help()
        return
    if "--" not in args:
        p.error("provide -- followed by the exact running CopyQ command")
    boundary = args.index("--"); a = p.parse_args(args[:boundary]); command = args[boundary + 1:]
    if not command:
        p.error("empty CopyQ command")
    try:
        probe = call(command, PROBE)
        result = {"probe": probe, "plan": plan(probe)}
        if a.action == "stage":
            if a.package is None or a.sha256 is None:
                p.error("stage requires --package and --sha256")
            metadata, name, raw = read_package(a.package, a.sha256)
            result["stage"] = call(command, stage_script(probe, metadata, name, raw), raw)
        print(json.dumps(result, indent=2, ensure_ascii=True))
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        p.exit(1, "Installation refused: " + str(error) + "\n")


if __name__ == "__main__":
    main()
