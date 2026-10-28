#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package a disposable strict core24 host using provider-reported SDK assets."""
from pathlib import Path
import re
import shutil
import subprocess

source = Path(__file__).resolve().parents[1]
out = source / "out/installations"
root = out / "snap-stage"
if root.exists():
    raise RuntimeError("Snap fixture output must be fresh")
shutil.copytree(out / "host-stage/opt", root / "opt")
# These are public build SDK assets on a disposable VM, not user folder search.
qt_plugins = Path(subprocess.check_output(["qmake6", "-query", "QT_INSTALL_PLUGINS"], text=True).strip())
shutil.copytree(qt_plugins, root / "qt-plugins")
qca = subprocess.check_output(["dpkg-query", "-L", "libqca-qt6-plugins"], text=True).splitlines()
for path in qca:
    p = Path(path)
    if p.is_file() and ".so" in p.name:
        destination = root / p.relative_to("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, destination)
def elf_files(directory):
    for path in directory.rglob("*"):
        if path.is_file():
            with path.open("rb") as binary:
                if binary.read(4) == b"\x7fELF":
                    yield path


# Stock installation also includes a bash-completion file named "copyq".
# Dependency collection is based on the ELF format, never its basename.
queue = list(elf_files(root))
if root / "opt/cqs-copyq17-fixture/bin/copyq" not in queue:
    raise RuntimeError("The actual stock CopyQ ELF executable is missing")
seen = set()
while queue:
    binary = queue.pop()
    log = subprocess.check_output(["ldd", str(binary)], text=True)
    if "not found" in log:
        raise RuntimeError("Missing fixture dependency: " + log)
    for path in re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", log, re.MULTILINE):
        if path in seen:
            continue
        seen.add(path)
        destination = root / Path(path).relative_to("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(path, destination)
            queue.append(Path(path))
(root / "bin").mkdir()
(root / "meta").mkdir()
# Dependencies such as libproxy keep a backend in a private subdirectory.
# Retain every provider-reported dependency directory, not just lib/usr-lib.
(root / "library-paths").write_text("\n".join(sorted({str(Path(p).parent) for p in seen})) + "\n")
(root / "bin/launch").write_text('''#!/bin/sh
cqs_library_path=""
while IFS= read -r cqs_library_directory; do
    cqs_library_path="${cqs_library_path:+$cqs_library_path:}$SNAP$cqs_library_directory"
done < "$SNAP/library-paths"
export LD_LIBRARY_PATH="$cqs_library_path"
export QT_PLUGIN_PATH="$SNAP/qt-plugins"
export QCA_PLUGIN_PATH="$SNAP/usr/lib/x86_64-linux-gnu/qca-qt6"
exec "$SNAP/opt/cqs-copyq17-fixture/bin/copyq" "$@"
''')
(root / "bin/launch").chmod(0o755)
(root / "meta/snap.yaml").write_text('''name: cqs-cq
version: '17.0.0'
summary: Disposable stock CopyQ Secure Sync acceptance fixture
description: Test host only, never distributed in Secure Sync packages.
base: core24
grade: devel
confinement: strict
architectures: [amd64]
layout:
  /opt/cqs-copyq17-fixture:
    bind: $SNAP/opt/cqs-copyq17-fixture
apps:
  copyq:
    command: bin/launch
    plugs: [x11, desktop, home, network-bind]
''')
subprocess.run(["snap", "pack", str(root), str(out), "--filename=copyq17-fixture.snap"], check=True)
