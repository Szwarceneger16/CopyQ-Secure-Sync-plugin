#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Export a disposable patched CopyQ source tree; never modify the input checkout."""
import argparse
from io import BytesIO
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

PIN = "d0c179f75c04974bfe801289ea6e58a1a49535fc"

def git_at(directory, *arguments, binary=False):
    env = os.environ.copy()
    # An export inside the plugin checkout (the Windows CI layout) must not
    # discover the enclosing repository. Otherwise git apply silently skips
    # every src/ patch outside that repository's current-directory prefix.
    # Also ignore inherited repository selectors, without changing credentials.
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(name, None)
    env["GIT_CEILING_DIRECTORIES"] = str(directory.parent)
    return subprocess.run(["git", "-C", str(directory), *arguments],
                          env=env, check=True, text=not binary, stdout=subprocess.PIPE).stdout

def prepare(source, out, extension):
    source, out, extension = source.resolve(), out.resolve(), extension.resolve()
    if (source == out or source in out.parents or out in source.parents or
            extension == out or extension in out.parents or out in extension.parents):
        raise ValueError("Use a separate disposable output tree")
    actual = git_at(source, "rev-parse", "HEAD").strip()
    dirty = git_at(source, "status", "--porcelain", "--", "src")
    if actual != PIN or dirty:
        raise ValueError("A clean pinned CopyQ source tree is required")
    marker = out / ".cqs-host-export"
    if out.exists():
        if not marker.is_file() or marker.read_text() != PIN:
            raise ValueError("Refusing to replace an output directory without our export marker")
        shutil.rmtree(out)
    out.mkdir(parents=True)
    marker.write_text(PIN)
    # Export committed bytes, not a possibly CRLF-converted Windows checkout or
    # untracked local files. This preserves executable modes and keeps the
    # reviewed patch independent of core.autocrlf and checkout filters.
    archive = git_at(source, "-c", "core.autocrlf=false", "-c", "core.eol=lf",
                     "archive", "--format=tar", PIN, binary=True)
    with tarfile.open(fileobj=BytesIO(archive)) as tree:
        tree.extractall(out, filter="data")
    patch = extension / "copyq-17.patch"
    apply = ("-c", "core.autocrlf=false", "-c", "core.eol=lf", "apply")
    git_at(out, *apply, "--check", str(patch))
    git_at(out, *apply, str(patch))
    # Prove that every hunk is present before reporting a prepared host.
    git_at(out, *apply, "--reverse", "--check", str(patch))
    for name in ("tab_bridge.h", "tab_persistence.h", "tab_persistence.cpp", "verified_save_file.h"):
        shutil.copyfile(extension / name, out / "src/item" / name)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--copyq", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    prepare(a.copyq, a.out, Path(__file__).resolve().parent)
    print("PREPARED_COPYQ_HOST_EXTENSION", PIN)

if __name__ == "__main__":
    main()
