#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Distinguish a pre-feature branch from an incomplete signed implementation."""
import argparse
from pathlib import Path


SOURCES = {
    "src/device_trust_journal.cpp",
    "src/device_identity_vault.cpp",
    "src/device_signed_event.cpp",
    "src/signed_join_checkpoint.cpp",
    "native/signed_join_entry.cpp",
    "native/signed_join_wizard.cpp",
    "native/signed_tab_storage.cpp",
    "native/signed_replica_background.cpp",
}


def signed_sources(source):
    present = {path for path in SOURCES if (source / path).is_file()}
    declared = "option(CQS_BUILD_SIGNED_JOIN " in (source / "CMakeLists.txt").read_text(encoding="utf-8")
    if not present and not declared:
        return False
    if present != SOURCES or not declared:
        raise ValueError("Incomplete signed source tree: " + ", ".join(sorted(SOURCES - present)))
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    print("true" if signed_sources(args.source) else "false")


if __name__ == "__main__":
    main()
