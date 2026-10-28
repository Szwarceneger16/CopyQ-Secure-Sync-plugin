#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package the main native sync module and its exact distribution contract."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
from distribution import DOCS, TARGET_ARTIFACTS, checksums, package_name, sha256, validate_package, version


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform', required=True, choices=tuple(TARGET_ARTIFACTS))
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--copyq', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--zlib', type=Path)
    a = p.parse_args()
    commit = subprocess.check_output(['git', '-C', str(a.source), 'rev-parse', 'HEAD'], text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Expected a concrete tested commit')
    subprocess.run(['git', '-C', str(a.source), 'diff', '--quiet', 'HEAD', '--'], check=True)
    subprocess.run(['git', '-C', str(a.source), 'ls-files', '--error-unmatch', 'VERSION', 'CHANGELOG.md', 'ci/distribution.py'], check=True, stdout=subprocess.DEVNULL)
    source_repository = os.environ.get('GITHUB_REPOSITORY', 'local checkout')
    if source_repository != 'local checkout' and not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', source_repository):
        raise ValueError('Invalid GITHUB_REPOSITORY')
    value = version(a.source)
    windows = a.platform == 'windows-x86_64'
    binary = a.out / 'stage/copyq/plugins' / ('securesync.dll' if windows else 'libsecuresync.so')
    if binary.is_symlink() or not binary.is_file() or not 0 < binary.stat().st_size <= 32 * 1024 * 1024:
        raise ValueError('Installed main native module missing or oversized')
    raw = binary.read_bytes()
    if value.encode() not in raw:
        raise ValueError('Module release version metadata missing; rebuild the actual module')
    abi = json.loads((a.out / 'build/cqs-abi.json').read_text())
    channel = 'candidate' if '-rc.' in value else 'stable'
    metadata = {'schema': 1, 'version': value, 'channel': channel, 'commit': commit,
                'target': a.platform, 'toolchain': json.loads((a.source / 'ci/toolchain.json').read_text()),
                'abi': abi, 'binary_sha256': sha256(raw),
                'status': 'Native Secure Sync; candidate builds require remaining product qualification.' if channel == 'candidate' else 'Native Secure Sync; see qualification evidence in the release manifest.',
                'compatibility': 'Stock CopyQ 17.0.0 x86_64; actual compiled Qt ' + abi['qt'] + '. See COMPATIBILITY.json and docs/INSTALLATION.md.',
                'host_bridge': 'Not linked or packaged; no CopyQ patch or rebuild is required.'}
    notice = (f'COPYQ SECURE SYNC {value} ({channel.upper()})\n'
              'Main native synchronization plugin for stock CopyQ 17.0.0 x86_64.\n'
              'Includes encrypted local storage, Seed/Join, automatic synchronization,\n'
              'conflict recovery, shared-key rotation and compact successor histories.\n'
              'Setup, key sharing and automatic synchronization require explicit actions.\n'
              'Install the matching ABI package using docs/INSTALLATION.md; restart CopyQ.\n'
              'No replacement CopyQ, host patch, laboratory plugin or runtime Python agent.\n'
              'Read CHANGELOG.md, COMPATIBILITY.json and THIRD-PARTY-NOTICES.md.\n'
              'Qt is supplied by CopyQ. Linux also needs system/runtime libcrypto and zlib.\n'
              'Back up state and vault before upgrade. Older modules cannot read schema 6;\n'
              'keep a backup and do not downgrade in place. Follow docs/DEVICE-SETUP.md\n'
              'for the Python 0.1.1 transition; do not run both implementations as writers.\n'
              'Corresponding sources accompany GitHub Releases; see docs/RELEASING.md.\n'
              f'Tested build sources: {source_repository}, commit {commit}\n')
    files = {'copyq/plugins/' + binary.name: raw, 'COPYQ-LICENSE': (a.copyq / 'LICENSE').read_bytes(),
             'COMPATIBILITY.json': (a.source / 'release/compatibility.json').read_bytes(),
             'BUILD-INFO.json': (json.dumps(metadata, indent=2) + '\n').encode(),
             'READ-ME-FIRST.txt': notice.encode()}
    for name in ('LICENSE', 'THIRD-PARTY-NOTICES.md', 'CHANGELOG.md', 'VERSION', 'tools/install.py', 'tools/installation.js', *('docs/' + n for n in DOCS)):
        files[name] = (a.source / name).read_bytes()
    if windows:
        if a.zlib is None:
            raise ValueError('Static zlib license source is required')
        files['ZLIB-NOTICE.txt'] = (a.zlib / 'README').read_bytes()
    files['PACKAGE-SHA256SUMS'] = checksums(files).encode()
    target = a.out / package_name(value, a.platform, commit)
    temporary = a.out / (target.name + '.tmp')
    try:
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, payload in sorted(files.items()):
                z.writestr(name, payload)
        # Validate before making an invalid package visible at its final name.
        # The validator also enforces the final versioned filename.
        temporary.replace(target)
        validate_package(target, a.source, commit, a.platform)
    except Exception:
        temporary.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        raise
    (a.out / 'SHA256SUMS').write_bytes(checksums({target.name: target.read_bytes()}).encode())
    print('PACKAGED_TESTED_NATIVE_MODULE', target.name)


if __name__ == '__main__':
    main()
