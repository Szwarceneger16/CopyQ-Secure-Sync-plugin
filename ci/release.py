#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Promote exact successful main-branch CI artifacts; never rebuild a release."""
import argparse
import gzip
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from check_tests_loader import gate
from distribution import TARGET_ARTIFACTS, checksums, package_name, sha256, validate_package, version

WORKFLOW = '.github/workflows/native-ci.yml'
JOBS = {'Linux / Ubuntu 24.04 container / Qt 6.10', 'Windows / real NTFS / MSVC 2022 / Qt 6.10',
        'Flatpak / installed CopyQ 17 / matching KDE SDK 6.10',
        'Linux / source + DEB + strict Snap / system Qt 6.4', 'Native CI gate'}
REPORTS = {'linux-native-reports', 'windows-native-reports', 'flatpak-gui-reports', 'linux-installation-reports'}
QUALIFICATIONS = {'physical-two-device-nextcloud', 'fault-and-historical-upgrade-acceptance', 'target-limit-performance'}


def api(endpoint):
    result = subprocess.run(['gh', 'api', endpoint], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def check_run(run, jobs, repository, main_commit):
    if (not re.fullmatch(r'[0-9a-f]{40}', main_commit) or run.get('head_sha') != main_commit
            or run.get('repository', {}).get('full_name') != repository
            or run.get('head_repository', {}).get('full_name') != repository
            or run.get('head_branch') != 'main' or run.get('event') not in ('push', 'workflow_dispatch')
            or run.get('path') != WORKFLOW or run.get('status') != 'completed' or run.get('conclusion') != 'success'):
        raise ValueError('Requires successful native CI for the current main commit in this repository')
    if len(jobs) != len(JOBS) or {j.get('name') for j in jobs} != JOBS:
        raise ValueError('Incomplete or duplicate CI job matrix')
    if any(j.get('run_id') != run['id'] or j.get('status') != 'completed'
           or j.get('conclusion') != 'success' or not j.get('steps') for j in jobs):
        raise ValueError('Every actual platform job and the aggregate gate must have run successfully')
    return run['head_sha']


def inspect(repository, run_id):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or run_id < 1:
        raise ValueError('Invalid repository/run')
    prefix = 'repos/' + repository
    run = api(f'{prefix}/actions/runs/{run_id}')
    jobs = api(f'{prefix}/actions/runs/{run_id}/jobs?filter=latest&per_page=100')['jobs']
    main = api(f'{prefix}/git/ref/heads/main')['object']['sha']
    commit = check_run(run, jobs, repository, main)
    artifacts = api(f'{prefix}/actions/runs/{run_id}/artifacts?per_page=100')['artifacts']
    required = set(TARGET_ARTIFACTS.values()) | REPORTS
    selected = [a for a in artifacts if a['name'] in required]
    if len(selected) != len(required) or {a['name'] for a in selected} != required or any(a.get('expired') for a in selected):
        raise ValueError('Required package/report artifacts are missing, duplicate or expired')
    return {'schema': 1, 'repository': repository, 'run_id': run_id, 'attempt': run['run_attempt'], 'commit': commit,
            'run_url': f'https://github.com/{repository}/actions/runs/{run_id}',
            'jobs': [{'id': j['id'], 'name': j['name']} for j in sorted(jobs, key=lambda j: j['name'])],
            'artifacts': [{'id': a['id'], 'name': a['name'], 'digest': a.get('digest')} for a in sorted(selected, key=lambda a: a['name'])]}


def check_qualification(source, value):
    qualification = json.loads((source / 'release/qualification.json').read_text())
    if qualification.get('schema') != 1 or set(qualification.get('gates', {})) != QUALIFICATIONS:
        raise ValueError('Invalid production qualification inventory')
    if '-rc.' not in value:
        for item in qualification['gates'].values():
            if item.get('status') != 'passed' or not re.fullmatch(r'https://[^\s]+', item.get('evidence') or ''):
                raise ValueError('Stable publication requires reviewed evidence for every production qualification gate')
    return qualification


def validate_reports(root):
    for platform in ('linux', 'windows'):
        report = root / f'{platform}-native-reports'
        xml = ET.parse(report / 'reports/ctest.xml').getroot()
        log = (report / 'build/Testing/Temporary/LastTest.log').read_text(encoding='utf-8')
        gate.check_result(xml, gate.expected(platform), log)
    scenarios = [('linux-native-reports', 'reports/nextcloud/result.json', 11),
                 ('windows-native-reports', 'reports/official-gui/result.json', 17),
                 ('windows-native-reports', 'reports/installed-gui/result.json', 17),
                 ('flatpak-gui-reports', 'default-installation/result.json', 5),
                 ('flatpak-gui-reports', 'official-gui/result.json', 17)]
    scenarios += [('linux-installation-reports', f'{kind}/result.json', 17) for kind in ('source', 'deb', 'snap')]
    for artifact, name, minimum in scenarios:
        value = json.loads((root / artifact / name).read_text())
        if value.get('status') != 'passed' or len(value.get('checks', [])) < minimum:
            raise ValueError('Installed-host acceptance report missing or incomplete: ' + name)
    if (root / 'linux-installation-reports/snap-confinement.txt').read_text().strip() != 'strict':
        raise ValueError('Snap acceptance did not execute with strict confinement')


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()


def source_archive(source, copyq, zlib, target, value, commit, lock):
    """Only committed bytes; shallow, self-contained Git identities permit offline builds."""
    roots = [('plugin', source, commit), ('copyq', copyq, lock['copyq_commit']), ('zlib', zlib, lock['zlib_commit'])]
    with tempfile.TemporaryDirectory(prefix='cqs-release-sources-') as temp:
        base = Path(temp) / ('CopyQ-Secure-Sync-' + value)
        base.mkdir()
        for name, original, expected in roots:
            if git(original, 'rev-parse', 'HEAD') != expected:
                raise ValueError('Wrong corresponding-source commit: ' + name)
            clone = base / name
            subprocess.run(['git', '-c', 'core.autocrlf=false', 'clone', '--no-local', '--depth=1',
                            '--no-checkout', '--quiet', str(original.resolve()), str(clone)], check=True)
            subprocess.run(['git', '-C', str(clone), '-c', 'core.autocrlf=false', 'checkout', '--quiet', '--detach', expected], check=True)
            subprocess.run(['git', '-C', str(clone), 'remote', 'remove', 'origin'], check=True)
            shutil.rmtree(clone / '.git/logs', ignore_errors=True)
            shutil.rmtree(clone / '.git/hooks', ignore_errors=True)
            if git(clone, 'rev-parse', 'HEAD') != expected or (clone / '.git/objects/info/alternates').exists():
                raise ValueError('Source checkout is not self-contained')
        (base / 'BUILD-SOURCES.txt').write_text(
            f'CopyQ Secure Sync {value}\nPlugin commit: {commit}\n'
            'plugin/, copyq/, zlib/ contain exact committed sources and their original licenses.\n'
            'Each includes a credential-free shallow .git identity for offline source/ABI checks.\n'
            'Install the matching Qt SDK, CMake, Ninja, compiler, system OpenSSL/zlib (Linux).\n'
            'Linux example from this directory:\n'
            'cmake -S plugin -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF '
            '-DCQS_BUILD_NATIVE_PLUGIN=ON -DCOPYQ_SOURCE_DIR="$PWD/copyq"\n'
            'cmake --build build --parallel 2\n'
            'Windows: build zlib/ with MSVC, then use the same SDK/CRT and ZLIB_ROOT.\n'
            'See plugin/docs/CI.md and plugin/ci/ for the pinned build environments.\n'
            'Qt and system libraries are not redistributed. Historical host tests are optional.\n', encoding='utf-8')
        def normalized(info):
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = 0
            return info
        with target.open('wb') as out, gzip.GzipFile(filename='', fileobj=out, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                archive.add(base, arcname=base.name, filter=normalized)


def assemble(source, root, out, proof, copyq, zlib):
    value = version(source)
    qualification = check_qualification(source, value)
    if git(source, 'rev-parse', 'HEAD') != proof['commit']:
        raise ValueError('Release source differs from tested commit')
    validate_reports(root)
    if out.exists() and any(out.iterdir()):
        raise ValueError('Release output must be empty')
    out.mkdir(parents=True, exist_ok=True)
    lock = json.loads((source / 'ci/toolchain.json').read_text())
    try:
        for target, artifact in TARGET_ARTIFACTS.items():
            folder = root / artifact
            packages = list(folder.glob('*.zip'))
            if len(packages) != 1 or {p.name for p in folder.iterdir()} != {packages[0].name, 'SHA256SUMS'}:
                raise ValueError('Expected exactly one module ZIP and checksums: ' + artifact)
            package = packages[0]
            if (folder / 'SHA256SUMS').read_bytes() != checksums({package.name: package.read_bytes()}).encode():
                raise ValueError('CI artifact checksum mismatch')
            validate_package(package, source, proof['commit'], target)
            from distribution import read_zip
            members = read_zip(package)
            if members['COPYQ-LICENSE'].replace(b'\r\n', b'\n') != (copyq / 'LICENSE').read_bytes().replace(b'\r\n', b'\n'):
                raise ValueError('CopyQ license differs from pinned source')
            if target == 'windows-x86_64' and members['ZLIB-NOTICE.txt'].replace(b'\r\n', b'\n') != (zlib / 'README').read_bytes().replace(b'\r\n', b'\n'):
                raise ValueError('zlib notice differs from pinned source')
            shutil.copyfile(package, out / package.name)
        archive = out / f'securesync-{value}-sources.tar.gz'
        source_archive(source, copyq, zlib, archive, value, proof['commit'], lock)
        notes = (source / 'CHANGELOG.md').read_text(encoding='utf-8')
        marker = '## ' + value + ' — '
        if notes.count(marker) != 1:
            raise ValueError('Version missing from changelog')
        section = notes.split(marker, 1)[1].split('\n## ', 1)[0]
        (out / 'RELEASE-NOTES.md').write_text(f'# Secure Sync {value} — ' + section + '\n\n'
            + f"Tested commit: `{proof['commit']}`\n\nCI: {proof['run_url']}\n\n"
            + 'See COMPATIBILITY.json inside each ZIP and docs/INSTALLATION.md. '
            + 'Corresponding sources and SHA256SUMS accompany these exact tested binaries.\n', encoding='utf-8')
        manifest = {'schema': 1, 'version': value, 'tag': 'v' + value, 'commit': proof['commit'],
                    'prerelease': '-rc.' in value, 'ci': proof, 'qualification': qualification,
                    'assets': {p.name: sha256(p.read_bytes()) for p in sorted(out.iterdir())}}
        (out / 'RELEASE-MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        (out / 'SHA256SUMS').write_bytes(checksums({p.name: p.read_bytes() for p in out.iterdir()}).encode('utf-8'))
    except Exception:
        # This dedicated output was empty on entry; never leave a partial candidate.
        for item in out.iterdir():
            item.unlink()
        raise
    return manifest


def verify_bundle(directory, source, proof):
    value = version(source)
    manifest = json.loads((directory / 'RELEASE-MANIFEST.json').read_text())
    packages = {package_name(value, t, proof['commit']) for t in TARGET_ARTIFACTS}
    expected = packages | {f'securesync-{value}-sources.tar.gz', 'RELEASE-NOTES.md'}
    if (manifest.get('schema') != 1 or manifest.get('version') != value or manifest.get('tag') != 'v' + value
            or manifest.get('commit') != proof['commit'] or manifest.get('prerelease') != ('-rc.' in value)
            or manifest.get('ci') != proof or manifest.get('qualification') != check_qualification(source, value)
            or set(manifest.get('assets', {})) != expected
            or {p.name for p in directory.iterdir()} != expected | {'RELEASE-MANIFEST.json', 'SHA256SUMS'}):
        raise ValueError('Release bundle identity/inventory differs')
    files = {p.name: p.read_bytes() for p in directory.iterdir() if p.name != 'SHA256SUMS'}
    if (directory / 'SHA256SUMS').read_bytes() != checksums(files).encode():
        raise ValueError('Release checksums differ')
    if any(sha256(files[n]) != digest for n, digest in manifest['assets'].items()):
        raise ValueError('Release asset differs')
    for target in TARGET_ARTIFACTS:
        validate_package(directory / package_name(value, target, proof['commit']), source, proof['commit'], target)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'assemble', 'verify', 'publish'))
    parser.add_argument('--repository', required=True)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--source', type=Path, default=Path('.'))
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--out', type=Path, default=Path('release-assets'))
    parser.add_argument('--copyq', type=Path)
    parser.add_argument('--zlib', type=Path)
    args = parser.parse_args()
    proof = inspect(args.repository, args.run_id) # Re-check CI and current main even at publication.
    if args.action == 'inspect':
        print(json.dumps(proof))
        return
    if args.action == 'assemble':
        result = assemble(args.source, args.artifacts, args.out, proof, args.copyq, args.zlib)
    else:
        result = verify_bundle(args.out, args.source, proof)
        if args.action == 'publish':
            # Refuse collisions and partial earlier publications; never overwrite a tag/release.
            check = subprocess.run(['gh', 'api', f"repos/{args.repository}/git/ref/tags/{result['tag']}"], capture_output=True, text=True)
            if check.returncode == 0 or 'HTTP 404' not in check.stderr:
                raise ValueError('Tag already exists or tag lookup failed; inspect manually')
            command = ['gh', 'release', 'create', result['tag'], '--repo', args.repository,
                       '--target', result['commit'], '--title', 'Secure Sync ' + result['version'],
                       '--notes-file', str(args.out / 'RELEASE-NOTES.md'), '--draft']
            if result['prerelease']:
                command.append('--prerelease')
            else:
                command += ['--latest']
            command += [str(p) for p in sorted(args.out.iterdir())]
            subprocess.run(command, check=True)
            subprocess.run(['gh', 'release', 'edit', result['tag'], '--repo', args.repository, '--draft=false'], check=True)
    print(json.dumps({'commit': result['commit'], 'version': result['version'], 'tag': result['tag']}))


if __name__ == '__main__':
    main()
