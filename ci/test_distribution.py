# SPDX-License-Identifier: GPL-3.0-or-later
"""Distribution acceptance uses synthetic modules; real Qt loading remains required in CI."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile
import distribution as d
import release as r

ROOT = Path(__file__).resolve().parents[1]


def commit(folder):
    subprocess.run(['git', 'init', '--quiet', str(folder)], check=True)
    subprocess.run(['git', '-C', str(folder), 'config', 'core.autocrlf', 'false'], check=True)
    subprocess.run(['git', '-C', str(folder), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(folder), '-c', 'user.name=Release test', '-c', 'user.email=release@example.invalid',
                    'commit', '--quiet', '-m', 'Public synthetic fixture'], check=True)
    return r.git(folder, 'rev-parse', 'HEAD')


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cqs-distribution-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        originals = d.COMMON - {'COPYQ-LICENSE', 'COMPATIBILITY.json', 'BUILD-INFO.json', 'READ-ME-FIRST.txt', 'PACKAGE-SHA256SUMS'}
        originals |= {'release/compatibility.json', 'release/qualification.json', 'ci/distribution.py'}
        for name in originals:
            dest = self.source / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        self.copyq = self.base / 'copyq'
        self.copyq.mkdir()
        (self.copyq / 'LICENSE').write_text('Synthetic public CopyQ license\n')
        self.copyq_commit = commit(self.copyq)
        self.zlib = self.base / 'zlib'
        self.zlib.mkdir()
        (self.zlib / 'README').write_text('Synthetic public zlib license\n')
        self.zlib_commit = commit(self.zlib)
        self.lock = json.loads((ROOT / 'ci/toolchain.json').read_text())
        self.lock.update(copyq_commit=self.copyq_commit, zlib_commit=self.zlib_commit)
        (self.source / 'ci').mkdir(exist_ok=True)
        (self.source / 'ci/toolchain.json').write_text(json.dumps(self.lock))
        self.commit = commit(self.source)
        self.proof = {'schema': 1, 'repository': 'example/repository', 'commit': self.commit, 'run_id': 42,
                      'run_url': 'https://github.com/example/repository/actions/runs/42', 'attempt': 1,
                      'jobs': [], 'artifacts': []}
        self.artifacts = self.base / 'artifacts'
        self.artifacts.mkdir()

    def package(self, target='linux-ubuntu24.04-x86_64'):
        out = self.artifacts / d.TARGET_ARTIFACTS[target]
        (out / 'build').mkdir(parents=True)
        windows = target == 'windows-x86_64'
        module = out / 'stage/copyq/plugins' / ('securesync.dll' if windows else 'libsecuresync.so')
        module.parent.mkdir(parents=True)
        module.write_bytes((b'MZ' if windows else b'\x7fELF') + b' synthetic test module ' + d.version(self.source).encode())
        abi = {'schema': 1, 'copyq': '17.0.0', 'qt': '6.4.2' if 'system' in target else '6.10.3',
               'pointer_size': 8, 'processor': 'AMD64' if windows else 'x86_64', 'compiler': 'MSVC' if windows else 'GNU'}
        (out / 'build/cqs-abi.json').write_text(json.dumps(abi))
        subprocess.run([sys.executable, str(ROOT / 'ci/package.py'), '--platform', target, '--source', str(self.source),
                        '--copyq', str(self.copyq), '--zlib', str(self.zlib), '--out', str(out)], check=True, capture_output=True)
        package = next(out.glob('*.zip'))
        # Uploaded module artifacts contain only the generated ZIP and sums.
        shutil.rmtree(out / 'build')
        shutil.rmtree(out / 'stage')
        return package

    def reports(self):
        for platform in ('linux', 'windows'):
            folder = self.artifacts / f'{platform}-native-reports'
            (folder / 'reports').mkdir(parents=True)
            (folder / 'build/Testing/Temporary').mkdir(parents=True)
            suite = ET.Element('testsuite')
            for name in sorted(r.gate.expected(platform)):
                ET.SubElement(suite, 'testcase', {'name': name, 'status': 'run'})
            ET.ElementTree(suite).write(folder / 'reports/ctest.xml')
            (folder / 'build/Testing/Temporary/LastTest.log').write_text('All scenarios ran\n')
        cases = [('linux-native-reports', 'reports/nextcloud/result.json', 11),
                 ('windows-native-reports', 'reports/official-gui/result.json', 17),
                 ('windows-native-reports', 'reports/installed-gui/result.json', 17),
                 ('flatpak-gui-reports', 'default-installation/result.json', 5),
                 ('flatpak-gui-reports', 'official-gui/result.json', 17)]
        cases += [('linux-installation-reports', f'{kind}/result.json', 17) for kind in ('source', 'deb', 'snap')]
        for artifact, name, count in cases:
            path = self.artifacts / artifact / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'status': 'passed', 'checks': [f'check {i}' for i in range(count)]}))
        (self.artifacts / 'linux-installation-reports/snap-confinement.txt').write_text('strict\n')

    def rewrite(self, package, change):
        files = d.read_zip(package)
        change(files)
        files['PACKAGE-SHA256SUMS'] = d.checksums({n: raw for n, raw in files.items() if n != 'PACKAGE-SHA256SUMS'}).encode()
        with zipfile.ZipFile(package, 'w') as z:
            for n, raw in files.items():
                z.writestr(n, raw)

    def test_four_actual_packaging_contracts_and_installer(self):
        from test_installation import installer
        for target in d.TARGET_ARTIFACTS:
            with self.subTest(target=target):
                package = self.package(target)
                metadata = d.validate_package(package, self.source, self.commit, target)
                value, name, raw = installer.read_package(package, d.sha256(package.read_bytes()))
                self.assertEqual(value['version'], d.version(self.source))
                self.assertEqual(d.sha256(raw), metadata['binary_sha256'])
                self.assertNotIn('host/', '\n'.join(d.read_zip(package)))

    def test_patch_lab_extra_module_and_path_traversal_are_refused(self):
        for forbidden in ('host/copyq-17.patch', 'copyq/plugins/libsecuresynclab.so', 'copyq/copyq.exe', '../escape'):
            with self.subTest(forbidden=forbidden):
                package = self.package()
                self.rewrite(package, lambda f: f.update({forbidden: b'forbidden'}))
                with self.assertRaises(ValueError):
                    d.validate_package(package, self.source, self.commit, 'linux-ubuntu24.04-x86_64')
                shutil.rmtree(package.parent)

    def test_wrong_commit_target_version_or_binary_cannot_be_relabelled(self):
        for field, replacement in (('commit', '0' * 40), ('version', '0.1.1'), ('target', 'windows-x86_64'), ('binary_sha256', '0' * 64)):
            with self.subTest(field=field):
                package = self.package()
                def change(files):
                    meta = json.loads(files['BUILD-INFO.json']);meta[field] = replacement
                    files['BUILD-INFO.json'] = json.dumps(meta).encode()
                self.rewrite(package, change)
                with self.assertRaises(ValueError):
                    d.validate_package(package, self.source, self.commit, 'linux-ubuntu24.04-x86_64')
                shutil.rmtree(package.parent)

    def test_changed_installer_refused_even_with_updated_checksums(self):
        package = self.package()
        self.rewrite(package, lambda f: f.update({'tools/install.py': b'changed installer'}))
        with self.assertRaises(ValueError):
            d.validate_package(package, self.source, self.commit, 'linux-ubuntu24.04-x86_64')

    def test_duplicate_member_and_corruption_refused(self):
        package = self.package()
        with zipfile.ZipFile(package, 'a') as z:
            z.writestr('VERSION', '0.1.1')
        with self.assertRaises(ValueError):
            d.validate_package(package, self.source, self.commit, 'linux-ubuntu24.04-x86_64')

    def test_incomplete_native_gui_and_unconfined_snap_reports_refused(self):
        self.reports()
        r.validate_reports(self.artifacts)
        snap = self.artifacts / 'linux-installation-reports/snap-confinement.txt'
        snap.write_text('devmode')
        with self.assertRaises(ValueError): r.validate_reports(self.artifacts)
        snap.write_text('strict')
        gui = self.artifacts / 'windows-native-reports/reports/official-gui/result.json'
        gui.write_text(json.dumps({'status': 'passed', 'checks': []}))
        with self.assertRaises(ValueError): r.validate_reports(self.artifacts)
        gui.write_text(json.dumps({'status': 'passed', 'checks': ['ok'] * 17}))
        report = self.artifacts / 'linux-native-reports/reports/ctest.xml'
        xml = ET.parse(report).getroot();xml.remove(xml.find('testcase'));ET.ElementTree(xml).write(report)
        with self.assertRaises(ValueError): r.validate_reports(self.artifacts)

    def test_stable_requires_all_reviewed_qualification_evidence(self):
        r.check_qualification(self.source, '0.2.0-rc.1')
        with self.assertRaises(ValueError): r.check_qualification(self.source, '0.2.0')
        qualification = {'schema': 1, 'gates': {n: {'status': 'passed', 'evidence': 'https://example.invalid/reviewed-report'} for n in r.QUALIFICATIONS}}
        path = self.source / 'release/qualification.json';path.write_text(json.dumps(qualification))
        r.check_qualification(self.source, '0.2.0')
        qualification['gates'].pop(next(iter(r.QUALIFICATIONS)));path.write_text(json.dumps(qualification))
        with self.assertRaises(ValueError): r.check_qualification(self.source, '0.2.0')

    def test_whole_bundle_and_corresponding_sources_are_exact_and_offline(self):
        self.reports()
        for target in d.TARGET_ARTIFACTS: self.package(target)
        (self.source / 'UNTRACKED-PRIVATE.key').write_text('synthetic private scratch')
        (self.source / 'LICENSE').write_text('uncommitted mutation')
        # Package/source mismatch must fail before a release can be assembled.
        with self.assertRaises(ValueError):
            r.assemble(self.source, self.artifacts, self.base / 'release', self.proof, self.copyq, self.zlib)
        subprocess.run(['git', '-C', str(self.source), 'restore', 'LICENSE'], check=True)
        out = self.base / 'release'
        manifest = r.assemble(self.source, self.artifacts, out, self.proof, self.copyq, self.zlib)
        self.assertTrue(manifest['prerelease'])
        r.verify_bundle(out, self.source, self.proof)
        archive = out / f'securesync-{d.version(self.source)}-sources.tar.gz'
        with tarfile.open(archive) as tar:
            self.assertFalse(any('UNTRACKED-PRIVATE' in n for n in tar.getnames()))
            tar.extractall(self.base / 'extracted', filter='data')
        extracted = self.base / 'extracted' / ('CopyQ-Secure-Sync-' + d.version(self.source))
        for name, expected in (('plugin', self.commit), ('copyq', self.copyq_commit), ('zlib', self.zlib_commit)):
            self.assertEqual(r.git(extracted / name, 'rev-parse', 'HEAD'), expected)
            self.assertEqual(r.git(extracted / name, 'remote'), '')
        (out / 'RELEASE-NOTES.md').write_text('tampered')
        with self.assertRaises(ValueError): r.verify_bundle(out, self.source, self.proof)

    def test_missing_platform_refuses_assembly_without_partial_release(self):
        self.reports();self.package()
        out = self.base / 'release'
        with self.assertRaises(ValueError): r.assemble(self.source, self.artifacts, out, self.proof, self.copyq, self.zlib)
        self.assertFalse(list(out.iterdir()))


class ReleaseCIIdentityTests(unittest.TestCase):
    def setUp(self):
        self.sha = 'a' * 40
        self.run = {'id': 42, 'head_sha': self.sha, 'repository': {'full_name': 'example/repo'},
                    'head_repository': {'full_name': 'example/repo'}, 'head_branch': 'main', 'event': 'push',
                    'path': r.WORKFLOW, 'status': 'completed', 'conclusion': 'success'}
        self.jobs = [{'name': name, 'run_id': 42, 'status': 'completed', 'conclusion': 'success',
                      'steps': [{'conclusion': 'success'}]} for name in r.JOBS]

    def test_only_successful_current_main_native_ci_is_accepted(self):
        self.assertEqual(r.check_run(self.run, self.jobs, 'example/repo', self.sha), self.sha)
        for field, bad in (('event', 'pull_request'), ('head_sha', 'b' * 40), ('head_branch', 'feature'),
                           ('conclusion', 'failure'), ('status', 'in_progress'), ('path', '.github/workflows/release.yml')):
            data = {**self.run, field: bad}
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.check_run(data, self.jobs, 'example/repo', self.sha)
        with self.assertRaises(ValueError): r.check_run(self.run, self.jobs, 'other/repo', self.sha)

    def test_missing_skipped_failed_unstarted_or_duplicate_job_refused(self):
        for field, bad in (('conclusion', 'skipped'), ('conclusion', 'failure'), ('steps', []), ('run_id', 43)):
            data = copy.deepcopy(self.jobs);data[0][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                r.check_run(self.run, data, 'example/repo', self.sha)
        for jobs in (self.jobs[:-1], self.jobs[:-1] + [self.jobs[0]]):
            with self.assertRaises(ValueError): r.check_run(self.run, jobs, 'example/repo', self.sha)

    def test_prepare_defaults_to_no_publication_and_no_write_token(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('default: false', workflow)
        before, publishing = workflow.split('  publish:\n', 1)
        self.assertNotIn('contents: write', before)
        self.assertIn('if: ${{ inputs.publish }}', publishing)
        self.assertIn('environment: release', publishing)
        self.assertNotIn('pull_request_target', workflow)
        import re
        self.assertTrue(all(re.fullmatch(r'[0-9a-f]{40}', ref) for ref in re.findall(r'uses: [^@\s]+@([^\s]+)', workflow)))


if __name__ == '__main__':
    unittest.main()
