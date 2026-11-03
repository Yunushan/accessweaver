import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_release_rebuild as rebuild

COMMIT = 'a'*40
REF = 'refs/heads/main'
VERIFIED = dict(repository=rebuild.REPOSITORY, workflow=rebuild.WORKFLOW, sourceCommit=COMMIT, sourceRef=REF,
                subjectsVerified=12, hostedRunnerRequired=True)


class RebuildTests(unittest.TestCase):
    def fixture(self, root):
        reference = root / 'reference'; reference.mkdir()
        rebuilt = root / 'rebuilt'; rebuilt.mkdir()
        for system in ('windows', 'linux', 'darwin', 'freebsd', 'openbsd'):
            for arch in ('amd64', 'arm64'):
                name = 'accessweaver-preview-'+system+'-'+arch+('.zip' if system == 'windows' else '.tar.gz')
                (reference / name).write_bytes(b'PRIVATE_FIXTURE_CONTENT: not an executable')
        (reference / 'BUILD-MANIFEST.json').write_text('{"packaging":{"pythonVersion":"3.12.3"}}', encoding='utf-8')
        (reference / 'SHA256SUMS.txt').write_bytes(b'fixture checksums')
        for file in reference.iterdir():
            (rebuilt / file.name).write_bytes(file.read_bytes())
        (reference / rebuild.BUNDLE_NAME).write_bytes(b'unit-only mocked signature; NOT real cryptographic evidence')
        return reference, rebuilt

    def test_complete_set_and_public_report_exclude_private_input(self):
        with tempfile.TemporaryDirectory(prefix='PRIVATE_PATH-') as folder:
            reference, candidate = self.fixture(Path(folder))
            with patch.object(rebuild, 'verify_provenance', return_value=VERIFIED) as verify:
                report = rebuild.compare(reference, candidate, COMMIT, REF, 'trusted-gh')
            self.assertTrue(report['allUnsignedSubjectsByteIdentical'])
            self.assertEqual(len(report['subjects']), 12)
            self.assertFalse(report['rebuildProcessIndependenceVerified'])
            self.assertFalse(report['productionQualificationComplete'])
            self.assertNotIn('PRIVATE', json.dumps(report))
            self.assertEqual(verify.call_args.args[1:], (COMMIT, REF, 'trusted-gh'))
            self.assertNotEqual(verify.call_args.args[0], reference)
            self.assertFalse(verify.call_args.args[0].exists(), 'owned snapshot was retained')

    def test_authentication_precedes_all_rebuild_reads(self):
        with tempfile.TemporaryDirectory() as folder:
            reference, candidate = self.fixture(Path(folder))
            with patch.object(rebuild, 'verify_provenance', side_effect=ValueError('signature rejected')), \
                 patch.object(rebuild, 'snapshot', wraps=rebuild.snapshot) as snapshot:
                with self.assertRaisesRegex(ValueError, 'signature rejected'):
                    rebuild.compare(reference, candidate / 'must-not-read', COMMIT, REF)
                self.assertEqual(snapshot.call_count, 1)

    def test_invalid_identity_and_partial_authentication_fail_before_rebuild_reads(self):
        with patch.object(rebuild, 'snapshot') as snapshot:
            with self.assertRaises(ValueError):
                rebuild.compare(Path('missing'), Path('missing'), 'short', REF)
            snapshot.assert_not_called()
        with tempfile.TemporaryDirectory() as folder:
            reference, candidate = self.fixture(Path(folder))
            for field, value in [('sourceCommit', 'b'*40), ('sourceRef', 'refs/tags/v1'), ('subjectsVerified', 11), ('hostedRunnerRequired', False)]:
                with patch.object(rebuild, 'verify_provenance', return_value={**VERIFIED, field: value}), \
                     patch.object(rebuild, 'snapshot', wraps=rebuild.snapshot) as snapshot:
                    with self.assertRaises(ValueError):
                        rebuild.compare(reference, candidate, COMMIT, REF)
                    self.assertEqual(snapshot.call_count, 1)

    def test_every_changed_subject_including_runtime_metadata_is_a_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            reference, candidate = self.fixture(Path(folder))
            for file in candidate.iterdir():
                original = file.read_bytes(); file.write_bytes(original+b'changed')
                try:
                    with patch.object(rebuild, 'verify_provenance', return_value=VERIFIED):
                        report = rebuild.compare(reference, candidate, COMMIT, REF)
                    self.assertFalse(report['allUnsignedSubjectsByteIdentical'], file.name)
                    self.assertEqual([item['file'] for item in report['subjects'] if not item['identical']], [file.name])
                finally:
                    file.write_bytes(original)

    def test_missing_extra_and_renamed_rebuild_files_fail_closed(self):
        for mode in ('missing', 'extra', 'rename'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                reference, candidate = self.fixture(Path(folder))
                file = candidate / 'SHA256SUMS.txt'
                if mode == 'missing':
                    file.unlink()
                elif mode == 'extra':
                    (candidate / 'unexpected').write_bytes(b'extra')
                else:
                    file.rename(candidate / 'renamed')
                with patch.object(rebuild, 'verify_provenance', return_value=VERIFIED), self.assertRaises(ValueError):
                    rebuild.compare(reference, candidate, COMMIT, REF)

    def test_links_and_non_regular_files_refused_before_authentication(self):
        for mode in ('hardlink', 'symlink', 'directory', 'fifo'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                reference, candidate = self.fixture(Path(folder))
                file = reference / 'SHA256SUMS.txt'; file.unlink()
                try:
                    if mode == 'hardlink': os.link(reference / 'BUILD-MANIFEST.json', file)
                    elif mode == 'symlink': file.symlink_to(reference / 'BUILD-MANIFEST.json')
                    elif mode == 'directory': file.mkdir()
                    elif hasattr(os, 'mkfifo'): os.mkfifo(file)
                    else: continue
                except (OSError, NotImplementedError):
                    continue
                with patch.object(rebuild, 'verify_provenance') as verify, self.assertRaises((ValueError, OSError)):
                    rebuild.compare(reference, candidate, COMMIT, REF)
                verify.assert_not_called()

    def test_changed_snapshot_read_and_set_bounds_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'source'; source.mkdir(); destination = root / 'out'; destination.mkdir()
            file = source / 'input'; file.write_bytes(b'original')
            original_read = os.read
            def changed_read(descriptor, count):
                data = original_read(descriptor, count)
                if data: file.write_bytes(b'changed-longer')
                return data
            with patch.object(os, 'read', side_effect=changed_read), self.assertRaises(ValueError):
                rebuild.snapshot(source, destination, 1)
        with tempfile.TemporaryDirectory() as folder:
            reference, candidate = self.fixture(Path(folder))
            with patch.object(rebuild, 'MAX_SET', 1), patch.object(rebuild, 'verify_provenance') as verify, self.assertRaises(ValueError):
                rebuild.compare(reference, candidate, COMMIT, REF)
            verify.assert_not_called()

    def test_cli_returns_nonzero_for_differences_and_never_claims_independence(self):
        report = dict(allUnsignedSubjectsByteIdentical=False, rebuildProcessIndependenceVerified=False, productionQualificationComplete=False)
        with patch('sys.argv', ['verify_release_rebuild.py', 'reference', 'rebuilt', '--source-commit', COMMIT, '--source-ref', REF]), \
             patch.object(rebuild, 'compare', return_value=report), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rebuild.main(), 1)


if __name__ == '__main__':
    unittest.main()
