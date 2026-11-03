#!/usr/bin/env python3
"""Authenticate a reference release, then compare every unsigned rebuild subject.

This checks bytes, not who performed a rebuild. No candidate executable runs;
metadata differences are failures, and there is no integrity-only fallback.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

from verify_release import require
from verify_release_provenance import BUNDLE_NAME, REPOSITORY, WORKFLOW, validate_identity, verify as verify_provenance

MAX_FILE = 128 << 20
MAX_SET = 256 << 20


def snapshot(source, destination, count):
    directory = source.lstat()
    require(stat.S_ISDIR(directory.st_mode) and not source.is_symlink()
            and not getattr(directory, 'st_file_attributes', 0) & 0x400, 'Expected a real input directory')
    names = set()
    total = 0
    with os.scandir(source) as entries:
        for entry in entries:
            require(len(names) < count and entry.name not in names, 'Unexpected extra input')
            path = source / entry.name
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and not getattr(before, 'st_file_attributes', 0) & 0x400
                    and 0 < before.st_size <= MAX_FILE, 'Expected a bounded regular single-link input')
            total += before.st_size
            require(total <= MAX_SET, 'Input set exceeds snapshot bound')
            flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_nlink)
                require(stat.S_ISREG(opened.st_mode) and identity(opened) == identity(before), 'Input changed before snapshot')
                with (destination / entry.name).open('xb') as output:
                    copied = 0
                    while True:
                        block = os.read(descriptor, min(1 << 20, MAX_FILE + 1 - copied))
                        if not block:
                            break
                        copied += len(block)
                        require(copied <= before.st_size, 'Input changed or exceeded its snapshot bound')
                        output.write(block)
                require(copied == before.st_size and identity(os.fstat(descriptor)) == identity(before), 'Input changed during snapshot')
            finally:
                os.close(descriptor)
            names.add(entry.name)
    require(len(names) == count, 'Missing release inputs')
    return names


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def compare(reference, rebuilt, commit, ref, gh='gh'):
    validate_identity(commit, ref)
    with tempfile.TemporaryDirectory(prefix='accessweaver-rebuild-check-') as temporary:
        root = Path(temporary)
        authenticated = root / 'reference'; authenticated.mkdir(mode=0o700)
        reference_names = snapshot(reference, authenticated, 13)
        # No rebuild input or reference manifest is interpreted before real trust.
        verified = verify_provenance(authenticated, commit, ref, gh)
        require(verified.get('sourceCommit') == commit and verified.get('sourceRef') == ref
                and verified.get('repository') == REPOSITORY and verified.get('workflow') == WORKFLOW
                and verified.get('subjectsVerified') == 12 and verified.get('hostedRunnerRequired') is True,
                'Reference authentication did not prove the required identity and subject coverage')
        expected = reference_names - {BUNDLE_NAME}
        require(len(expected) == 12 and {'BUILD-MANIFEST.json', 'SHA256SUMS.txt'} <= expected, 'Unexpected authenticated subject set')
        frozen = root / 'rebuilt'; frozen.mkdir(mode=0o700)
        require(snapshot(rebuilt, frozen, 12) == expected, 'Rebuild subject names differ from the authenticated release')
        subjects = []
        for name in sorted(expected):
            reference_hash = digest(authenticated / name)
            rebuilt_hash = digest(frozen / name)
            subjects.append(dict(file=name, referenceSha256=reference_hash, rebuiltSha256=rebuilt_hash, identical=reference_hash == rebuilt_hash))
        return dict(schemaVersion=1, repository=REPOSITORY, workflow=WORKFLOW, sourceCommit=commit, sourceRef=ref,
                    referenceSubjectsAuthenticated=12, unsignedSubjectsCompared=12, coreArchivesCompared=10,
                    allUnsignedSubjectsByteIdentical=all(item['identical'] for item in subjects), subjects=subjects,
                    signingBundleCompared=False, rebuildProcessIndependenceVerified=False,
                    publisherSignatureVerified=False, productionQualificationComplete=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference', type=Path)
    parser.add_argument('rebuilt', type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--source-ref', required=True)
    parser.add_argument('--gh', default='gh', help='trusted GitHub CLI executable')
    parser.add_argument('--report', type=Path, help='new public report file; existing files are not replaced')
    args = parser.parse_args()
    try:
        result = compare(args.reference, args.rebuilt, args.source_commit, args.source_ref, args.gh)
        if args.report:
            with args.report.open('x', encoding='utf-8', newline='\n') as stream:
                json.dump(result, stream, indent=2)
                stream.write('\n')
        print(json.dumps(result))
        return 0 if result['allUnsignedSubjectsByteIdentical'] else 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print('Rebuild comparison failed: '+str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
