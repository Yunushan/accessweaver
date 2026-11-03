#!/usr/bin/env python3
"""Hosted-only, read-only discovery of the original authenticated Windows CLI.

Raw inventory, result JSON, workflow logs and temporary paths stay in the owned
capsule. Only fixed checks, build/digest identity and allowlisted timings leave it.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from stage_packaged_native import host_target
from verify_release_provenance import validate_identity, REPOSITORY, WORKFLOW

DEADLINE_SECONDS = 45
MAX_OUTPUT = 1 << 20
ENGINES = {'byedpi', 'proxifyre', 'wgcf', 'zapret', 'zapret2', 'goodbyedpi', 'dnscrypt', 'drover'}
APPS = {'discord', 'discord-ptb', 'splitcord'}
WORKFLOW_PHASES = 'storage-ready script-ready request-ready environment-ready launch first-output child-exited shell-input shell-parse shell-initialize shell-utility-ready shell-management-ready shell-request-decoded shell-network-ready shell-root-ready shell-state-ready shell-catalog-ready shell-dispatch'.split()
DISCOVERY_PHASES = 'services components applications conflicts refresh-task final-paths complete'.split()
TASK_PHASES = 'start started capture-ready exited timed-out drained cleanup tree-helper-returned disposed'.split()
TIMING = re.compile(r'^(Workflow timing ms: ('+'|'.join(WORKFLOW_PHASES)+r')|Discovery timing ms: ('+'|'.join(DISCOVERY_PHASES)+r')|Task query timing ms: ('+'|'.join(TASK_PHASES)+r')) [0-9]{1,12}$')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def strict_json(data):
    def pairs(items):
        result = dict(items)
        require(len(result) == len(items), 'Duplicate JSON fields')
        return result
    return json.loads(data, object_pairs_hook=pairs)


def regular_bytes(path, limit):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink() and before.st_nlink == 1
            and not getattr(before, 'st_file_attributes', 0) & 0x400
            and 0 < before.st_size <= limit, 'Expected a bounded regular single-link file')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    after = path.lstat()
    require(len(data) == before.st_size <= limit and (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) ==
            (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns), 'Acceptance input changed while reading')
    return data


def validate_context(env):
    require(env.get('ACCESSWEAVER_DISPOSABLE_WINDOWS_DISCOVERY_TEST') == '1'
            and env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            'Discovery requires explicit hosted disposable-runner opt-in')
    commit, ref = env.get('GITHUB_SHA', ''), env.get('GITHUB_REF', '')
    validate_identity(commit, ref)
    target = ('windows', env.get('ACCESSWEAVER_EXPECT_GOARCH'))
    require(env.get('ACCESSWEAVER_EXPECT_GOOS') == 'windows' and target[1] in ('amd64', 'arm64')
            and host_target() == target, 'Discovery requires the matching native Windows host')
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', env.get('GO_VERSION', '')) is not None,
            'Discovery requires the independently pinned compiler')
    return commit, ref, target


def validate_receipt(receipt, env):
    commit, ref, target = validate_context(env)
    require(type(receipt.get('schemaVersion')) is int and receipt['schemaVersion'] == 1
            and receipt.get('sourceCommit') == commit and receipt.get('sourceRef') == ref
            and receipt.get('repository') == REPOSITORY and receipt.get('workflow') == WORKFLOW
            and receipt.get('target') == '/'.join(target) and receipt.get('binary') == 'accessweaver.exe'
            and receipt.get('authenticatedBeforeStaging') is True
            and type(receipt.get('provenanceSubjectsVerified')) is int and receipt['provenanceSubjectsVerified'] == 12,
            'Discovery receipt does not match authenticated native staging')
    for key in ('binarySha256', 'archiveSha256', 'manifestSha256', 'bundleSha256'):
        require(re.fullmatch(r'[a-f0-9]{64}', str(receipt.get(key, ''))) is not None, 'Missing authenticated input digest')
    build = receipt.get('build')
    require(isinstance(build, dict) and set(build) == {'version', 'commit', 'sourceState', 'builtAt', 'goVersion', 'platform', 'arch'}
            and all(isinstance(value, str) and value for value in build.values())
            and build['commit'] == commit and build['sourceState'] == 'clean' and build['platform'] == target[0]
            and build['arch'] == target[1] and build['goVersion'] == 'go'+env['GO_VERSION'], 'Discovery build identity mismatch')


def validate_job(job):
    require(isinstance(job, dict) and job.get('action') == 'discover' and job.get('state') == 'succeeded'
            and not job.get('error') and re.fullmatch(r'[a-f0-9]{48}', str(job.get('id', ''))) is not None,
            'Packaged discovery did not finish successfully')
    result = job.get('result')
    require(isinstance(result, dict) and result.get('ok') is True and result.get('rebootRequired') is False
            and result.get('journal') is None and result.get('events') == [], 'Read-only discovery changed workflow state')
    data = result.get('data')
    require(isinstance(data, dict) and set(data) == {'services', 'serviceInspectionError', 'components', 'applications',
            'wiresockCLI', 'conflicts', 'managedRoot', 'refreshTask', 'refreshTaskInspectionError', 'dnsSnapshot'},
            'Discovery result omitted or added inventory fields')
    nullable_text = lambda value: value is None or isinstance(value, str)
    require(isinstance(data['services'], list) and all(isinstance(item, dict) and set(item) == {'name', 'status', 'owned'}
            and isinstance(item['name'], str) and isinstance(item['status'], str) and type(item['owned']) is bool
            for item in data['services']), 'Invalid complete service inventory')
    for key, names in (('components', ENGINES), ('applications', APPS)):
        require(isinstance(data[key], dict) and set(data[key]) == names and all(nullable_text(value) for value in data[key].values()),
                'Invalid complete component or application inventory')
    require(nullable_text(data['serviceInspectionError']) and nullable_text(data['wiresockCLI'])
            and isinstance(data['managedRoot'], str) and bool(data['managedRoot'])
            and isinstance(data['conflicts'], list) and all(isinstance(value, str) for value in data['conflicts'])
            and type(data['dnsSnapshot']) is bool, 'Invalid discovery inventory types')
    require((type(data['refreshTask']) is bool or data['refreshTask'] is None)
            and nullable_text(data['refreshTaskInspectionError'])
            and ((data['refreshTask'] is None) == bool(data['refreshTaskInspectionError'])),
            'Unknown task state was confused with a known result')
    return job['id']


def public_phases(raw):
    return [line.strip() for line in raw.decode('utf-8', errors='replace').splitlines() if TIMING.fullmatch(line.strip())][:128]


def system_directory():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    function = kernel.GetSystemDirectoryW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    function.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = function(buffer, len(buffer))
    require(0 < length < len(buffer), 'Cannot resolve the trusted Windows utility directory')
    return Path(buffer.value)


def stop_owned(child):
    if child.poll() is not None:
        return
    try:
        child.send_signal(signal.CTRL_BREAK_EVENT)
        child.wait(timeout=8)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    confirmed = False
    try:
        helper = subprocess.run([str(system_directory() / 'taskkill.exe'), '/PID', str(child.pid), '/T', '/F'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=5, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
        confirmed = helper.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        pass
    finally:
        if child.poll() is None:
            child.kill()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Owned CLI cleanup could not be confirmed') from None
    require(confirmed, 'Owned CLI tree cleanup could not be confirmed')


def run_cli(binary, arguments, env, capsule, label, timeout):
    output, errors = capsule / (label+'.stdout'), capsule / (label+'.stderr')
    child = None
    started = time.monotonic()
    try:
        with output.open('xb') as stdout, errors.open('xb') as stderr:
            child = subprocess.Popen([str(binary), *arguments], env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            while child.poll() is None:
                require(time.monotonic() - started < timeout, 'Packaged CLI exceeded its execution deadline')
                require(os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size <= MAX_OUTPUT,
                        'Packaged CLI output exceeded its capture bound')
                time.sleep(0.02)
            require(child.returncode == 0, 'Packaged CLI returned failure')
        require(output.stat().st_size + errors.stat().st_size <= MAX_OUTPUT, 'Packaged CLI output exceeded its capture bound')
        elapsed = int((time.monotonic() - started) * 1000)
        require(elapsed <= timeout * 1000, 'Packaged CLI exceeded its execution deadline')
        return strict_json(regular_bytes(output, MAX_OUTPUT)), elapsed
    finally:
        if child is not None:
            stop_owned(child)


def cleanup_capsule(capsule, temporary_root):
    require(capsule.parent == temporary_root and capsule.name.startswith('accessweaver-packaged-discovery-')
            and not capsule.is_symlink() and capsule.resolve() == capsule,
            'Refusing to remove a replaced or unexpected discovery capsule')
    shutil.rmtree(capsule)
    require(not capsule.exists(), 'Owned discovery capsule was not removed')


def probe(staged, report_dir=Path('build/packaged-native-checks')):
    env = dict(os.environ)
    commit, ref, target = validate_context(env)  # Fail before any executable, directory creation or log export.
    require(staged.is_dir() and not staged.is_symlink(), 'Expected the privately staged candidate directory')
    receipt = strict_json(regular_bytes(staged / 'candidate.json', 64 << 10))
    validate_receipt(receipt, env)
    binary = (staged / 'accessweaver.exe').absolute()
    digest = lambda: hashlib.sha256(regular_bytes(binary, 64 << 20)).hexdigest()
    require(digest() == receipt['binarySha256'], 'Original archived CLI digest mismatch')
    temporary_root = Path(tempfile.gettempdir()).resolve()
    capsule = Path(tempfile.mkdtemp(prefix='accessweaver-packaged-discovery-', dir=temporary_root)).resolve()
    child_env = {key: value for key, value in env.items() if key.upper() not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    child_env['ACCESSWEAVER_HOME'] = str(capsule / 'state')
    try:
        build, _ = run_cli(binary, ['version', '--json'], child_env, capsule, 'identity', 30)
        require(build == receipt['build'], 'Executed CLI identity differs from its authenticated archive')
        job, elapsed = run_cli(binary, ['system', 'discover'], child_env, capsule, 'discovery', DEADLINE_SECONDS)
        identifier = validate_job(job)
        phases = public_phases(regular_bytes(capsule / 'state' / 'workflows' / identifier / 'process.log', 64 << 10))
        for phase in ('shell-dispatch', 'child-exited'):
            require(any(line.startswith('Workflow timing ms: '+phase+' ') for line in phases), 'Missing bounded workflow timing')
        require(any(line.startswith('Discovery timing ms: complete ') for line in phases), 'Discovery never reached complete inventory')
        require(digest() == receipt['binarySha256'], 'Archived CLI changed during discovery')
    finally:
        cleanup_capsule(capsule, temporary_root)
    report = {key: receipt[key] for key in ('sourceCommit', 'sourceRef', 'target', 'binarySha256', 'archiveSha256', 'manifestSha256', 'bundleSha256', 'build')}
    report.update(schemaVersion=1, probeElapsedMilliseconds=elapsed, deadlineMilliseconds=DEADLINE_SECONDS*1000,
                  phases=phases, originalArchiveExecuted=True, readOnlyActionVerified=True, fullDiscoveryShapeVerified=True,
                  ownedProcessStopped=True, ownedCapsuleRemoved=True,
                  serviceInspectionSucceeded=job['result']['data']['serviceInspectionError'] is None,
                  taskInspectionSucceeded=type(job['result']['data']['refreshTask']) is bool and job['result']['data']['refreshTaskInspectionError'] is None,
                  settingsChanged=False, productionQualificationComplete=False)
    require(not report_dir.is_symlink(), 'Unexpected discovery report directory')
    report_dir.mkdir(parents=True, exist_ok=True)
    with (report_dir / ('discovery-windows-'+target[1]+'.json')).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('staged', type=Path)
    args = parser.parse_args()
    try:
        report = probe(args.staged)
        require(report['serviceInspectionSucceeded'] and report['taskInspectionSucceeded'], 'Packaged discovery retained an unknown service or task inspection')
        print(json.dumps(report))
    except Exception as error:
        # Never echo child stdout/stderr, inventory values or temporary paths.
        print('Packaged Windows discovery failed: '+(str(error) if type(error) is RuntimeError else type(error).__name__), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
