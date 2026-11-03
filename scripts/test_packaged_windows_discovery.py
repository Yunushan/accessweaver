import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import packaged_windows_discovery as probe

COMMIT = 'a'*40
BUILD = dict(version='0.1.0-alpha', commit=COMMIT, sourceState='clean', builtAt='2026-11-03T00:00:00Z',
             goVersion='go1.27.3', platform='windows', arch='arm64')
ENV = dict(ACCESSWEAVER_DISPOSABLE_WINDOWS_DISCOVERY_TEST='1', GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
           GITHUB_SHA=COMMIT, GITHUB_REF='refs/heads/main', ACCESSWEAVER_EXPECT_GOOS='windows', ACCESSWEAVER_EXPECT_GOARCH='arm64', GO_VERSION='1.27.3')


def job():
    return dict(id='b'*48, action='discover', state='succeeded', result=dict(ok=True, rebootRequired=False, journal=None, events=[], data=dict(
        services=[dict(name='PRIVATE_SERVICE', status='Running', owned=False)], serviceInspectionError=None,
        components={name: 'PRIVATE_COMPONENT' for name in probe.ENGINES}, applications={name: 'PRIVATE_APPLICATION' for name in probe.APPS},
        wiresockCLI='PRIVATE_BINARY', conflicts=['PRIVATE_CONFLICT'], managedRoot='PRIVATE_ROOT', refreshTask=False,
        refreshTaskInspectionError=None, dnsSnapshot=False)))


class DiscoveryTests(unittest.TestCase):
    def test_context_refuses_every_missing_guard_before_execution(self):
        for key in ENV:
            with self.subTest(key=key), patch.dict(os.environ, {k: v for k, v in ENV.items() if k != key}, clear=True), \
                 patch.object(probe, 'host_target', return_value=('windows', 'arm64')), patch.object(probe.subprocess, 'Popen') as run:
                with self.assertRaises((ValueError, RuntimeError)):
                    probe.probe(Path('must-not-read'))
                run.assert_not_called()
        for target in [('linux', 'arm64'), ('windows', 'amd64'), ('darwin', 'arm64')]:
            with patch.dict(os.environ, ENV, clear=True), patch.object(probe, 'host_target', return_value=target), patch.object(probe.subprocess, 'Popen') as run:
                with self.assertRaises(RuntimeError):
                    probe.probe(Path('must-not-read'))
                run.assert_not_called()

    def receipt(self):
        return dict(schemaVersion=1, sourceCommit=COMMIT, sourceRef=ENV['GITHUB_REF'], target='windows/arm64',
                    repository=probe.REPOSITORY, workflow=probe.WORKFLOW, binary='accessweaver.exe',
                    authenticatedBeforeStaging=True, provenanceSubjectsVerified=12, build=copy.deepcopy(BUILD),
                    **{key: 'd'*64 for key in ('binarySha256', 'archiveSha256', 'manifestSha256', 'bundleSha256')})

    def test_receipt_requires_native_authenticated_identity(self):
        with patch.object(probe, 'host_target', return_value=('windows', 'arm64')):
            probe.validate_receipt(self.receipt(), ENV)
            for key, value in dict(schemaVersion=True, sourceCommit='c'*40, sourceRef='refs/tags/v1', target='windows/amd64',
                                   repository='other/repo', workflow='other/workflow', binary='../other.exe', authenticatedBeforeStaging=False,
                                   provenanceSubjectsVerified=True, binarySha256='invalid', archiveSha256='', manifestSha256=None, bundleSha256='g'*64).items():
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    probe.validate_receipt({**self.receipt(), key: value}, ENV)
            for key in BUILD:
                receipt = self.receipt()
                receipt['build'][key] = '' if key in ('version', 'builtAt') else 'changed'
                with self.subTest(build=key), self.assertRaises(RuntimeError):
                    probe.validate_receipt(receipt, ENV)

    def test_complete_inventory_and_explicit_unknown_task_semantics(self):
        self.assertEqual(probe.validate_job(job()), 'b'*48)
        for key in job()['result']['data']:
            incomplete = job()
            del incomplete['result']['data'][key]
            with self.subTest(missing=key), self.assertRaises(RuntimeError):
                probe.validate_job(incomplete)
        for key, value in dict(services=[dict(name='x', status='Running', owned=1)], components={}, applications={}, conflicts='private',
                               managedRoot=None, dnsSnapshot=0, refreshTask=0, refreshTaskInspectionError='failed').items():
            invalid = job()
            invalid['result']['data'][key] = value
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                probe.validate_job(invalid)
        unknown = job()
        unknown['result']['data'].update(refreshTask=None, refreshTaskInspectionError='PRIVATE_QUERY_ERROR')
        probe.validate_job(unknown)
        unknown['result']['data']['refreshTaskInspectionError'] = None
        with self.assertRaises(RuntimeError):
            probe.validate_job(unknown)
        for key, value in [('id', '../escape'), ('state', 'failed'), ('action', 'install'), ('error', 'private')]:
            with self.assertRaises(RuntimeError):
                probe.validate_job({**job(), key: value})
        for key, value in [('events', ['changed']), ('journal', 'private'), ('rebootRequired', True), ('ok', False)]:
            invalid = job()
            invalid['result'][key] = value
            with self.assertRaises(RuntimeError):
                probe.validate_job(invalid)

    def test_public_timings_exclude_private_unknown_and_unbounded_values(self):
        raw = b'PRIVATE\nWorkflow timing ms: shell-management-ready 10\nTask query timing ms: disposed 25\nWorkflow timing ms: PRIVATE 1\nDiscovery timing ms: complete 1234567890123\nDiscovery timing ms: complete 40\n'
        expected = ['Workflow timing ms: shell-management-ready 10', 'Task query timing ms: disposed 25', 'Discovery timing ms: complete 40']
        self.assertEqual(probe.public_phases(raw), expected)
        self.assertEqual(len(probe.public_phases(raw*100)), 128)

    def test_full_probe_exports_only_identity_fixed_checks_and_timings(self):
        with tempfile.TemporaryDirectory() as folder:
            staged = Path(folder) / 'staged'; staged.mkdir()
            binary = staged / 'accessweaver.exe'; binary.write_bytes(b'NOT EXECUTED: archived fixture bytes')
            receipt = self.receipt(); receipt['binarySha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            (staged / 'candidate.json').write_text(json.dumps(receipt), encoding='utf-8')
            output = Path(folder) / 'reports'
            capsules = []
            def fake_process(args, **kwargs):
                self.assertNotIn('GH_TOKEN', kwargs['env']); self.assertNotIn('GITHUB_TOKEN', kwargs['env'])
                self.assertEqual(args[0], str(binary.absolute()))
                if args[1:] == ['version', '--json']:
                    payload = BUILD
                else:
                    self.assertEqual(args[1:], ['system', 'discover'])
                    payload = job()
                    state = Path(kwargs['env']['ACCESSWEAVER_HOME']); capsules.append(state.parent)
                    logs = state / 'workflows' / payload['id']; logs.mkdir(parents=True)
                    (logs / 'process.log').write_bytes(b'PRIVATE_LOG\nWorkflow timing ms: shell-dispatch 15\nDiscovery timing ms: complete 30\nWorkflow timing ms: child-exited 60\n')
                kwargs['stdout'].write(json.dumps(payload).encode()); kwargs['stdout'].flush()
                return Mock(returncode=0, poll=Mock(return_value=0))
            with patch.dict(os.environ, {**ENV, 'GH_TOKEN': 'PRIVATE_TOKEN', 'GITHUB_TOKEN': 'PRIVATE_TOKEN'}, clear=True), \
                 patch.object(probe, 'host_target', return_value=('windows', 'arm64')), \
                 patch.object(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x200, create=True), patch.object(subprocess, 'Popen', side_effect=fake_process):
                report = probe.probe(staged, output)
            self.assertTrue(report['fullDiscoveryShapeVerified']); self.assertTrue(report['originalArchiveExecuted'])
            self.assertFalse(report['productionQualificationComplete']); self.assertEqual(report['deadlineMilliseconds'], 45000)
            encoded = (output / 'discovery-windows-arm64.json').read_text()
            self.assertNotIn('PRIVATE', encoded); self.assertNotIn(str(folder), encoded)
            self.assertTrue(all(not capsule.exists() for capsule in capsules))
            self.assertEqual(report['binarySha256'], receipt['binarySha256'])

    def test_timeout_cleanup_uses_bounded_trusted_helper_and_keeps_failure(self):
        child = Mock(pid=1234, poll=Mock(return_value=None))
        child.send_signal.side_effect = OSError()
        child.wait.return_value = 0
        with patch.object(signal := probe.signal, 'CTRL_BREAK_EVENT', 1, create=True), \
             patch.object(subprocess, 'CREATE_NO_WINDOW', 0x8000000, create=True), \
             patch.object(probe, 'system_directory', return_value=Path('trusted-system')), \
             patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired('helper', 5)) as helper:
            with self.assertRaisesRegex(RuntimeError, 'tree cleanup'):
                probe.stop_owned(child)
            child.kill.assert_called_once()
            self.assertEqual(helper.call_args.args[0], ['trusted-system/taskkill.exe' if os.name != 'nt' else 'trusted-system\\taskkill.exe', '/PID', '1234', '/T', '/F'])
            self.assertEqual(helper.call_args.kwargs['timeout'], 5)
            self.assertEqual(child.wait.call_args.kwargs['timeout'], 2)

    def test_cli_deadline_and_output_overflow_always_clean_the_owned_child(self):
        for overflow in (False, True):
            with self.subTest(overflow=overflow), tempfile.TemporaryDirectory() as folder:
                child = Mock(poll=Mock(return_value=None))
                def create(*args, **kwargs):
                    if overflow:
                        kwargs['stdout'].write(b'x'*(probe.MAX_OUTPUT+1)); kwargs['stdout'].flush()
                    return child
                with patch.object(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x200, create=True), \
                     patch.object(subprocess, 'Popen', side_effect=create), patch.object(probe, 'stop_owned') as cleanup, \
                     patch.object(probe.time, 'sleep'), patch.object(probe.time, 'monotonic', side_effect=[0, 0, 46]):
                    with self.assertRaisesRegex(RuntimeError, 'capture bound' if overflow else 'execution deadline'):
                        probe.run_cli(Path('not-executed.exe'), ['system', 'discover'], {}, Path(folder), 'fixture', 45)
                    cleanup.assert_called_once_with(child)

    def test_duplicate_and_changed_inputs_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            probe.strict_json('{"ok":true,"ok":false}')
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / 'input'; file.write_bytes(b'original')
            self.assertEqual(probe.regular_bytes(file, 8), b'original')
            with self.assertRaises(RuntimeError):
                probe.regular_bytes(file, 7)
            with self.assertRaises(RuntimeError):
                probe.regular_bytes(Path(folder), 128)


if __name__ == '__main__':
    unittest.main()
