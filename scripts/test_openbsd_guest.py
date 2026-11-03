import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

_spec = importlib.util.spec_from_file_location("openbsd_probe", Path(__file__).with_name("test-openbsd-guest.py"))
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)
PUBLIC = "ssh-ed25519 " + base64.b64encode(b"x" * 51).decode() + " aw-fixture"


class OpenBSDGuardTests(unittest.TestCase):
    def test_no_opt_in_cannot_reach_host_commands(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(probe.common, "guard") as host:
            with self.assertRaises(RuntimeError):
                probe.guard()
            host.assert_not_called()

    def test_openbsd_opt_in_retains_the_existing_host_and_source_guard(self):
        with patch.dict(os.environ, {"ACCESSWEAVER_DISPOSABLE_OPENBSD_GUEST_TEST": "1"}), patch.object(probe.common, "guard", side_effect=RuntimeError("host refused")) as host:
            with self.assertRaisesRegex(RuntimeError, "host refused"):
                probe.guard()
            host.assert_called_once()

    def test_target_is_explicit_and_architecture_is_preserved(self):
        for arch in ("amd64", "arm64"):
            base = probe.common.selected_target(arch)
            with self.subTest(arch=arch), patch.dict(os.environ, {"ACCESSWEAVER_DISPOSABLE_OPENBSD_GUEST_TEST": "1"}), patch.object(probe.common, "guard", return_value=(Path('/repo'), 'a'*40, {'GOHOSTARCH': arch}, base)):
                _, source, sdk, target = probe.guard()
            self.assertEqual(target['goos'], 'openbsd')
            self.assertEqual(target['arch'], arch)
            self.assertEqual(target['label'], 'openbsd-'+arch)
            self.assertEqual(target['imageSHA256'], probe.MEDIA[arch][0])
            self.assertTrue(target['imageURL'].endswith('/'+arch+'/install80.iso'))

    def test_guest_identity_rejects_wrong_os_release_arch_root_and_user(self):
        correct = ['OpenBSD', '8.0', 'amd64', '1000', 'awtest']
        self.assertEqual(probe.validate_identity(correct, 'amd64')['uid'], 1000)
        for index, value in ((0,'FreeBSD'), (1,'7.9'), (2,'arm64'), (3,'0'), (4,'root')):
            wrong = correct.copy();wrong[index]=value
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                probe.validate_identity(wrong,'amd64')
        with self.assertRaises(RuntimeError):
            probe.validate_identity(['OpenBSD','8.0','mips','1000','awtest'],'mips')


class InstallerInputTests(unittest.TestCase):
    def signed(self, arch='amd64', digest=None):
        key=base64.b64decode(probe.PUBLIC_KEY)
        signature=base64.b64encode(key[:10]+b'0'*64)
        payload=b'SHA256 (install80.iso) = '+(digest or probe.MEDIA[arch][0]).encode()+b'\n'
        return b'untrusted comment: fixture, NOT a signature\n'+signature+b'\n'+payload

    def test_signature_is_checked_before_digest_interpretation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(probe.common,'run',side_effect=RuntimeError('signature refused')) as run:
                with self.assertRaisesRegex(RuntimeError,'signature refused'):
                    probe.verify_manifest(self.signed(digest='f'*64),root,'amd64')
            command=run.call_args.args[0]
            self.assertEqual(command[:5],['openssl','pkeyutl','-verify','-rawin','-pubin'])
            self.assertEqual((root/'SHA256').read_bytes(),self.signed(digest='f'*64).split(b'\n',2)[2])

    def test_authenticated_checksum_must_match_reviewed_pin(self):
        for arch in ('amd64','arm64'):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as tmp, patch.object(probe.common,'run'):
                self.assertTrue(probe.verify_manifest(self.signed(arch),Path(tmp),arch)['installerMetadataSignatureVerified'])
            with tempfile.TemporaryDirectory() as tmp, patch.object(probe.common,'run'), self.assertRaises(ValueError):
                probe.verify_manifest(self.signed(arch,'f'*64),Path(tmp),arch)

    def test_unknown_signer_malformed_signature_and_oversize_fail_before_crypto(self):
        key=base64.b64decode(probe.PUBLIC_KEY)
        wrong=base64.b64encode(b'Ed'+b'Z'*8+b'0'*64)
        for data in (b'',b'x'*65537,b'not an envelope',b'untrusted comment: x\nNOT-BASE64\nabc',b'untrusted comment: x\n'+wrong+b'\nabc'):
            with self.subTest(size=len(data)), tempfile.TemporaryDirectory() as tmp, patch.object(probe.common,'run') as run:
                with self.assertRaises(ValueError):
                    probe.verify_manifest(data,Path(tmp),'amd64')
                run.assert_not_called()

    def test_private_bootstrap_has_no_permissive_signature_or_root_login_answer(self):
        for arch in ('amd64','arm64'):
            data=probe.response_file(arch,PUBLIC)
            self.assertIn('Which disk is the root disk = sd0\n',data)
            self.assertIn('Location of sets = cd0\n',data)
            self.assertIn('Allow root ssh login = no\n',data)
            self.assertIn('Password for root account = *************\n',data)
            self.assertNotIn('without verification',data)
            self.assertNotIn('Continue anyway',data)
            self.assertIn('Public ssh key for user awtest = '+PUBLIC,data)
        for invalid in ('private-data',PUBLIC+'\nAllow root ssh login = yes'):
            with self.assertRaises(ValueError):
                probe.response_file('amd64',invalid)
        script=probe.bootstrap_script()
        self.assertLess(script.index('/install -af'),script.index('ssh_host_ed25519_key'))
        self.assertIn('chroot /mnt /usr/sbin/sshd -t',script)
        self.assertLess(script.index('umount -af'),script.index('AW_OPENBSD_PRIVATE_BOOTSTRAP_COMPLETE'))

    def test_media_transform_retains_official_set_signature_and_private_seed(self):
        for arch in ('amd64','arm64'):
            with self.subTest(arch=arch),tempfile.TemporaryDirectory() as tmp:
                capsule=Path(tmp)
                (capsule/'host').write_bytes(b'PRIVATE_HOST_KEY_FIXTURE')
                (capsule/'host.pub').write_text(PUBLIC,encoding='ascii')
                target=dict(probe.common.selected_target(arch),imageURL='https://cdn.openbsd.org/pub/OpenBSD/8.0/'+arch+'/install80.iso',imageSHA256=probe.MEDIA[arch][0],imageBytes=probe.MEDIA[arch][1])
                events=[]
                def fetch(url,destination,maximum,expected=None):
                    if url.endswith('SHA256.sig'):
                        events.append('signed-metadata');destination.write_bytes(b'signature-fixture');return 17,'0'*64
                    events.append('image');self.assertEqual(expected,probe.MEDIA[arch][0]);destination.write_bytes(b'official-image');return probe.MEDIA[arch][1],expected
                def authenticate(*args):
                    events.append('authenticate');return {'installerMetadataSignatureVerified':True}
                def command(args,**kwargs):
                    if '-outdev' in args:
                        events.append('transform')
                        self.assertIn('/etc/boot.conf',args)
                        self.assertIn('/8.0/'+arch+'/SHA256.sig',args)
                        self.assertIn(['-boot_image','any','replay'],[args[i:i+3] for i in range(len(args)-2)])
                        Path(args[args.index('-outdev')+1]).write_bytes(b'prepared-image')
                    elif '-extract' in args:
                        (capsule/'inserted-signature').write_bytes((capsule/'SHA256.sig').read_bytes())
                        (capsule/'inserted-boot.conf').write_bytes((capsule/'boot.conf').read_bytes())
                    else:
                        Path(args[args.index('-o')+1]).write_bytes(b'private-seed-image')
                actual_digest=probe.common.digest
                def digest(path):
                    return probe.MEDIA[arch][0] if path.name=='official.iso' else actual_digest(path)
                with patch.object(probe,'download',side_effect=fetch),patch.object(probe,'verify_manifest',side_effect=authenticate),patch.object(probe.common,'run',side_effect=command),patch.object(probe.common,'digest',side_effect=digest):
                    installer,seed,observed=probe.prepare_media(capsule,target,PUBLIC)
                self.assertEqual(events[:4],['signed-metadata','authenticate','image','transform'])
                self.assertEqual((capsule/'official.iso').read_bytes(),b'official-image')
                self.assertEqual((capsule/'seed/host').read_bytes(),b'PRIVATE_HOST_KEY_FIXTURE')
                self.assertNotIn('PRIVATE_HOST_KEY_FIXTURE',json.dumps(observed))
                config=(capsule/'seed/sshd_config').read_text()
                self.assertIn('PermitRootLogin no',config)
                self.assertIn('PasswordAuthentication no',config)
                self.assertIn('AllowUsers awtest',config)

    def test_installer_seed_never_appears_in_installed_runtime(self):
        firmware={'code':Path('/private/code'),'variables':Path('/private/vars')}
        for arch in ('amd64','arm64'):
            target=probe.common.selected_target(arch)
            for acceleration in ('tcg','kvm'):
                install=probe.machine_command(target,Path('/private/root'),acceleration,firmware,Path('/private/installer'),Path('/private/seed'))
                runtime=probe.machine_command(target,Path('/private/root'),acceleration,firmware)
                for command in (install,runtime):
                    self.assertIn('user,id=n1,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22',command)
                    self.assertEqual(command[command.index('-monitor')+1],'none')
                    self.assertNotIn('-virtfs',command)
                    self.assertNotIn('-fsdev',command)
                self.assertTrue(any('file='+str(Path('/private/seed'))+',' in a for a in install))
                self.assertIn('virtio-blk-pci,drive=osdisk,bootindex=2',install)
                self.assertIn('scsi-cd,drive=installer,bus=scsi0.0,bootindex=1',install)
                self.assertIn('virtio-blk-pci,drive=osdisk,bootindex=1',runtime)
                self.assertFalse(any('cdrom' in a or 'installer' in a or 'seed' in a for a in runtime))
        with self.assertRaises(ValueError):
            probe.machine_command(target,Path('/private/root'),'tcg',firmware,Path('/private/installer'))

    def test_payload_cannot_mix_os_label_or_use_openbsd_packaged_fallback(self):
        for target,packaged in ((dict(probe.common.selected_target('amd64'),goos='openbsd'),None),
                                 (dict(probe.common.selected_target('amd64'),goos='openbsd',label='openbsd-amd64'),Path('/staged'))):
            with tempfile.TemporaryDirectory() as tmp,patch.object(probe.common,'run') as run:
                with self.assertRaises(ValueError):
                    probe.common.build_payload(Path(tmp),Path(tmp),'a'*40,target,packaged)
                run.assert_not_called()
                self.assertFalse((Path(tmp)/'payload').exists())


class SSHBootTests(unittest.TestCase):
    def test_probe_timeout_waits_on_the_same_live_process(self):
        process=Mock();process.poll.return_value=None
        report={}
        success=subprocess.CompletedProcess([],0,b'')
        with patch.object(probe.common,'run',side_effect=[TimeoutError('still booting'),success]) as run,patch.object(probe.time,'sleep'):
            probe.wait_for_ssh(['ssh'],process,report,timeout=10)
        self.assertEqual(run.call_count,2)
        self.assertEqual(report['bootProbeTimeouts'],1)

    def test_dead_process_wrong_host_key_and_deadline_refuse_execution(self):
        process=Mock();process.poll.return_value=0
        with patch.object(probe.common,'run') as run,self.assertRaises(RuntimeError):
            probe.wait_for_ssh(['ssh'],process,{},timeout=10)
        run.assert_not_called()
        process.poll.return_value=None
        result=subprocess.CompletedProcess([],255,b'Host key verification failed')
        with patch.object(probe.common,'run',return_value=result),self.assertRaisesRegex(RuntimeError,'host key'):
            probe.wait_for_ssh(['ssh'],process,{},timeout=10)
        with patch.object(probe.common,'run') as run,self.assertRaises(TimeoutError):
            probe.wait_for_ssh(['ssh'],process,{},timeout=0)
        run.assert_not_called()


@unittest.skipUnless(os.name=='posix','bounded serial subprocess pipes require POSIX')
class SerialTests(unittest.TestCase):
    def test_partial_prompt_is_observed_without_waiting_for_full_buffer(self):
        machine=probe.Console([sys.executable,'-c',"import sys,time;sys.stdout.write('PRIVATE_TEST_DATA PROMPT');sys.stdout.flush();time.sleep(30)"])
        try:
            machine.wait(b'PROMPT',2)
            observed=machine.observations()
            self.assertNotIn('PRIVATE_TEST_DATA',json.dumps(observed))
            with self.assertRaises(ValueError):
                machine.send(b'x'*1025)
        finally:
            self.assertTrue(machine.stop())
        self.assertTrue(machine.process.stdout.closed)
        self.assertTrue(machine.process.stdin.closed)

    def test_serial_reader_start_failure_reaps_the_child_and_closes_pipes(self):
        actual=probe.subprocess.Popen
        children=[]
        def create(*args,**kwargs):
            child=actual(*args,**kwargs);children.append(child);return child
        with patch.object(probe.subprocess,'Popen',side_effect=create),patch.object(probe.threading.Thread,'start',side_effect=RuntimeError('reader unavailable')):
            with self.assertRaisesRegex(RuntimeError,'reader unavailable'):
                probe.Console([sys.executable,'-c','import time;time.sleep(30)'])
        self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdin.closed)
        self.assertTrue(children[0].stdout.closed)

    def test_missing_prompt_has_a_deadline_and_owned_child_is_reaped(self):
        machine=probe.Console([sys.executable,'-c',"import time;time.sleep(30)"])
        try:
            with self.assertRaises(TimeoutError):
                machine.wait(b'UNREACHABLE',0.1)
        finally:
            self.assertTrue(machine.stop())
        self.assertIsNotNone(machine.process.returncode)


if __name__=='__main__':
    unittest.main()
