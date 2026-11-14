import verify_macos_deployment_provenance as verify_module
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from verify_macos_deployment_provenance import subjects,verification_command,verify,check_rejections,WORKFLOW,PROVENANCE_BUNDLE

COMMIT="a"*40
REF="refs/heads/main"
RUN_URI = "https://github.com/Yunushan/accessweaver/actions/runs/7/attempts/2\n"

class DeploymentProvenanceContracts(unittest.TestCase):
    def fixture(self,root):
        for name in set(subjects("amd64"))|{PROVENANCE_BUNDLE}:(root/name).write_bytes(b"not parsed before authentication")
    def test_known_subjects_and_source_workflow_are_independent_inputs(self):
        self.assertEqual(len(subjects("amd64")),18)
        command=verification_command(Path("p.pkg"),Path("bundle"),COMMIT,REF,"trusted-gh")
        for flag,value in {"--signer-workflow":WORKFLOW,"--repo":"Yunushan/accessweaver","--source-digest":COMMIT,"--signer-digest":COMMIT,"--source-ref":REF,"--cert-oidc-issuer":"https://token.actions.githubusercontent.com","--predicate-type":"https://slsa.dev/provenance/v1"}.items():self.assertEqual(command[command.index(flag)+1],value)
        self.assertIn("--deny-self-hosted-runners",command)
        with self.assertRaises(ValueError):subjects("x86")
    def test_every_subject_authenticates_before_parsing_in_a_private_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root);authenticated=[]
            def auth(path,bundle,commit,ref,gh,run_id):
                self.assertNotEqual(path.parent,root);self.assertEqual(bundle.parent,path.parent);authenticated.append(path.name)
            def parse(private,*args):
                self.assertEqual(set(authenticated),set(subjects("amd64")))
                name=next(n for n in subjects("amd64") if n.endswith(".pkg"));(root/name).write_bytes(b"changed outside snapshot")
                self.assertEqual((private/name).read_bytes(),b"not parsed before authentication")
                return {"mocked":True,"lifecycleRunID":"7"}
            with patch("verify_macos_deployment_provenance.authenticate",side_effect=auth),patch("verify_macos_deployment_provenance.validate_contents",side_effect=parse):result=verify(root,COMMIT,REF,"amd64","trusted-gh",run_id="7")
            self.assertEqual(result["subjectsVerified"],18);self.assertFalse(result["localTargetExecution"])
    def test_first_and_last_signature_failure_stop_before_parsing(self):
        for failed in (1,18):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);self.fixture(root);calls=[]
                def invoke(*args,**kwargs):
                    calls.append(args[0])
                    status = 1 if len(calls) == failed else 0
                    return subprocess.CompletedProcess(args[0], status, stdout=RUN_URI, stderr="private child error")
                with patch("verify_macos_deployment_provenance.subprocess.run",side_effect=invoke),patch("verify_macos_deployment_provenance.validate_contents") as contents:
                    with self.assertRaisesRegex(ValueError,"cryptographic"):verify(root,COMMIT,REF,"amd64","trusted-gh",run_id="7")
                    contents.assert_not_called();self.assertEqual(len(calls),failed)
    def test_a_subject_from_another_successful_run_refuses_before_parsing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            good = subprocess.CompletedProcess(["gh"], 0, stdout=RUN_URI)
            other = subprocess.CompletedProcess(["gh"], 0, stdout=RUN_URI.replace("/runs/7/", "/runs/8/"))
            with patch("verify_macos_deployment_provenance.subprocess.run", side_effect=[good] * 17 + [other]) as run, patch(
                "verify_macos_deployment_provenance.validate_contents"
            ) as parse, self.assertRaisesRegex(ValueError, "expected GitHub Actions run"):
                verify(root, COMMIT, REF, "amd64", run_id="7")
            self.assertEqual(run.call_count, 18)
            parse.assert_not_called()

    def test_missing_extra_linked_and_wrong_target_inputs_fail_closed(self):
        for kind in ("missing","extra","link","wrong-target"):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);self.fixture(root);name=next(n for n in subjects("amd64") if n.endswith(".pkg"))
                if kind=="missing":(root/name).unlink()
                elif kind=="extra":(root/"unexpected").write_bytes(b"extra")
                elif kind=="link":
                    target=root/"outside";target.write_bytes((root/name).read_bytes());(root/name).unlink();(root/name).hardlink_to(target)
                with patch("verify_macos_deployment_provenance.authenticate") as auth:
                    with self.assertRaises(ValueError):verify(root,COMMIT,REF,"arm64" if kind=="wrong-target" else "amd64","trusted-gh",run_id="7")
                    auth.assert_not_called()
    def test_caller_run_identity_is_checked_after_all_subject_authentication(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root)
            with patch("verify_macos_deployment_provenance.authenticate") as auth,patch("verify_macos_deployment_provenance.validate_contents",return_value={"lifecycleRunID":"7"}):
                with self.assertRaisesRegex(ValueError,"native run"):verify(root,COMMIT,REF,"amd64","trusted-gh",run_id="8")
                self.assertEqual(auth.call_count,18)
    def test_real_rejection_protocol_brackets_all_five_changed_choices(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/"p.pkg";path.write_bytes(b"candidate");calls=[]
            def invoke(command,**kwargs):
                calls.append(command)
                if len(calls)==6:self.assertEqual(Path(command[3]).read_bytes(),b"candidatechanged")
                return subprocess.CompletedProcess(command,0 if len(calls) in (1,7) else 1)
            with patch("verify_macos_deployment_provenance.subprocess.run",side_effect=invoke):result=check_rejections(path,root/PROVENANCE_BUNDLE,COMMIT,REF,"trusted-gh")
            self.assertEqual(calls[0],calls[-1]);self.assertEqual(len(result["rejected"]),5)

class ManagedDetectionProvenanceTests(unittest.TestCase):
    def test_requires_fixed_cases_and_matching_package_helper(self):
        old, new = verify_module.VERSIONS
        bindings = {old: {"helperSHA256": "a" * 64}, new: {"helperSHA256": "b" * 64}}
        cases = [
            dict(name=name, version=version, detected=detected, elevated=elevated,
                 statePreserved=True, helperSHA256=bindings[version]["helperSHA256"])
            for name, version, detected, elevated in (
                ("absent", old, False, False), ("initial-active", old, True, False),
                ("descriptor-hint", old, False, False), ("superseded", old, False, False),
                ("upgraded-active", new, True, True), ("reinstalled-active", new, True, False),
                ("changed-active", new, False, False), ("restored-active", new, True, False),
                ("inactive", new, False, False),
            )
        ]
        self.assertEqual(verify_module.validate_managed_detection(cases, bindings), {"managedDetectionChecksVerified": 9})
        busy = {**cases[1], "name": "writer-lease-held", "detected": False}
        released = {**cases[1], "name": "writer-lease-released"}
        with_writer = [*cases[:2], busy, released, *cases[2:]]
        self.assertEqual(verify_module.validate_managed_detection(with_writer, bindings, writer_lease_required=True),
                         {"managedDetectionChecksVerified": 11})
        for invalid in (
            cases, [*cases[:2], released, busy, *cases[2:]],
            [*cases[:2], {**busy, "detected": True}, released, *cases[2:]],
            [*cases[:2], busy, {**released, "detected": False}, *cases[2:]],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                verify_module.validate_managed_detection(invalid, bindings, writer_lease_required=True)
        for invalid in (
            cases[:-1],
            cases[::-1],
            [dict(cases[0], helperSHA256=bindings[new]["helperSHA256"]), *cases[1:]],
            [dict(cases[0], detected=0), *cases[1:]],
            [dict(cases[0], statePreserved=False), *cases[1:]],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                verify_module.validate_managed_detection(invalid, bindings)


if __name__=="__main__":unittest.main()
