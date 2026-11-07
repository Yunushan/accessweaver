import copy
import json
import sys
import unittest

import fixture_qualification as q

class FixtureQualificationTests(unittest.TestCase):
    def peer(self):
        return {"passed": True, "tcpIPv4": True, "udpIPv4": True, "tcpIPv6": True, "udpIPv6": True,
                "peer": {"last_handshake_time_sec": "1000", "rx_bytes": "128", "tx_bytes": "256"}}

    def test_guest_guard_preserves_disposable_boundary(self):
        environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
        q.hosted_guest(environment, "linux", "x86_64", 1001)
        for key, value in [("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"), ("RUNNER_ARCH", "ARM64")]:
            altered = dict(environment)
            altered[key] = value
            with self.assertRaises(AssertionError):
                q.hosted_guest(altered, "linux", "x86_64", 1001)
        with self.assertRaises(AssertionError):
            q.hosted_guest(environment, "linux", "x86_64", 0)

    def test_peer_projection_requires_all_traffic_and_no_private_fields(self):
        projected = q.peer_result(self.peer(), 1000)
        self.assertEqual(projected, {"tcpIPv4": True, "udpIPv4": True, "tcpIPv6": True, "udpIPv6": True,
                                    "freshHandshake": True, "rxBytes": 128, "txBytes": 256})
        for mutate in [lambda p: p.update(privateKey="PRIVATE_SYNTHETIC"),
                       lambda p: p.update(tcpIPv6=False), lambda p: p.update(passed="true"),
                       lambda p: p["peer"].update(private_key="PRIVATE_SYNTHETIC"),
                       lambda p: p["peer"].update(rx_bytes="0"),
                       lambda p: p["peer"].update(tx_bytes="12\nPRIVATE_SYNTHETIC"),
                       lambda p: p["peer"].update(last_handshake_time_sec="1")]:
            altered = self.peer()
            mutate(altered)
            with self.assertRaises(AssertionError):
                q.peer_result(altered, 1000)
        self.assertNotIn("PRIVATE_SYNTHETIC", json.dumps(projected))

    def test_build_identity_drops_paths_and_binds_mode_target_and_dependency(self):
        source = "a" * 40
        raw = ("/PRIVATE_SYNTHETIC_PATH/wgpeer: go1.27.3\n\tpath\taccessweaver.test/wgpeer\n"
               "\tmod\taccessweaver.test/wgpeer\t(devel)\n\tdep\tgolang.org/x/crypto\t" + q.CRYPTO + "\t" + q.CRYPTO_SUM +
               "\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n\tbuild\tCGO_ENABLED=0\n"
               "\tbuild\tvcs.revision=" + source + "\n\tbuild\tvcs.modified=false\n").encode()
        result = q.decode_build_info(raw, "linux/amd64", False, source, "peer")
        self.assertNotIn("PRIVATE_SYNTHETIC", json.dumps(result))
        for altered in [raw.replace(b"CGO_ENABLED=0", b"CGO_ENABLED=1"),
                        raw.replace(b"GOARCH=amd64", b"GOARCH=arm64"),
                        raw.replace(q.CRYPTO.encode(), b"v0.58.0"),
                        raw.replace(b"vcs.modified=false", b"vcs.modified=true")]:
            with self.assertRaises(AssertionError):
                q.decode_build_info(altered, "linux/amd64", False, source, "peer")

    def report(self):
        def binary(role, target, race):
            return {"role": role, "target": target, "race": race, "go": "go1.27.3",
                    "format": "elf" if target.startswith("linux/") else "pe", "binarySHA256": "c" * 64}
        return {"schemaVersion": 1, "sourceCommit": "a" * 40, "sourceTree": "b" * 40,
                "sourceSHA256": {name: "c" * 64 for name in q.SOURCES}, "hostedGuestVerified": True,
                "go": "go1.27.3", "cryptoVersion": q.CRYPTO, "cryptoSum": q.CRYPTO_SUM,
                "openpgpExcluded": True, "sourceStable": True, "stage": "complete", "exitCode": 0,
                "failureKind": "none", "outcome": "passed", "productionQualificationComplete": False,
                "modes": [{"mode": mode, "binary": binary("peer", "linux/amd64", mode == "race"),
                           "checks": q.peer_result(self.peer(), 1000)} for mode in ["normal", "race"]],
                "windows": [binary(role, "windows/amd64", False) for role in ["peer", "probe"]],
                "advisories": [{"target": target, "scanner": "v1.9.0", "go": "go1.27.3",
                                "databaseModifiedAt": "2026-11-07T00:00:00Z", "affected": 0,
                                "moduleOnly": 0, "reportSHA256": "d" * 64} for target in ["linux/amd64", "windows/amd64"]]}

    def test_public_report_refuses_private_fields_and_incomplete_success(self):
        valid = self.report()
        encoded = q.public_report(valid)
        for mutate in [lambda p: p.update(private="PRIVATE_SYNTHETIC"),
                       lambda p: p["modes"][0]["checks"].update(private="PRIVATE_SYNTHETIC"),
                       lambda p: p["modes"].pop(), lambda p: p.update(sourceStable=False),
                       lambda p: p["advisories"][0].update(moduleOnly=1),
                       lambda p: p["windows"][0].update(role="probe"),
                       lambda p: p.update(productionQualificationComplete=True)]:
            changed = copy.deepcopy(valid)
            mutate(changed)
            with self.assertRaises(AssertionError):
                q.public_report(changed)
        self.assertNotIn("PRIVATE_SYNTHETIC", encoded)

    def test_owned_command_limits_and_timeout_do_not_publish_raw_output(self):
        with self.assertRaises(q.Failure) as over:
            q.command([sys.executable, "-c", "import sys;sys.stdout.write('PRIVATE_SYNTHETIC'*1024)"], None, None, limit=128)
        self.assertEqual(over.exception.kind, "output-budget")
        self.assertNotIn("PRIVATE_SYNTHETIC", str(over.exception))
        with self.assertRaises(q.Failure) as timeout:
            q.command([sys.executable, "-c", "import time;time.sleep(5)"], None, None, seconds=0.1)
        self.assertEqual(timeout.exception.kind, "timeout")

if __name__ == "__main__":
    unittest.main()
