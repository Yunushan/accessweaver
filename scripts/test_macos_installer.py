import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest

from macos_installer import BUNDLE_ID,bundle_manifest,bundle_plist,macho_identity,verify_bundle,version_parts
from sbom import macos_package,sha,validate
from macos_deployment import verify_deployment_bundle,detached_payload_manifest,PAYLOAD_SBOM

class MacPackageContracts(unittest.TestCase):
    def image(self,arch="amd64"):
        cpu={"amd64":0x1000007,"arm64":0x100000c}[arch]
        return struct.pack("<8I",0xfeedfacf,cpu,0,2,1,16,0,0)+struct.pack("<4I",0x24,16,0x000d0000,0)
    def test_release_versions_keep_full_identity_and_reject_bad_bundle_fields(self):
        for value in ("0.1.0-alpha","1.2.3+build.1","1.2.3-rc.2"):
            self.assertEqual(version_parts(value),value.split("-")[0].split("+")[0])
            self.assertEqual(bundle_plist(value,"13.0.0")["AccessWeaverReleaseVersion"],value)
        for value in ("v1.2.3","01.2.3","1.2.3-alpha.01","1.2.3+","1.100.0","10000.0.0","1.2",("1.2.3-"+"a"*251)):
            with self.assertRaises(ValueError):version_parts(value)
    def test_macho_target_extent_and_minimum_os_are_enforced(self):
        for arch in ("amd64","arm64"):
            self.assertEqual(macho_identity(self.image(arch),arch)["minimumOSVersion"],"13.0.0")
        for data in (b"x",self.image()[:40],struct.pack("<8I",0xfeedfacf,0x1000007,0,2,999,16,0,0)+self.image()[32:]):
            with self.assertRaises(ValueError):macho_identity(data,"amd64")
        with self.assertRaises(ValueError):macho_identity(self.image(),"arm64")
    @unittest.skipUnless(os.name=="posix","POSIX file-mode contract requires a native Unix filesystem")
    def test_bundle_changed_files_embedded_manifest_and_unexpected_objects_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            bundle=Path(folder)/"AccessWeaver.app";resources=bundle/"Contents/Resources";resources.mkdir(parents=True)
            binary=bundle/"Contents/MacOS/accessweaver";binary.parent.mkdir();binary.write_bytes(self.image());binary.chmod(0o755)
            identity={"version":"0.1.0-alpha","arch":"amd64"}
            (resources/"BUILD-INFO.json").write_text(json.dumps(identity),encoding="utf-8")
            with (bundle/"Contents/Info.plist").open("wb") as f:plistlib.dump(bundle_plist(identity["version"],"13.0.0"),f)
            for root,dirs,files in os.walk(bundle):
                os.chmod(root,0o755)
                for name in files:
                    if Path(root)/name!=binary:os.chmod(Path(root)/name,0o644)
            manifest=bundle_manifest(bundle);embedded=resources/"INSTALL-MANIFEST.json";embedded.write_text(json.dumps(manifest),encoding="utf-8");embedded.chmod(0o644)
            self.assertTrue(verify_bundle(bundle,manifest,identity))
            extra=dict(manifest,unexpected=True);embedded.write_text(json.dumps(extra),encoding="utf-8")
            with self.assertRaises(ValueError):verify_bundle(bundle,extra,identity)
            embedded.write_text(json.dumps(manifest),encoding="utf-8")
            (resources/"unexpected").mkdir()
            with self.assertRaises(ValueError):verify_bundle(bundle,manifest,identity)
            (resources/"unexpected").rmdir()
            embedded.write_text("{}",encoding="utf-8")
            with self.assertRaises(ValueError):verify_bundle(bundle,manifest,identity)
            embedded.write_text(json.dumps(manifest),encoding="utf-8")
            original=binary.read_bytes();binary.write_bytes(original+b"changed")
            with self.assertRaises(ValueError):verify_bundle(bundle,manifest,identity)
            binary.write_bytes(original)
            encoded=embedded.read_bytes();sidecar=Path(folder)/"INSTALL-MANIFEST.json";embedded.rename(sidecar)
            self.assertTrue(verify_deployment_bundle(bundle,manifest,identity,encoded))
            embedded.write_bytes(encoded)
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest,identity,encoded)
            embedded.unlink();sidecar.write_bytes(encoded+b" ")
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest,identity,encoded)
            sidecar.write_bytes(encoded);sidecar.chmod(0o600)
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest,identity,encoded)
            sidecar.chmod(0o644);alias=Path(folder)/"manifest-alias";alias.hardlink_to(sidecar)
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest,identity,encoded)
            alias.unlink();sidecar.rename(alias);sidecar.symlink_to(alias)
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest,identity,encoded)
            sidecar.unlink();alias.rename(sidecar)
            self.assertTrue(verify_deployment_bundle(bundle,manifest,identity,encoded))
            payload=Path(folder)/PAYLOAD_SBOM;payload.write_bytes(b"{}");payload.chmod(0o644)
            manifest2=detached_payload_manifest(bundle_manifest(bundle),b"{}")
            encoded2=json.dumps(manifest2).encode();sidecar.write_bytes(encoded2)
            self.assertTrue(verify_deployment_bundle(bundle,manifest2,identity,encoded2))
            payload.write_bytes(b"[]")
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest2,identity,encoded2)
            payload.write_bytes(b"{}");payload.chmod(0o600)
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest2,identity,encoded2)
            payload.chmod(0o644);alias.hardlink_to(payload)
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest2,identity,encoded2)
            alias.unlink();payload.rename(alias);payload.symlink_to(alias)
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest2,identity,encoded2)
            payload.unlink();alias.rename(payload)
            (resources/"SBOM.cdx.json").write_bytes(b"{}")
            with self.assertRaises(ValueError):verify_deployment_bundle(bundle,manifest2,identity,encoded2)
            (resources/"SBOM.cdx.json").unlink()
            with self.assertRaises(ValueError):verify_bundle(bundle,manifest2,identity)
            self.assertTrue(verify_deployment_bundle(bundle,manifest2,identity,encoded2))
    def test_package_sbom_binds_pkg_and_bundle_files_without_claiming_native_closure(self):
        with tempfile.TemporaryDirectory() as folder:
            pkg=Path(folder)/"test.pkg";pkg.write_bytes(b"xar!fixture")
            evidence=json.dumps([{"path":"licenses/core.txt","sha256":"a"*64}])
            root={"bom-ref":"application","type":"application","name":"core","version":"0.1.0-alpha","hashes":[{"alg":"SHA-256","content":"b"*64}],"properties":[{"name":"accessweaver:target-os","value":"darwin"},{"name":"accessweaver:license-evidence","value":evidence}]}
            payload={"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":root},"components":[],"dependencies":[{"ref":"application","dependsOn":[]}],"compositions":[{"aggregate":"incomplete","assemblies":["application"]}]}
            manifest={"bundleIdentifier":BUNDLE_ID,"files":[{"path":"Contents/Info.plist","sha256":"c"*64}]}
            result=macos_package(pkg,payload,manifest,{"sha256":"d"*64,"osVersion":"15.0","osBuild":"24A1"})
            self.assertTrue(validate(result,pkg.read_bytes()));self.assertEqual(payload["metadata"]["component"]["bom-ref"],"application")
            self.assertEqual(result["metadata"]["component"]["hashes"][0]["content"],sha(pkg.read_bytes()))
            self.assertEqual(result["compositions"][0]["aggregate"],"incomplete")
            changed=copy.deepcopy(manifest);changed["files"][0]["path"]="../escape"
            with self.assertRaises(ValueError):macos_package(pkg,payload,changed,{"sha256":"d"*64,"osVersion":"15.0","osBuild":"24A1"})

if __name__=="__main__":unittest.main()
