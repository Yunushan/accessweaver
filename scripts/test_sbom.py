import copy
import json
import io
import tarfile
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sbom import generate, installer, json_stream, sha, validate
from verify_release import inspect_archive


class SBOMTests(unittest.TestCase):
    def fixture(self):
        identity={"version":"0.1.0-alpha","commit":"a"*40,"sourceState":"clean","platform":"linux","arch":"amd64","goVersion":"go1.27.3","builtAt":"2026-11-01T00:00:00Z"}
        root={"bom-ref":"application","type":"application","name":"AccessWeaver","version":identity["version"],"hashes":[{"alg":"SHA-256","content":sha(b"binary")}],"properties":[{"name":"accessweaver:"+k,"value":v} for k,v in [("source-commit",identity["commit"]),("source-state","clean"),("target-os","linux"),("target-arch","amd64")]]}
        evidence={"name":"accessweaver:license-evidence","value":json.dumps([{"path":"licenses/notice.txt","sha256":"a"*64}])}
        root["properties"].append(evidence)
        document={"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":root},"components":[{"bom-ref":"stdlib","type":"library","name":"Go","properties":[evidence]}],"dependencies":[{"ref":"application","dependsOn":["stdlib"]},{"ref":"stdlib","dependsOn":[]}],"compositions":[{"aggregate":"incomplete","assemblies":["application"]}]}
        return document,identity

    def test_binary_identity_graph_and_completeness_are_checked(self):
        document,identity=self.fixture()
        self.assertTrue(validate(document,b"binary",identity))
        for kind in ("hash","target","duplicate","dangling","missing","unreachable","completeness"):
            with self.subTest(kind=kind):
                changed=copy.deepcopy(document)
                if kind=="hash":changed["metadata"]["component"]["hashes"][0]["content"]="0"*64
                elif kind=="target":next(p for p in changed["metadata"]["component"]["properties"] if p["name"]=="accessweaver:target-arch")["value"]="arm64"
                elif kind=="duplicate":changed["components"].append(changed["components"][0])
                elif kind=="dangling":changed["dependencies"][0]["dependsOn"].append("missing")
                elif kind=="missing":changed["dependencies"].pop()
                elif kind=="unreachable":changed["dependencies"][0]["dependsOn"]=[]
                else:changed["compositions"][0]["aggregate"]="complete"
                with self.assertRaises(ValueError):validate(changed,b"binary",identity)

    def test_installer_preserves_payload_and_marks_native_closure_incomplete(self):
        document,_=self.fixture()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            binary=root/"setup.exe";binary.write_bytes(b"installer")
            compiler=root/"ISCC.exe";compiler.write_bytes(b"compiler")
            license=root/"License.txt";license.write_bytes(b"Inno Setup notice")
            result=installer(binary,document,compiler,"6.7.1",license,root/"licenses")
            self.assertTrue(validate(result,b"installer"))
            self.assertEqual(result["metadata"]["component"]["hashes"][0]["content"],sha(b"installer"))
            payload=next(c for c in result["components"] if c["bom-ref"]=="payload-application")
            self.assertEqual(payload["hashes"][0]["content"],sha(b"binary"))
            self.assertEqual(result["compositions"][0]["aggregate"],"incomplete")
            self.assertEqual(document["metadata"]["component"]["bom-ref"],"application")

    def test_archive_rejects_missing_sbom_changed_binary_and_changed_notices(self):
        document,identity=self.fixture()
        for c in [document["metadata"]["component"]]+document["components"]:
            for prop in c.get("properties",[]):
                if prop["name"]=="accessweaver:license-evidence":prop["value"]=json.dumps([{"path":"licenses/notice.txt","sha256":sha(b"notice")}])
        for mode in ("valid","missing-sbom","changed-binary","changed-notice"):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as folder:
                root="accessweaver-test-linux-amd64"
                path=Path(folder)/"fixture.tar.gz"
                files={"accessweaver":b"changed" if mode=="changed-binary" else b"binary","BUILD-INFO.json":json.dumps(identity).encode(),
                       "SBOM.cdx.json":json.dumps(document).encode(),"LICENSE":b"fixture","THIRD_PARTY.md":b"fixture","SECURITY.md":b"fixture",
                       "licenses/Go-runtime-LICENSE":b"fixture","licenses/SplitWire-Turkey-MIT.txt":b"fixture",
                       "licenses/notice.txt":b"changed" if mode=="changed-notice" else b"notice"}
                if mode=="missing-sbom":del files["SBOM.cdx.json"]
                with tarfile.open(path,"w:gz") as archive:
                    for name,data in files.items():
                        info=tarfile.TarInfo(root+"/"+name);info.size=len(data)
                        archive.addfile(info,io.BytesIO(data))
                if mode=="valid":self.assertEqual(inspect_archive(path,root,"accessweaver")[1],b"binary")
                else:
                    with self.assertRaises(ValueError):inspect_archive(path,root,"accessweaver")

    def test_stream_parser_requires_valid_bounded_metadata(self):
        self.assertEqual(json_stream(' {"a":1} \n {"b":2} '),[{"a":1},{"b":2}])
        with self.assertRaises((ValueError,json.JSONDecodeError)):json_stream('{"a":')

    def test_source_analysis_rejects_binary_with_cgo_before_running_sources(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);binary=root/"binary";binary.write_bytes(b"not executed")
            info={"Settings":[{"Key":"CGO_ENABLED","Value":"1"}]}
            with patch("sbom.command",return_value=json.dumps(info)) as run:
                with self.assertRaisesRegex(ValueError,"CGO_ENABLED"):
                    generate(binary,root,".",{},root/"licenses")
                self.assertEqual(run.call_count,1)


if __name__=="__main__":unittest.main()
