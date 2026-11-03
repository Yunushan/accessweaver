import io
import json
import stat
import unittest
import warnings
import zipfile

from macos_launcher import archive_name,inspect_launcher,BINARY,MAIN
from macos_installer import digest
from sbom import properties
from test_macos_deployment import image

class LauncherArchiveContracts(unittest.TestCase):
    def fixture(self,arch="amd64"):
        identity={"version":"0.1.1-alpha","commit":"a"*40,"sourceState":"clean","builtAt":"2026-11-03T00:00:00Z","goVersion":"go1.27.3","platform":"darwin","arch":arch}
        binary=image(arch);notice=b"launcher notice"
        evidence=json.dumps([{"path":"licenses/notice.txt","sha256":digest(notice)}])
        root={"bom-ref":"application","type":"application","name":"launcher","version":identity["version"],"hashes":[{"alg":"SHA-256","content":digest(binary)}],"properties":properties({"source-commit":identity["commit"],"source-state":"clean","target-os":"darwin","target-arch":arch,"license-evidence":evidence})}
        bom={"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":root},"components":[],"dependencies":[{"ref":"application","dependsOn":[]}],"compositions":[{"aggregate":"incomplete","assemblies":["application"]}]}
        from macos_installer import macho_identity
        flags=" ".join("-X github.com/Yunushan/accessweaver/internal/buildinfo."+k+"="+v for k,v in {"Version":identity["version"],"Commit":identity["commit"],"SourceState":"clean","BuiltAt":identity["builtAt"]}.items())
        metadata={"GoVersion":"go1.27.3","Path":MAIN,"Settings":[{"Key":k,"Value":v} for k,v in {"GOOS":"darwin","GOARCH":arch,"CGO_ENABLED":"0","-trimpath":"true"}.items()]}
        report={"schemaVersion":1,"build":identity,"binarySHA256":digest(binary),"binaryBytes":len(binary),"macho":macho_identity(binary,arch),"goBuildMetadata":metadata,"linkerFlags":flags,"unsigned":True,"publisherSignatureVerified":False,"publicApplicationIntegrated":False,"productionQualificationComplete":False}
        data={BINARY:binary,"BUILD-INFO.json":json.dumps(identity).encode(),"SBOM.cdx.json":json.dumps(bom).encode(),"compiler-artifact.json":json.dumps(report).encode(),"licenses/notice.txt":notice}
        return identity,data
    def archive(self,data,mode=None,duplicate=False):
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w",compression=zipfile.ZIP_DEFLATED) as z:
            for name,value in data.items():
                info=zipfile.ZipInfo(name);info.create_system=3;info.external_attr=((mode if mode is not None and name==BINARY else stat.S_IFREG|(0o755 if name==BINARY else 0o644)))<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,value)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore",UserWarning);z.writestr(BINARY,data[BINARY])
        return output.getvalue()
    def test_native_targets_bind_binary_graph_source_and_notices(self):
        for arch in ("amd64","arm64"):
            identity,data=self.fixture(arch);result=inspect_launcher(self.archive(data),identity)
            self.assertEqual(result["binarySHA256"],digest(data[BINARY]));self.assertEqual(result["noticesVerified"],1)
            self.assertFalse(result["publicApplicationIntegrated"]);self.assertFalse(result["publisherSignatureVerified"])
            self.assertTrue(archive_name(arch).endswith(".zip"))
    def test_changed_missing_extra_alias_and_duplicate_members_fail(self):
        for kind in ("binary","notice","missing","extra","traversal","symlink","writable","duplicate"):
            with self.subTest(kind=kind):
                identity,data=self.fixture();mode=None
                if kind=="binary":data[BINARY]+=b"changed"
                elif kind=="notice":data["licenses/notice.txt"]+=b"changed"
                elif kind=="missing":del data["BUILD-INFO.json"]
                elif kind=="extra":data["licenses/unreferenced.txt"]=b"extra"
                elif kind=="traversal":data["../outside"]=b"unexpected"
                elif kind=="symlink":mode=stat.S_IFLNK|0o755
                elif kind=="writable":mode=stat.S_IFREG|0o777
                with self.assertRaises((ValueError,KeyError,zipfile.BadZipFile)):inspect_launcher(self.archive(data,mode,kind=="duplicate"),identity)
    def test_report_identity_target_linker_and_scope_cannot_substitute(self):
        for kind in ("source","architecture","flags","main","scope","notice-hash"):
            with self.subTest(kind=kind):
                identity,data=self.fixture();report=json.loads(data["compiler-artifact.json"])
                if kind=="source":report["build"]["commit"]="b"*40
                elif kind=="architecture":report["goBuildMetadata"]["Settings"][1]["Value"]="arm64"
                elif kind=="flags":report["linkerFlags"]="different"
                elif kind=="main":report["goBuildMetadata"]["Path"]="other"
                elif kind=="scope":report["publicApplicationIntegrated"]=True
                else:
                    bom=json.loads(data["SBOM.cdx.json"]);next(p for p in bom["metadata"]["component"]["properties"] if p["name"]=="accessweaver:license-evidence")["value"]=json.dumps([{"path":"licenses/notice.txt","sha256":"0"*64}]);data["SBOM.cdx.json"]=json.dumps(bom).encode()
                data["compiler-artifact.json"]=json.dumps(report).encode()
                with self.assertRaises(ValueError):inspect_launcher(self.archive(data),identity)

if __name__=="__main__":unittest.main()
