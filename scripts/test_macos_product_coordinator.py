import copy
import json
from pathlib import Path
import stat
import tempfile
import unittest
import xml.etree.ElementTree as ET

from macos_desktop import component_name,inspect_component,package_sbom,record_name
from macos_installer import digest
from verify_macos_desktop_provenance import validate_coordinated_application
import test_macos_desktop as desktop_fixture
from test_macos_deployment import archive,flat_package


class ProductCoordinatorProvenance(unittest.TestCase):
    def fixture(self,root,arch="amd64"):
        identity,encoded,payload,scripts,_,info,_=desktop_fixture.DesktopComponentContracts().fixture("application",arch)
        record=json.loads(encoded);helper_graph=json.loads(record["compiledSBOM"])
        helper_graph["metadata"]["component"]["properties"].append({"name":"accessweaver:main-package","value":"./cmd/accessweaver-product-installer"})
        scripts["licenses"]={"mode":stat.S_IFDIR|0o755,"uid":501,"gid":20}
        scripts["licenses/notice.txt"]={"data":b"launcher notice","mode":stat.S_IFREG|0o644,"uid":501,"gid":20}
        manifest=[{"path":name,"bytes":len(entry["data"]),"sha256":digest(entry["data"]),"mode":"0755" if name in ("preinstall","postinstall") else "0644"} for name,entry in scripts.items() if "data" in entry]
        raw=flat_package({"Bom":b"fixture-bom","PackageInfo":ET.tostring(info),"Payload":archive(payload),"Scripts":archive(scripts)})
        name=component_name(identity["version"],arch,"application",product=True);prefix="product-application-"+identity["version"]+"-"
        core={"manifestSHA256":"1"*64,"payloadSHA256":"2"*64,"pkgbuild":{"sha256":"3"*64,"osBuild":"fixture","osVersion":"15.0"}}
        launcher={"binarySHA256":digest(payload["AccessWeaver.app/Contents/MacOS/accessweaver-launcher"]["data"]),"archiveSHA256":"4"*64}
        stamps={"Version":identity["version"],"Commit":identity["commit"],"SourceState":"clean","BuiltAt":identity["builtAt"]}
        seals={"sealedDesktopRecordSHA256":digest(encoded),"sealedDesktopComponent":"application","sealedVersion":identity["version"],"sealedManifestSHA256":core["manifestSHA256"],"sealedPayloadSHA256":core["payloadSHA256"]}
        flags=["-X github.com/Yunushan/accessweaver/internal/buildinfo."+k+"="+v for k,v in stamps.items()]+["-X github.com/Yunushan/accessweaver/internal/packageupgrade."+k+"="+v for k,v in seals.items()]
        inspection=inspect_component(raw,encoded,identity,"application",manifest,{"uid":501,"gid":20})
        item={"component":"application","file":name,"bytes":len(raw),"sha256":digest(raw),"archiveInspection":inspection,"helperSHA256":inspection["helperSHA256"],"scriptArchiveOwner":{"uid":501,"gid":20},"helperLinkerFlags":" ".join(flags),"helperBuildMetadata":{"GoVersion":identity["goVersion"],"Path":"github.com/Yunushan/accessweaver/cmd/accessweaver-product-installer","Settings":[{"Key":k,"Value":v} for k,v in {"GOOS":"darwin","GOARCH":arch,"CGO_ENABLED":"0","-trimpath":"true"}.items()]}}
        report={"schemaVersion":1,"sourceCommit":identity["commit"],"build":identity,"recordFile":record_name(encoded),"recordSHA256":digest(encoded),"productCoordination":True,"coreIdentity":{"version":identity["version"],"manifestSHA256":core["manifestSHA256"],"payloadSHA256":core["payloadSHA256"]},"pkgbuild":core["pkgbuild"],"launcherBinarySHA256":launcher["binarySHA256"],"launcherArchiveSHA256":launcher["archiveSHA256"],"components":[item]}
        for key in ("nativeBundleConstructionVerified","actualExpandedPayloadAndScriptsVerified","allCompiledAndPackageGraphsSchemaValidated","metadataOutsideAppVerified","packagePayloadWritesAreOSInstallerOnly","unsigned"):report[key]=True
        for key in ("installationExecuted","launchServicesQualified","publisherSignatureVerified","notarized","productUninstallQualified","managedEndpointQualified","productionQualificationComplete"):report[key]=False
        records=[dict(f,path="AccessWeaver.app/"+f["path"]) for f in record["manifest"]["files"]]
        graph=package_sbom(raw,identity,helper_graph,json.loads(record["compiledSBOM"]),records,manifest,core["pkgbuild"])
        (root/name).write_bytes(raw)
        for filename,value in ((name+".cdx.json",graph),(prefix+"compiler-artifact.json",report),(prefix+"application-SCRIPT-MANIFEST.json",manifest),(prefix+"application-helper-SBOM.cdx.json",helper_graph)):
            (root/filename).write_text(json.dumps(value),encoding="utf-8")
        return (root,identity["commit"],arch,identity,encoded,record,core,launcher),prefix,name

    def test_actual_package_graph_and_dual_seals_bind_both_architectures(self):
        for arch in ("amd64","arm64"):
            with tempfile.TemporaryDirectory() as folder:
                args,_,name=self.fixture(Path(folder),arch)
                result=validate_coordinated_application(*args)
                self.assertEqual(result["component"],"application");self.assertFalse(result["targetExecutionPerformed"])
                self.assertNotEqual(name,component_name(args[3]["version"],arch,"application"))

    def test_partial_seals_standard_helper_and_unearned_scope_fail(self):
        for kind in ("manifest","payload","version","missing-seal","role","main","record","source","package-name","scope","component-count"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                args,prefix,_=self.fixture(Path(folder));p=Path(folder)/(prefix+"compiler-artifact.json");report=json.loads(p.read_bytes());item=report["components"][0]
                if kind in ("manifest","payload","version"):report["coreIdentity"][{"manifest":"manifestSHA256","payload":"payloadSHA256","version":"version"}[kind]]="different"
                elif kind=="missing-seal":item["helperLinkerFlags"]=item["helperLinkerFlags"].split(" -X github.com/Yunushan/accessweaver/internal/packageupgrade.sealedVersion")[0]
                elif kind=="role":report["productCoordination"]=False
                elif kind=="main":item["helperBuildMetadata"]["Path"]="github.com/Yunushan/accessweaver/cmd/accessweaver-desktop-installer"
                elif kind=="record":report["recordSHA256"]="5"*64
                elif kind=="source":report["sourceCommit"]="b"*40
                elif kind=="package-name":item["file"]=component_name(args[3]["version"],"amd64","application")
                elif kind=="scope":report["productionQualificationComplete"]=True
                elif kind=="component-count":report["components"].append(copy.deepcopy(item))
                p.write_text(json.dumps(report),encoding="utf-8")
                with self.assertRaises(ValueError):validate_coordinated_application(*args)

    def test_substituted_script_graph_main_and_package_graph_fail(self):
        for kind in ("script-bytes","helper-main","package-graph"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);args,prefix,name=self.fixture(root)
                if kind=="script-bytes":
                    p=root/(prefix+"application-SCRIPT-MANIFEST.json");value=json.loads(p.read_bytes());value[0]["sha256"]="6"*64
                elif kind=="helper-main":
                    p=root/(prefix+"application-helper-SBOM.cdx.json");value=json.loads(p.read_bytes());next(v for v in value["metadata"]["component"]["properties"] if v["name"]=="accessweaver:main-package")["value"]="./cmd/accessweaver-desktop-installer"
                else:
                    p=root/(name+".cdx.json");value=json.loads(p.read_bytes());value["metadata"]["component"]["name"]="different"
                p.write_text(json.dumps(value),encoding="utf-8")
                with self.assertRaises(ValueError):validate_coordinated_application(*args)
