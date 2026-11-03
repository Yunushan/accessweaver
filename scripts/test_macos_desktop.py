import json
import os
from pathlib import Path
import plistlib
import stat
import tempfile
import unittest
import xml.etree.ElementTree as ET

from macos_desktop import DESKTOP_ID,ROOT,ROLE,NOTICE_ROOT,record_name,package_id,plist,validate_record,verify_bundle,inspect_component,package_sbom
from macos_installer import digest
from macos_launcher import BINARY
import test_macos_launcher as launcher_fixture
from test_macos_deployment import image,archive,flat_package

class DesktopComponentContracts(unittest.TestCase):
    def fixture(self,role="application",arch="amd64"):
        identity,launcher=launcher_fixture.LauncherArchiveContracts().fixture(arch)
        values={"Contents/Info.plist":plistlib.dumps(plist(identity)),"Contents/MacOS/"+BINARY:launcher[BINARY],"Contents/Resources/BUILD-INFO.json":launcher["BUILD-INFO.json"],"Contents/Resources/licenses/notice.txt":launcher["licenses/notice.txt"]}
        dirs=["Contents","Contents/MacOS","Contents/Resources","Contents/Resources/licenses"]
        manifest={"schemaVersion":1,"bundleIdentifier":DESKTOP_ID,"directories":[{"path":n,"mode":"0755"} for n in dirs],"files":[{"path":n,"mode":"0755" if n.endswith("/"+BINARY) else "0644","bytes":len(v),"sha256":digest(v)} for n,v in values.items()]}
        r={"schemaVersion":1,"role":ROLE,"build":identity,"manifest":manifest,"compiledSBOM":launcher["SBOM.cdx.json"].decode(),"noticeRoot":NOTICE_ROOT};encoded=json.dumps(r,sort_keys=True).encode()
        payload={".":{"mode":stat.S_IFDIR|0o755}}
        if role=="metadata":payload[record_name(encoded)]={"data":encoded}
        else:
            payload["AccessWeaver.app"]={"mode":stat.S_IFDIR|0o755}
            payload.update({"AccessWeaver.app/"+d:{"mode":stat.S_IFDIR|0o755} for d in dirs})
            payload.update({"AccessWeaver.app/"+n:{"data":v,"mode":stat.S_IFREG|(0o755 if n.endswith("/"+BINARY) else 0o644)} for n,v in values.items()})
        scripts={".":{"mode":stat.S_IFDIR|0o755},"preinstall":{"data":image(arch),"mode":stat.S_IFREG|0o755},"postinstall":{"data":image(arch),"mode":stat.S_IFREG|0o755}}
        for entry in scripts.values():entry.update({"uid":501,"gid":20})
        records=[{"path":n,"bytes":len(v["data"]),"sha256":digest(v["data"]),"mode":"0755"} for n,v in scripts.items() if "data" in v]
        info=ET.Element("pkg-info",identifier=package_id(role,encoded),version=identity["version"],auth="root",relocatable="false",attrib={"install-location":ROOT if role=="metadata" else "/Applications"})
        ET.SubElement(info,"relocate");strict=ET.SubElement(info,"strict-identifier")
        if role=="application":ET.SubElement(strict,"bundle",id=DESKTOP_ID)
        phases=ET.SubElement(info,"scripts");ET.SubElement(phases,"preinstall",file="./preinstall");ET.SubElement(phases,"postinstall",file="./postinstall")
        return identity,encoded,payload,scripts,records,info,values
    def inspect(self,f,role):
        identity,encoded,payload,scripts,records,info,_=f
        package=flat_package({"Bom":b"fixture-bom","PackageInfo":ET.tostring(info),"Payload":archive(payload),"Scripts":archive(scripts)})
        return inspect_component(package,encoded,identity,role,records,{"uid":501,"gid":20})
    def test_both_native_roles_bind_distinct_fixed_destinations_and_receipts(self):
        for role in ("metadata","application"):
            for arch in ("amd64","arm64"):
                f=self.fixture(role,arch);result=self.inspect(f,role)
                self.assertEqual(result["recordSHA256"],digest(f[1]));self.assertFalse(result["targetExecutionPerformed"]);self.assertFalse(result["productionQualificationComplete"])
                self.assertEqual(result["packageIdentifier"],package_id(role,f[1]))
    def test_unknown_modified_aliased_or_writable_payloads_fail(self):
        for role in ("metadata","application"):
            for kind in ("bytes","owner","group","writable","symlink","hardlink","extra","target","identity","script-owner","script-group","phase"):
                with self.subTest(role=role,kind=kind):
                    f=self.fixture(role);leaf=f[2][record_name(f[1]) if role=="metadata" else "AccessWeaver.app/Contents/MacOS/"+BINARY]
                    if kind=="bytes":leaf["data"]+=b"changed"
                    elif kind=="owner":leaf["uid"]=501
                    elif kind=="group":leaf["gid"]=80
                    elif kind=="writable":leaf["mode"]=stat.S_IFREG|0o777
                    elif kind=="symlink":leaf["mode"]=stat.S_IFLNK|0o644
                    elif kind=="hardlink":leaf["links"]=2
                    elif kind=="extra":f[2]["unrelated"]={"data":b"preserve"}
                    elif kind=="target":f[5].set("install-location","/tmp/other")
                    elif kind=="identity":f[5].set("identifier","other")
                    elif kind=="script-owner":f[3]["preinstall"]["uid"]=0
                    elif kind=="script-group":f[3]["postinstall"]["gid"]=80
                    else:f[3]["postinstall"]["data"]+=b"changed"
                    with self.assertRaises(ValueError):self.inspect(f,role)
    def test_registration_rejects_public_core_confusion_and_unbound_graphs(self):
        for kind in ("bundle","executable","mode","source","arch","binary","graph-format","notice-root","embedded","duplicate","null","utf16"):
            with self.subTest(kind=kind):
                identity,encoded,*_=self.fixture();r=json.loads(encoded)
                if kind=="bundle":r["manifest"]["bundleIdentifier"]="io.github.yunushan.accessweaver"
                elif kind=="executable":r["manifest"]["files"][1]["path"]="Contents/MacOS/other"
                elif kind=="mode":r["manifest"]["files"][1]["mode"]="0644"
                elif kind=="source":r["build"]["commit"]="b"*40
                elif kind=="arch":r["build"]["arch"]="arm64"
                elif kind=="binary":r["manifest"]["files"][1]["sha256"]="0"*64
                elif kind=="graph-format":r["compiledSBOM"]=r["compiledSBOM"].replace("CycloneDX","other")
                elif kind=="notice-root":r["noticeRoot"]="../other"
                elif kind=="embedded":r["manifest"]["files"][2]["path"]="Contents/Resources/SBOM.cdx.json"
                elif kind=="null":r["compiledSBOM"]=None
                raw=json.dumps(r).encode()
                if kind=="utf16":raw=json.dumps(r).encode("utf-16")
                if kind=="duplicate":raw=raw.replace(b'"schemaVersion": 1',b'"schemaVersion": 1,"schemaVersion":1',1)
                with self.assertRaises((ValueError,TypeError,KeyError)):validate_record(raw,identity)
    def test_component_graph_names_actual_payload_paths_and_retains_incomplete_closure(self):
        for role in ("metadata","application"):
            f=self.fixture(role);identity,encoded,payload,scripts,records,info,_=f
            raw=flat_package({"Bom":b"fixture-bom","PackageInfo":ET.tostring(info),"Payload":archive(payload),"Scripts":archive(scripts)})
            _,source=launcher_fixture.LauncherArchiveContracts().fixture();graph=json.loads(source["SBOM.cdx.json"])
            graph["metadata"]["component"]["properties"].append({"name":"accessweaver:inventory-scope","value":"compiled helper graph"})
            original_graph=json.dumps(graph,sort_keys=True)
            manifest=json.loads(encoded)["manifest"]
            paths=[dict(item,path="AccessWeaver.app/"+item["path"]) for item in manifest["files"]] if role=="application" else [{"path":record_name(encoded),"sha256":digest(encoded)}]
            result=package_sbom(raw,identity,graph,graph if role=="application" else None,paths,records,{"osBuild":"fixture","sha256":"a"*64})
            self.assertEqual({c["name"] for c in result["components"] if c["bom-ref"].startswith("payload:")},{n for n,v in payload.items() if "data" in v})
            self.assertTrue(all(c["aggregate"]=="incomplete" for c in result["compositions"]))
            self.assertEqual(sum(p["name"]=="accessweaver:inventory-scope" for p in result["metadata"]["component"]["properties"]),1)
            self.assertEqual(json.dumps(graph,sort_keys=True),original_graph)
            helper_root=next(c for c in result["components"] if c["bom-ref"]=="helper:application")
            self.assertEqual(next(p["value"] for p in helper_root["properties"] if p["name"]=="accessweaver:inventory-scope"),"compiled helper graph")
    @unittest.skipUnless(os.name=="posix","Physical modes/alias checks require POSIX")
    def test_real_bundle_does_not_hide_binary_bound_metadata_or_aliases(self):
        identity,encoded,_,_,_,_,values=self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            app=Path(tmp)/"AccessWeaver.app"
            for name,value in values.items():
                path=app/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value);path.chmod(0o755 if name.endswith("/"+BINARY) else 0o644)
            for path in [app]+[p for p in app.rglob("*") if p.is_dir()]:path.chmod(0o755)
            verify_bundle(app,encoded,identity)
            forbidden=app/"Contents/Resources/INSTALL-MANIFEST.json";forbidden.write_bytes(b"hidden")
            with self.assertRaises(ValueError):verify_bundle(app,encoded,identity)
            forbidden.unlink();target=app/("Contents/MacOS/"+BINARY);target.unlink();target.symlink_to("/nonexistent")
            with self.assertRaises(ValueError):verify_bundle(app,encoded,identity)

if __name__=="__main__":unittest.main()
