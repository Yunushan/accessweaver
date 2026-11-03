import copy
import hashlib
import json
import plistlib
import stat
import struct
import unittest
import xml.etree.ElementTree as ET
import zlib

from macos_deployment import PACKAGE_ID,MANIFEST,DETACHED_MANIFEST,PAYLOAD_SBOM,EMBEDDED_SBOM,detached_payload_manifest,install_location,inspect_deployment,manifest_contract,script_contract,deployment_sbom
from macos_installer import BUNDLE_ID,bundle_plist,digest
from sbom import validate,properties


def image(arch):
    return struct.pack("<8I",0xfeedfacf,{"amd64":0x1000007,"arm64":0x100000c}[arch],0,2,1,16,0,0)+struct.pack("<4I",0x24,16,0x000d0000,0)

def cpio_entry(name,data=b"",mode=stat.S_IFREG|0o644,uid=0,gid=0,links=1):
    encoded=name.encode()+b"\0"
    fields=[(0,6),(1,6),(mode,6),(uid,6),(gid,6),(links,6),(0,6),(0,11),(len(encoded),6),(len(data),11)]
    return b"070707"+b"".join(format(v,"0"+str(w)+"o").encode() for v,w in fields)+encoded+data

def archive(entries):
    data=b"".join(cpio_entry(name,**item) for name,item in entries.items())+cpio_entry("TRAILER!!!",mode=0)
    compressor=zlib.compressobj(wbits=31)
    return compressor.compress(data)+compressor.flush()

def flat_package(members):
    root=ET.Element("xar");toc=ET.SubElement(root,"toc");checksum=ET.SubElement(toc,"checksum",style="sha1")
    ET.SubElement(checksum,"offset").text="0";ET.SubElement(checksum,"size").text="20"
    heap=b"";offset=20
    for name,contents in members.items():
        entry=ET.SubElement(toc,"file");ET.SubElement(entry,"name").text=name;ET.SubElement(entry,"type").text="file";data=ET.SubElement(entry,"data");raw=zlib.compress(contents)
        for key,value in (("offset",offset),("length",len(raw)),("size",len(contents))):ET.SubElement(data,key).text=str(value)
        ET.SubElement(data,"encoding",style="application/x-gzip")
        ET.SubElement(data,"archived-checksum",style="sha1").text=hashlib.sha1(raw).hexdigest()
        ET.SubElement(data,"extracted-checksum",style="sha1").text=hashlib.sha1(contents).hexdigest()
        heap+=raw;offset+=len(raw)
    decoded=ET.tostring(root);encoded=zlib.compress(decoded)
    return struct.pack(">4sHHQQI",b"xar!",28,1,len(encoded),len(decoded),1)+encoded+hashlib.sha1(encoded).digest()+heap

class DeploymentPackageContracts(unittest.TestCase):
    def fixture(self,arch="amd64",signature_resources=False):
        identity={"version":"0.1.0-alpha","commit":"a"*40,"sourceState":"clean","platform":"darwin","arch":arch,"goVersion":"go1.27.3","builtAt":"2026-11-03T00:00:00Z"}
        values={"Contents/Info.plist":plistlib.dumps(bundle_plist(identity["version"],"13.0.0")),"Contents/MacOS/accessweaver":image(arch),"Contents/Resources/BUILD-INFO.json":json.dumps(identity).encode()}
        if signature_resources:values["Contents/_CodeSignature/CodeResources"]=b"opaque resource-seal fixture; not a validated signature"
        manifest={"schemaVersion":2,"payloadSBOM":{"path":PAYLOAD_SBOM,"bytes":2,"sha256":digest(b"{}"),"mode":"0644"},"bundleIdentifier":BUNDLE_ID,"directories":[{"path":n,"mode":"0755"} for n in (("Contents","Contents/MacOS","Contents/Resources","Contents/_CodeSignature") if signature_resources else ("Contents","Contents/MacOS","Contents/Resources"))],"files":[{"path":n,"bytes":len(v),"sha256":digest(v),"mode":"0755" if n.endswith("/accessweaver") else "0644"} for n,v in values.items()]}
        encoded=json.dumps(manifest).encode()
        payload={".":{"mode":stat.S_IFDIR|0o755},"AccessWeaver.app":{"mode":stat.S_IFDIR|0o755}}
        payload.update({"AccessWeaver.app/"+d["path"]:{"mode":stat.S_IFDIR|0o755} for d in manifest["directories"]})
        payload.update({"AccessWeaver.app/"+n:{"data":v,"mode":stat.S_IFREG|(0o755 if n.endswith("/accessweaver") else 0o644)} for n,v in values.items()})
        payload[DETACHED_MANIFEST]={"data":encoded};payload[PAYLOAD_SBOM]={"data":b"{}"}
        scripts={".":{"mode":stat.S_IFDIR|0o755,"uid":501,"gid":20},"licenses":{"mode":stat.S_IFDIR|0o755,"uid":501,"gid":20},"preinstall":{"data":image(arch),"mode":stat.S_IFREG|0o755,"uid":501,"gid":20},"postinstall":{"data":image(arch),"mode":stat.S_IFREG|0o755,"uid":501,"gid":20},"licenses/notice.txt":{"data":b"notice","uid":501,"gid":20}}
        records=[{"path":n,"mode":"0755" if n in ("preinstall","postinstall") else "0644","bytes":len(v["data"]),"sha256":digest(v["data"])} for n,v in scripts.items() if "data" in v]
        metadata=ET.Element("pkg-info",identifier=PACKAGE_ID,version=identity["version"],auth="root",relocatable="false",attrib={"install-location":install_location(digest(encoded))})
        ET.SubElement(metadata,"relocate");strict=ET.SubElement(metadata,"strict-identifier");ET.SubElement(strict,"bundle",id=BUNDLE_ID)
        phases=ET.SubElement(metadata,"scripts");ET.SubElement(phases,"preinstall",file="./preinstall");ET.SubElement(phases,"postinstall",file="./postinstall")
        return identity,manifest,encoded,payload,scripts,records,metadata
    def inspect(self,fixture):
        identity,manifest,encoded,payload,scripts,records,metadata=fixture
        package=flat_package({"Bom":b"fixture-bom","PackageInfo":ET.tostring(metadata),"Payload":archive(payload),"Scripts":archive(scripts)})
        return inspect_deployment(package,encoded,identity,records)
    def test_actual_archive_structure_binds_two_native_binary_phases_and_private_input(self):
        for arch in ("amd64","arm64"):
            fixture=self.fixture(arch);result=self.inspect(fixture)
            self.assertEqual(result["installLocation"],install_location(digest(fixture[2])))
            self.assertEqual(result["helperSHA256"],digest(image(arch)))
            self.assertTrue(result["allPathsModesOwnershipAndHashesVerified"])
            self.assertTrue(result["detachedManifestOutsideAppVerified"])
            self.assertTrue(result["detachedPayloadSBOMOutsideAppVerified"])
            self.assertFalse(result["targetExecutionPerformed"])
            self.assertFalse(result["productionQualificationComplete"])
    def test_payload_changes_aliases_extra_paths_and_owner_changes_fail(self):
        for kind in ("changed","owner","group","writable","alias","hardlink","extra"):
            with self.subTest(kind=kind):
                f=self.fixture();leaf=f[3]["AccessWeaver.app/Contents/MacOS/accessweaver"]
                if kind=="changed":leaf["data"]+=b"changed"
                elif kind=="owner":leaf["uid"]=501
                elif kind=="group":leaf["gid"]=80
                elif kind=="writable":leaf["mode"]=stat.S_IFREG|0o777
                elif kind=="alias":leaf["mode"]=stat.S_IFLNK|0o755
                elif kind=="hardlink":leaf["links"]=2
                else:f[3]["unrelated"]={"data":b"preserve"}
                with self.assertRaises(ValueError):self.inspect(f)
    def test_detached_inventory_hashes_signature_resources_without_claiming_signature_validation(self):
        fixture=self.fixture(signature_resources=True);result=self.inspect(fixture)
        self.assertTrue(result["detachedManifestOutsideAppVerified"])
        self.assertFalse(result["publisherSignatureVerified"])
        fixture[3]["AccessWeaver.app/Contents/_CodeSignature/CodeResources"]["data"]+=b"changed"
        with self.assertRaises(ValueError):self.inspect(fixture)

    def test_detached_manifest_must_be_exact_unique_regular_and_outside_app(self):
        for kind in ("missing","changed","embedded","both","mode","owner","alias","hardlink"):
            with self.subTest(kind=kind):
                f=self.fixture();sidecar=f[3][DETACHED_MANIFEST]
                if kind=="missing":del f[3][DETACHED_MANIFEST]
                elif kind=="changed":sidecar["data"]+=b" "
                elif kind in ("embedded","both"):
                    f[3]["AccessWeaver.app/"+MANIFEST]=dict(sidecar)
                    if kind=="embedded":del f[3][DETACHED_MANIFEST]
                elif kind=="mode":sidecar["mode"]=stat.S_IFREG|0o600
                elif kind=="owner":sidecar["uid"]=501
                elif kind=="alias":sidecar["mode"]=stat.S_IFLNK|0o644
                else:sidecar["links"]=2
                with self.assertRaises(ValueError):self.inspect(f)

    def test_detached_payload_sbom_requires_exact_bytes_and_single_regular_subject(self):
        for kind in ("missing","changed","embedded","mode","owner","alias","hardlink"):
            with self.subTest(kind=kind):
                f=self.fixture();sidecar=f[3][PAYLOAD_SBOM]
                if kind=="missing":del f[3][PAYLOAD_SBOM]
                elif kind=="changed":sidecar["data"]+=b" "
                elif kind=="embedded":f[3]["AccessWeaver.app/"+EMBEDDED_SBOM]=dict(sidecar)
                elif kind=="mode":sidecar["mode"]=stat.S_IFREG|0o600
                elif kind=="owner":sidecar["uid"]=501
                elif kind=="alias":sidecar["mode"]=stat.S_IFLNK|0o644
                else:sidecar["links"]=2
                with self.assertRaises(ValueError):self.inspect(f)
        for mutate in (lambda m:m.pop("payloadSBOM"),lambda m:m["payloadSBOM"].update(path="../other"),lambda m:m["payloadSBOM"].update(bytes=True),lambda m:m["payloadSBOM"].update(bytes=0),lambda m:m["payloadSBOM"].update(mode="0755"),lambda m:m["payloadSBOM"].update(sha256="unknown")):
            manifest=copy.deepcopy(self.fixture()[1]);mutate(manifest)
            with self.assertRaises(ValueError):manifest_contract(manifest)
        inventory={k:v for k,v in self.fixture()[1].items() if k!="payloadSBOM"};inventory["schemaVersion"]=1
        result=detached_payload_manifest(inventory,b"{}");self.assertEqual(result,self.fixture()[1]);self.assertEqual(inventory["schemaVersion"],1)
        inventory["schemaVersion"]=True
        with self.assertRaises(ValueError):detached_payload_manifest(inventory,b"{}")

    def test_scripts_and_fixed_package_destination_cannot_be_substituted(self):
        for kind in ("helper","phase","unexpected","destination","identifier","version","relocation","duplicate-phase"):
            with self.subTest(kind=kind):
                f=self.fixture()
                if kind=="helper":f[4]["preinstall"]["data"]=image("arm64")
                elif kind=="phase":f[4]["postinstall"]["data"]+=b"different"
                elif kind=="unexpected":f[4]["other"]={"data":b"unexpected"}
                elif kind=="duplicate-phase":ET.SubElement(f[6].find("scripts"),"preinstall",file="./preinstall")
                else:f[6].set({"destination":"install-location","identifier":"identifier","version":"version","relocation":"relocatable"}[kind],{"destination":"/Applications","identifier":BUNDLE_ID,"version":"0.0.9","relocation":"true"}[kind])
                with self.assertRaises(ValueError):self.inspect(f)
    def test_manifest_and_script_subject_contracts_reject_ambiguity(self):
        for change in (lambda m:m.update(schemaVersion=True),lambda m:m["files"].append(dict(m["files"][0],path="contents/Info.plist")),lambda m:m["files"][0].update(path="../outside"),lambda m:m["files"][0].update(bytes=True),lambda m:m["files"][0].update(bytes=64<<20|1),lambda m:m["files"][0].update(mode="0755"),lambda m:m["directories"].pop(0)):
            manifest=copy.deepcopy(self.fixture()[1]);change(manifest)
            with self.assertRaises(ValueError):manifest_contract(manifest)
        for name in ("../outside","licenses/..","preinstall/extra","licenses/nested/file"):
            records=copy.deepcopy(self.fixture()[5]);records[-1]["path"]=name
            with self.assertRaises(ValueError):script_contract(records)
        for seal in ("a"*63,"A"*64,"../input",None):
            with self.assertRaises(ValueError):install_location(seal)
    def test_sbom_keeps_both_compiled_graphs_and_file_subjects_with_incomplete_os_closure(self):
        f=self.fixture();identity,manifest,_,_,_,records,_=f
        def document(binary):
            evidence=json.dumps([{"path":"licenses/notice.txt","sha256":digest(b"notice")}])
            root={"bom-ref":"application","type":"application","name":"AccessWeaver","version":identity["version"],"hashes":[{"alg":"SHA-256","content":digest(binary)}],"properties":properties({"source-commit":identity["commit"],"source-state":"clean","target-os":"darwin","target-arch":"amd64","license-evidence":evidence})}
            return {"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":root},"components":[{"bom-ref":"stdlib","type":"library","name":"Go","properties":properties({"license-evidence":evidence})}],"dependencies":[{"ref":"application","dependsOn":["stdlib"]},{"ref":"stdlib","dependsOn":[]}],"compositions":[{"aggregate":"incomplete","assemblies":["application"]}]}
        payload=document(image("amd64"));helper=document(image("amd64"));payload_raw=json.dumps(payload).encode();manifest["payloadSBOM"].update(bytes=len(payload_raw),sha256=digest(payload_raw));encoded=json.dumps(manifest).encode();tool={"osBuild":"fixture","osVersion":"15.0","sha256":"c"*64}
        result=deployment_sbom(b"xar!fixture",payload_raw,helper,encoded,records,tool,image("amd64"),image("amd64"))
        self.assertTrue(validate(result,b"xar!fixture"))
        self.assertEqual(result["compositions"][0]["aggregate"],"incomplete")
        refs={c["bom-ref"] for c in result["components"]};self.assertIn("payload:application",refs);self.assertIn("helper:application",refs);self.assertIn("script-file:postinstall",refs);self.assertIn("detached-file:INSTALL-MANIFEST.json",refs);self.assertIn("detached-file:payload-SBOM.cdx.json",refs)
        changed=copy.deepcopy(helper);changed["metadata"]["component"]["hashes"][0]["content"]="0"*64
        with self.assertRaises(ValueError):deployment_sbom(b"xar!fixture",payload_raw,changed,encoded,records,tool,image("amd64"),image("amd64"))
        self.assertEqual(payload["metadata"]["component"]["bom-ref"],"application")

if __name__=="__main__":unittest.main()
