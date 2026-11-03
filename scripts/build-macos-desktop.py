#!/usr/bin/env python3
"""Construct/inspect two unsigned native desktop components; never install them."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
import zipfile

from macos_desktop import DESKTOP_ID,ROOT,NOTICE_ROOT,ROLE,MAX_RECORD,inventory,plist,record_name,package_id,component_name,validate_record,verify_bundle,inspect_component,package_sbom
from macos_launcher import BINARY,archive_name,inspect_launcher
from macos_installer import BUNDLE_NAME,digest,require,version_parts
from sbom import generate,validate
from macos_package_archive import flat_members,cpio,inflate

REPO=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location("accessweaver_desktop_dependency_builder",Path(__file__).with_name("build-macos-deployment.py"))
deployment=importlib.util.module_from_spec(spec);spec.loader.exec_module(deployment)
run=deployment.run;encode=deployment.encode


def build(version,arch,go="go"):
    version_parts(version);require(arch in ("amd64","arm64"),"Expected native desktop architecture")
    require(deployment.legacy.platform.system()=="Darwin" and os.geteuid()!=0,"Native ordinary-user Mac desktop builder required")
    base=REPO/"build/macos-deployment-checks"/arch
    identity=json.loads((base/version/"BUILD-INFO.json").read_bytes())
    require(identity["version"]==version and identity["arch"]==arch and identity["platform"]=="darwin" and identity["sourceState"]=="clean" and identity["commit"]==run(["git","rev-parse","HEAD"]).stdout.decode().strip() and not run(["git","status","--porcelain","--untracked-files=normal"]).stdout.strip(),"Desktop requires exact clean core source")
    archive=base/archive_name(arch,None if version=="0.1.1-alpha" else version)
    if not archive.exists():deployment.build_launcher(arch,go,version)
    inspected=inspect_launcher(archive.read_bytes(),identity)
    sdk=json.loads(run([go,"env","-json","GOHOSTOS","GOHOSTARCH","GOVERSION"],env=dict(os.environ,GOTOOLCHAIN="local")).stdout)
    require(sdk=={"GOHOSTOS":"darwin","GOHOSTARCH":arch,"GOVERSION":identity["goVersion"]},"Desktop native SDK differs")
    require(run(["/usr/sbin/sysctl","-n","sysctl.proc_translated"],codes=(0,1)).stdout.strip()!=b"1","Translated desktop build refused")
    cpu=run(["/usr/sbin/sysctl","-n","hw.optional.arm64"],codes=(0,1)).stdout.strip()
    require(arch==("arm64" if cpu==b"1" else "amd64"),"Cross/emulated desktop build refused")
    output=base/"desktop"/version;require(not output.exists(),"Desktop output exists; preserve it");output.mkdir(parents=True)
    stage=Path(tempfile.mkdtemp(prefix="macos-desktop-stage-",dir=REPO/"build"))
    environment=dict(os.environ,GOTOOLCHAIN="local",GOFLAGS="",GOOS="darwin",GOARCH=arch,CGO_ENABLED="0")
    try:
        payload=stage/"application-payload";app=payload/BUNDLE_NAME
        for path in (app,app/"Contents",app/"Contents/MacOS",app/"Contents/Resources",app/"Contents/Resources/licenses"):
            path.mkdir(parents=True,exist_ok=True);path.chmod(0o755)
        with zipfile.ZipFile(io.BytesIO(archive.read_bytes())) as source:
            binary=source.read(BINARY);graph=source.read("SBOM.cdx.json")
            require(digest(binary)==inspected["binarySHA256"],"Actual desktop launcher differs")
            (app/("Contents/MacOS/"+BINARY)).write_bytes(binary);(app/("Contents/MacOS/"+BINARY)).chmod(0o755)
            for name in source.namelist():
                if name.startswith("licenses/"):
                    path=app/"Contents/Resources"/name;path.write_bytes(source.read(name));path.chmod(0o644)
        encode(app/"Contents/Resources/BUILD-INFO.json",identity)
        with (app/"Contents/Info.plist").open("wb") as stream:plistlib.dump(plist(identity),stream,sort_keys=True)
        for path in (app/"Contents/Info.plist",app/"Contents/Resources/BUILD-INFO.json"):path.chmod(0o644)
        receipt={"schemaVersion":1,"role":ROLE,"build":identity,"manifest":inventory(app),"compiledSBOM":graph.decode("utf-8"),"noticeRoot":NOTICE_ROOT}
        encoded=(json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode("utf-8");require(len(encoded)<=MAX_RECORD,"Desktop registration exceeds embedded metadata budget")
        validate_record(encoded,identity);verify_bundle(app,encoded,identity)
        name=record_name(encoded);(output/name).write_bytes(encoded);(output/"DESKTOP-RECORD.json").write_bytes(encoded);encode(output/"BUILD-INFO.json",identity)
        metadata_payload=stage/"metadata-payload";metadata_payload.mkdir();metadata_payload.chmod(0o755)
        (metadata_payload/name).write_bytes(encoded);(metadata_payload/name).chmod(0o644)
        payload.chmod(0o755);reports=[]
        tool=json.loads((base/version/"compiler-artifact.json").read_bytes())["pkgbuild"]
        private=stage/"user";private.mkdir();child_env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":str(private),"TMPDIR":str(private),"LANG":"C","LC_ALL":"C","TZ":"UTC"}
        for role in ("metadata","application"):
            scripts=stage/(role+"-scripts");scripts.mkdir();scripts.chmod(0o755)
            helper=stage/("desktop-helper-"+role)
            stamps={"Version":version,"Commit":identity["commit"],"SourceState":"clean","BuiltAt":identity["builtAt"]}
            flags=["-X github.com/Yunushan/accessweaver/internal/buildinfo."+k+"="+v for k,v in stamps.items()]
            flags.extend("-X github.com/Yunushan/accessweaver/internal/packageupgrade."+k+"="+v for k,v in {"sealedDesktopRecordSHA256":digest(encoded),"sealedDesktopComponent":role}.items())
            run([go,"build","-mod=readonly","-trimpath","-buildvcs=false","-ldflags"," ".join(flags),"-o",helper,"./cmd/accessweaver-desktop-installer"],env=environment)
            helper_bytes=helper.read_bytes();helper_info=json.loads(run([go,"version","-m","-json",helper],env=environment).stdout)
            require(helper_info["GoVersion"]==identity["goVersion"] and helper_info["Path"]=="github.com/Yunushan/accessweaver/cmd/accessweaver-desktop-installer","Desktop helper SDK/main differs")
            settings={v["Key"]:v["Value"] for v in helper_info["Settings"]}
            require(settings.get("GOOS")=="darwin" and settings.get("GOARCH")==arch and settings.get("CGO_ENABLED")=="0" and settings.get("-trimpath")=="true" and "-ldflags" not in settings,"Desktop helper native settings differ")
            require(json.loads(run([helper,"version","--json"],env=child_env,timeout=30).stdout)==identity,"Executed desktop helper identity differs")
            helper_bom=generate(helper,REPO,"./cmd/accessweaver-desktop-installer",identity,scripts/"licenses",go)
            for phase in ("preinstall","postinstall"):shutil.copyfile(helper,scripts/phase);(scripts/phase).chmod(0o755)
            for directory,dirs,files in os.walk(scripts):
                os.chmod(directory,0o755)
                for filename in files:os.chmod(Path(directory)/filename,0o755 if Path(directory)==scripts and filename in ("preinstall","postinstall") else 0o644)
            script_manifest=[]
            for path in sorted(p for p in scripts.rglob("*") if p.is_file()):
                require(not path.is_symlink() and path.stat().st_nlink==1,"Desktop script alias")
                raw=path.read_bytes();script_manifest.append({"path":path.relative_to(scripts).as_posix(),"bytes":len(raw),"sha256":digest(raw),"mode":f"{path.stat().st_mode&0o7777:04o}"})
            script_stat=scripts.stat();script_owner={"uid":script_stat.st_uid,"gid":script_stat.st_gid}
            require(script_owner["uid"]==os.getuid(),"Desktop script tree is not owned by this native builder")
            for path in scripts.rglob("*"):
                st=path.lstat();require(st.st_uid==script_owner["uid"] and st.st_gid==script_owner["gid"],"Desktop script tree ownership is not uniform")
            components=stage/(role+"-components.plist")
            with components.open("wb") as stream:plistlib.dump([{"RootRelativeBundlePath":BUNDLE_NAME,"BundleIsRelocatable":False,"BundleHasStrictIdentifier":True,"BundleIsVersionChecked":False,"BundleOverwriteAction":"upgrade"}] if role=="application" else [],stream)
            target=output/component_name(version,arch,role)
            run(["/usr/bin/pkgbuild","--root",payload if role=="application" else metadata_payload,"--identifier",package_id(role,encoded),"--version",version,"--install-location","/Applications" if role=="application" else ROOT,"--ownership","recommended","--component-plist",components,"--scripts",scripts,target],env=child_env)
            raw=target.read_bytes();inspection=inspect_component(raw,encoded,identity,role,script_manifest,script_owner)
            require(inspection["helperSHA256"]==digest(helper_bytes),"Desktop phase helper differs from actual package")
            expanded=stage/(role+"-expanded");run(["/usr/sbin/pkgutil","--expand-full",target,expanded],env=child_env)
            if role=="application":verify_bundle(expanded/"Payload"/BUNDLE_NAME,encoded,identity)
            else:require((expanded/"Payload"/name).read_bytes()==encoded,"Expanded registration differs")
            for f in script_manifest:
                path=expanded/"Scripts"/f["path"]
                require(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1 and path.stat().st_mode&0o7777==int(f["mode"],8) and digest(path.read_bytes())==f["sha256"],"Expanded desktop script differs")
            signature=run(["/usr/sbin/pkgutil","--check-signature",target],env=child_env,codes=(0,1))
            require(signature.returncode!=0 and b"no signature" in (signature.stdout+signature.stderr).lower(),"Experimental desktop unexpectedly publisher-signed")
            records=[dict(f,path=BUNDLE_NAME+"/"+f["path"]) for f in receipt["manifest"]["files"]] if role=="application" else [{"path":name,"bytes":len(encoded),"sha256":digest(encoded),"mode":"0644"}]
            bom=package_sbom(raw,identity,helper_bom,json.loads(graph) if role=="application" else None,records,script_manifest,tool)
            # Resolve all compiled-component notices against actual script/app bytes.
            actual_scripts=cpio(inflate(flat_members(raw)["Scripts"],32<<20,31))
            from sbom import prop_map
            for c in [bom["metadata"]["component"]]+bom["components"]:
                for evidence in json.loads(prop_map(c).get("accessweaver:license-evidence","[]")):
                    require(evidence["path"] in actual_scripts and digest(actual_scripts[evidence["path"]]["data"])==evidence["sha256"],"Compiled desktop component notice differs")
            encode(output/(target.name+".cdx.json"),bom);encode(output/(role+"-SCRIPT-MANIFEST.json"),script_manifest);encode(output/(role+"-helper-SBOM.cdx.json"),helper_bom)
            reports.append({"component":role,"file":target.name,"bytes":len(raw),"sha256":digest(raw),"archiveInspection":inspection,"helperBuildMetadata":helper_info,"scriptArchiveOwner":script_owner,"helperSHA256":digest(helper_bytes),"helperLinkerFlags":" ".join(flags)})
        validator=stage/"sbom-schema"
        run([go,"-C",REPO/"scripts/sbom-tools","build","-mod=readonly","-trimpath","-o",validator,"."],env=environment)
        graph_path=stage/"launcher-SBOM.cdx.json";graph_path.write_bytes(graph)
        run([validator,"--schemas",REPO/"scripts/sbom/schema",graph_path]+sorted(output.glob("*.cdx.json")),env=child_env)
        report={"schemaVersion":1,"sourceCommit":identity["commit"],"build":identity,"recordFile":name,"recordSHA256":digest(encoded),"launcherArchiveSHA256":inspected["archiveSHA256"],"launcherBinarySHA256":digest(binary),"components":reports,"pkgbuild":tool,"nativeBundleConstructionVerified":True,"actualExpandedPayloadAndScriptsVerified":True,"allCompiledAndPackageGraphsSchemaValidated":True,"metadataOutsideAppVerified":True,"packagePayloadWritesAreOSInstallerOnly":True,"unsigned":True,"installationExecuted":False,"launchServicesQualified":False,"publisherSignatureVerified":False,"notarized":False,"productUninstallQualified":False,"managedEndpointQualified":False,"productionQualificationComplete":False}
        encode(output/"compiler-artifact.json",report);return report
    finally:
        require(stage.resolve().parent==(REPO/"build").resolve() and stage.name.startswith("macos-desktop-stage-"),"Unsafe desktop builder cleanup");shutil.rmtree(stage)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--version",required=True);p.add_argument("--architecture",choices=("amd64","arm64"),required=True);p.add_argument("--go",default="go");a=p.parse_args()
    print(json.dumps(build(a.version,a.architecture,a.go)))

if __name__=="__main__":main()
