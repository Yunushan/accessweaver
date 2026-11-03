#!/usr/bin/env python3
"""Build/inspect an unsigned experimental versioned deployment package; never install it."""
import argparse
import datetime
import stat
import zipfile
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile

from macos_deployment import BUNDLE_NAME,PACKAGE_ID,MANIFEST,DETACHED_MANIFEST,PAYLOAD_SBOM,EMBEDDED_SBOM,detached_payload_manifest,verify_deployment_bundle,install_location,inspect_deployment,deployment_sbom,manifest_contract
from macos_installer import bundle_manifest,digest,macho_identity,require,version_parts,MAX_BYTES
from macos_package_archive import flat_members,cpio,inflate,inspect as inspect_legacy
from sbom import generate,validate
from macos_launcher import archive_name,inspect_launcher,BINARY

REPO=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location("accessweaver_native_package_builder",Path(__file__).with_name("build-macos-installer.py"))
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
run=legacy.run
encode=legacy.encode


def build(version,arch,go="go"):
    version_parts(version)
    filename="accessweaver-"+version+"-darwin-"+arch+"-deployment-experimental.pkg"
    require(arch in ("amd64","arm64") and len(filename.encode())<=255,"Invalid deployment package target/name")
    # Reuse the already native/SDK-checked core construction. The old clean-only
    # package is just a local build input and is never installed by this builder.
    original=legacy.build(version,arch,go)
    require(original["sourceState"]=="clean","Deployment packages require a clean source checkout")
    identity=original["payloadBuild"];source=REPO/"build/macos-installer-checks"/arch/version
    encoded=(source/"INSTALL-MANIFEST.json").read_bytes();manifest=json.loads(encoded);manifest_contract(manifest)
    old_package=(source/original["packageFile"]).read_bytes()
    require(inspect_legacy(old_package,manifest,identity)==original["archiveInspection"],"Core build input differs from its inspected package")
    entries=cpio(inflate(flat_members(old_package)["Payload"],MAX_BYTES,31));prefix="Applications/"+BUNDLE_NAME+"/"
    require(entries[prefix+MANIFEST]["data"]==encoded,"Core manifest sidecar differs from actual package")
    environment=dict(os.environ,GOTOOLCHAIN="local",GOFLAGS="",GOOS="darwin",GOARCH=arch,CGO_ENABLED="0")
    output=REPO/"build/macos-deployment-checks"/arch/version
    require(not output.exists(),"Deployment output exists; preserve it and use a new workspace")
    output.mkdir(parents=True)
    stage=Path(tempfile.mkdtemp(prefix="macos-deployment-stage-",dir=REPO/"build"))
    try:
        payload=stage/"payload";app=payload/BUNDLE_NAME;app.mkdir(parents=True)
        for directory in sorted(manifest["directories"],key=lambda d:d["path"]):
            path=app/directory["path"];path.mkdir();path.chmod(0o755)
        for record in manifest["files"]:
            if record["path"]==EMBEDDED_SBOM:continue
            path=app/record["path"]
            with path.open("xb") as stream:stream.write(entries[prefix+record["path"]]["data"])
            path.chmod(int(record["mode"],8))
        payload_raw=(source/PAYLOAD_SBOM).read_bytes()
        require(entries[prefix+EMBEDDED_SBOM]["data"]==payload_raw,"Legacy payload SBOM input differs")
        (payload/PAYLOAD_SBOM).write_bytes(payload_raw);(payload/PAYLOAD_SBOM).chmod(0o644)
        manifest=detached_payload_manifest(bundle_manifest(app),payload_raw)
        encoded=(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8")
        (payload/DETACHED_MANIFEST).write_bytes(encoded);(payload/DETACHED_MANIFEST).chmod(0o644)
        payload.chmod(0o755);app.chmod(0o755);verify_deployment_bundle(app,manifest,identity,encoded)
        core=(app/"Contents/MacOS/accessweaver").read_bytes()
        validate(json.loads(payload_raw),core,identity)
        names={"Version":version,"Commit":identity["commit"],"SourceState":"clean","BuiltAt":identity["builtAt"]}
        flags=["-X github.com/Yunushan/accessweaver/internal/buildinfo."+key+"="+value for key,value in names.items()]
        flags.extend("-X github.com/Yunushan/accessweaver/internal/packageupgrade."+key+"="+value for key,value in {"sealedVersion":version,"sealedManifestSHA256":digest(encoded),"sealedPayloadSHA256":digest(core)}.items())
        helper=stage/"accessweaver-installer"
        run([go,"build","-mod=readonly","-trimpath","-buildvcs=false","-ldflags"," ".join(flags),"-o",helper,"./cmd/accessweaver-installer"],env=environment)
        helper_bytes=helper.read_bytes();helper_native=macho_identity(helper_bytes,arch)
        private=stage/"user";private.mkdir()
        child_env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":str(private),"TMPDIR":str(private),"LANG":"C","LC_ALL":"C","TZ":"UTC"}
        actual=json.loads(run([helper,"version","--json"],env=child_env,timeout=30).stdout)
        require(actual==identity,"Executed new package helper identity differs")
        helper_build=json.loads(run([go,"version","-m","-json",helper],env=environment).stdout)
        require(helper_build["GoVersion"]==identity["goVersion"] and helper_build["Path"]=="github.com/Yunushan/accessweaver/cmd/accessweaver-installer","Package helper Go metadata differs")
        settings={v["Key"]:v["Value"] for v in helper_build["Settings"]}
        require(settings.get("GOOS")=="darwin" and settings.get("GOARCH")==arch and settings.get("CGO_ENABLED")=="0" and settings.get("-trimpath")=="true" and "-ldflags" not in settings,"Package helper settings/seals differ")
        scripts=stage/"scripts";scripts.mkdir();scripts.chmod(0o755)
        for phase in ("preinstall","postinstall"):
            shutil.copyfile(helper,scripts/phase);(scripts/phase).chmod(0o755)
        helper_bom=generate(helper,REPO,"./cmd/accessweaver-installer",identity,scripts/"licenses",go)
        for directory,dirs,files in os.walk(scripts):
            os.chmod(directory,0o755)
            for name in files:os.chmod(Path(directory)/name,0o755 if name in ("preinstall","postinstall") and Path(directory)==scripts else 0o644)
        scripts_manifest=[]
        for path in sorted(p for p in scripts.rglob("*") if p.is_file()):
            require(not path.is_symlink() and path.stat().st_nlink==1,"Package scripts cannot contain aliases")
            data=path.read_bytes();scripts_manifest.append({"path":path.relative_to(scripts).as_posix(),"mode":f"{path.stat().st_mode&0o7777:04o}","bytes":len(data),"sha256":digest(data)})
        component=stage/"components.plist"
        with component.open("wb") as stream:plistlib.dump([{"RootRelativeBundlePath":BUNDLE_NAME,"BundleIsRelocatable":False,"BundleHasStrictIdentifier":True,"BundleIsVersionChecked":False,"BundleOverwriteAction":"upgrade"}],stream)
        package=output/filename
        run(["/usr/bin/pkgbuild","--root",payload,"--identifier",PACKAGE_ID,"--version",version,"--install-location",install_location(digest(encoded)),"--ownership","recommended","--component-plist",component,"--scripts",scripts,package],env=child_env)
        package_bytes=package.read_bytes();inspected=inspect_deployment(package_bytes,encoded,identity,scripts_manifest)
        require(inspected["payloadSHA256"]==digest(core) and inspected["helperSHA256"]==digest(helper_bytes),"Actual deployment package subjects differ")
        expanded=stage/"expanded";run(["/usr/sbin/pkgutil","--expand-full",package,expanded],env=child_env)
        verify_deployment_bundle(expanded/"Payload"/BUNDLE_NAME,manifest,identity,encoded)
        for record in scripts_manifest:
            path=expanded/"Scripts"/record["path"]
            require(path.is_file() and not path.is_symlink() and digest(path.read_bytes())==record["sha256"],"Expanded package script differs")
        signature=run(["/usr/sbin/pkgutil","--check-signature",package],env=child_env,codes=(0,1))
        require(signature.returncode!=0 and b"no signature" in (signature.stdout+signature.stderr).lower(),"Experimental package unexpectedly has a publisher signature")
        bom=deployment_sbom(package_bytes,payload_raw,helper_bom,encoded,scripts_manifest,original["pkgbuild"],core,helper_bytes)
        encode(output/(filename+".cdx.json"),bom)
        encode(output/"BUILD-INFO.json",identity);encode(output/"SCRIPT-MANIFEST.json",scripts_manifest)
        (output/"INSTALL-MANIFEST.json").write_bytes(encoded)
        (output/PAYLOAD_SBOM).write_bytes(payload_raw);encode(output/"helper-SBOM.cdx.json",helper_bom)
        validator=stage/"sbom-schema"
        run([go,"-C",REPO/"scripts/sbom-tools","build","-mod=readonly","-trimpath","-o",validator,"."],env=environment)
        run([validator,"--schemas",REPO/"scripts/sbom/schema",output/(filename+".cdx.json"),output/"payload-SBOM.cdx.json",output/"helper-SBOM.cdx.json"],env=child_env)
        report={"schemaVersion":1,"sourceCommit":identity["commit"],"sourceState":"clean","target":"darwin/"+arch,"payloadBuild":identity,"packageFile":filename,"packageBytes":len(package_bytes),"packageSHA256":digest(package_bytes),"payloadSHA256":digest(core),"manifestSHA256":digest(encoded),"helperSHA256":digest(helper_bytes),"helperBuild":actual,"helperBuildMetadata":helper_build,"helperLinkerFlags":" ".join(flags),"helperMachO":helper_native,"pkgbuild":original["pkgbuild"],"archiveInspection":inspected,"actualExpandedPayloadAndScriptsVerified":True,"packageScriptsIntegrated":True,"detachedManifestOutsideAppVerified":True,"detachedPayloadSBOMOutsideAppVerified":True,"payloadSBOMSHA256":digest(payload_raw),"unsigned":True,"publisherSignatureVerified":False,"notarized":False,"installationExecuted":False,"upgradeQualified":False,"productUninstallQualified":False,"launcherIntegrated":False,"managedEndpointQualified":False,"productionQualificationComplete":False}
        encode(output/"compiler-artifact.json",report)
        return report
    finally:
        require(stage.resolve().parent==(REPO/"build").resolve() and stage.name.startswith("macos-deployment-stage-"),"Unsafe deployment builder cleanup")
        shutil.rmtree(stage)


def build_launcher(arch,go="go",version="0.1.1-alpha"):
    version_parts(version)
    require(legacy.platform.system()=="Darwin" and arch in ("amd64","arm64"),"Native Mac launcher builder required")
    root=REPO/"build/macos-deployment-checks"/arch
    identity=json.loads((root/version/"BUILD-INFO.json").read_bytes())
    require(identity["sourceState"]=="clean" and identity["arch"]==arch and identity["platform"]=="darwin" and identity["commit"]==run(["git","rev-parse","HEAD"]).stdout.decode().strip() and not run(["git","status","--porcelain","--untracked-files=normal"]).stdout.strip(),"Launcher requires the exact clean native package source")
    environment=dict(os.environ,GOTOOLCHAIN="local",GOFLAGS="",GOOS="darwin",GOARCH=arch,CGO_ENABLED="0")
    sdk=json.loads(run([go,"env","-json","GOHOSTOS","GOHOSTARCH","GOVERSION"],env=environment).stdout)
    require(sdk=={"GOHOSTOS":"darwin","GOHOSTARCH":arch,"GOVERSION":identity["goVersion"]},"Launcher native SDK differs")
    require(run(["/usr/sbin/sysctl","-n","sysctl.proc_translated"],codes=(0,1)).stdout.strip()!=b"1","Translated launcher builds are not qualified")
    native=run(["/usr/sbin/sysctl","-n","hw.optional.arm64"],codes=(0,1)).stdout.strip()
    require(arch==("arm64" if native==b"1" else "amd64"),"Cross/emulated launcher builds are not qualified")
    output=root/("launcher" if version=="0.1.1-alpha" else "launcher-"+version);require(not output.exists(),"Launcher output exists; preserve it")
    output.mkdir();binary=output/BINARY
    flags=" ".join("-X github.com/Yunushan/accessweaver/internal/buildinfo."+key+"="+value for key,value in {"Version":identity["version"],"Commit":identity["commit"],"SourceState":"clean","BuiltAt":identity["builtAt"]}.items())
    run([go,"build","-mod=readonly","-trimpath","-buildvcs=false","-ldflags",flags,"-o",binary,"./cmd/accessweaver-launcher"],env=environment)
    metadata=json.loads(run([go,"version","-m","-json",binary],env=environment).stdout)
    private=Path(tempfile.mkdtemp(prefix="macos-launcher-probe-",dir=REPO/"build"))
    try:
        child_env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":str(private),"TMPDIR":str(private),"LANG":"C","LC_ALL":"C","TZ":"UTC"}
        require(json.loads(run([binary,"launcher-version","--json"],env=child_env,timeout=30).stdout)==identity,"Executed launcher identity differs")
        bom=generate(binary,REPO,"./cmd/accessweaver-launcher",identity,output/"licenses",go)
        encode(output/"BUILD-INFO.json",identity);encode(output/"SBOM.cdx.json",bom)
        report={"schemaVersion":1,"build":identity,"binarySHA256":digest(binary.read_bytes()),"binaryBytes":binary.stat().st_size,"macho":macho_identity(binary.read_bytes(),arch),"goBuildMetadata":metadata,"linkerFlags":flags,"unsigned":True,"publisherSignatureVerified":False,"publicApplicationIntegrated":False,"productionQualificationComplete":False}
        encode(output/"compiler-artifact.json",report)
        epoch=int(run(["git","show","-s","--format=%ct","HEAD"]).stdout);stamp=datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc).timetuple()[:6]
        target=root/archive_name(arch,None if version=="0.1.1-alpha" else version);require(not target.exists(),"Launcher archive exists")
        with zipfile.ZipFile(target,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
            for path in sorted(p for p in output.rglob("*") if p.is_file()):
                require(not path.is_symlink() and path.stat().st_nlink==1,"Launcher source alias")
                name=path.relative_to(output).as_posix();info=zipfile.ZipInfo(name,stamp);info.create_system=3;info.external_attr=(stat.S_IFREG|(0o755 if name==BINARY else 0o644))<<16;info.compress_type=zipfile.ZIP_DEFLATED
                archive.writestr(info,path.read_bytes())
        return inspect_launcher(target.read_bytes(),identity)
    finally:
        require(private.resolve().parent==(REPO/"build").resolve() and private.name.startswith("macos-launcher-probe-"),"Unsafe launcher probe cleanup")
        shutil.rmtree(private)


def main():
    parser=argparse.ArgumentParser(description=__doc__);choice=parser.add_mutually_exclusive_group(required=True);choice.add_argument("--version");choice.add_argument("--launcher",action="store_true");parser.add_argument("--architecture",choices=("amd64","arm64"),required=True);parser.add_argument("--go",default="go")
    args=parser.parse_args()
    if args.launcher:
        print(json.dumps(build_launcher(args.architecture,args.go)));return
    report=build(args.version,args.architecture,args.go)
    print(json.dumps({"sourceCommit":report["sourceCommit"],"target":report["target"],"packageSHA256":report["packageSHA256"],"installationExecuted":False,"productionQualificationComplete":False}))

if __name__=="__main__":main()
