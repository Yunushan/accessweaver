#!/usr/bin/env python3
"""Build and inspect an experimental unsigned native macOS app/package. Never installs it."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile

from macos_installer import BUNDLE_ID,BUNDLE_NAME,bundle_manifest,bundle_plist,digest,macho_identity,require,verify_bundle,version_parts
from sbom import generate,macos_package
from macos_package_archive import inspect as inspect_flat_package

REPO=Path(__file__).resolve().parent.parent

def run(args,cwd=None,env=None,timeout=180,codes=(0,)):
    result=subprocess.run([str(v) for v in args],cwd=cwd or REPO,env=env,capture_output=True,timeout=timeout)
    require(len(result.stdout)+len(result.stderr)<=16<<20,"Native tool output exceeds limit")
    require(result.returncode in codes,"Native package tool failed: "+Path(str(args[0])).name)
    return result

def encode(path,value):path.write_text(json.dumps(value,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")

def build(version,arch,go="go"):
    require(platform.system()=="Darwin" and arch in ("amd64","arm64"),"Native macOS builder required")
    numeric=version_parts(version)
    environment=dict(os.environ,GOTOOLCHAIN="local",GOFLAGS="",GOOS="darwin",GOARCH=arch,CGO_ENABLED="0")
    sdk=json.loads(run([go,"env","-json","GOHOSTOS","GOHOSTARCH","GOVERSION"],env=environment).stdout)
    require(sdk["GOHOSTOS"]=="darwin" and sdk["GOHOSTARCH"]==arch,"Installer target must match the native SDK host")
    translated=run(["/usr/sbin/sysctl","-n","sysctl.proc_translated"],codes=(0,1)).stdout.strip()
    require(translated!=b"1","Translated package builders are not qualified")
    native=run(["/usr/sbin/sysctl","-n","hw.optional.arm64"],codes=(0,1)).stdout.strip()
    require(arch==("arm64" if native==b"1" else "amd64"),"Cross/emulated package builds are not qualified")
    commit=run(["git","rev-parse","HEAD"]).stdout.decode().strip()
    changed=bool(run(["git","status","--porcelain","--untracked-files=normal"]).stdout.strip())
    epoch=int(run(["git","show","-s","--format=%ct","HEAD"]).stdout)
    built=datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    identity={"version":version,"commit":commit,"sourceState":"modified" if changed else "clean","builtAt":built,"goVersion":sdk["GOVERSION"],"platform":"darwin","arch":arch}
    output=REPO/"build"/"macos-installer-checks"/arch/version
    require(not output.exists(),"Package output already exists; preserve it and use a new build workspace")
    output.mkdir(parents=True)
    stage=Path(tempfile.mkdtemp(prefix="macos-installer-stage-",dir=REPO/"build"))
    try:
        payload=stage/"payload";bundle=payload/"Applications"/BUNDLE_NAME
        resources=bundle/"Contents/Resources";binary=bundle/"Contents/MacOS/accessweaver"
        resources.mkdir(parents=True);binary.parent.mkdir(parents=True)
        names={"Version":version,"Commit":commit,"SourceState":identity["sourceState"],"BuiltAt":built}
        flags=" ".join("-X github.com/Yunushan/accessweaver/internal/buildinfo."+key+"="+value for key,value in names.items())
        run([go,"build","-mod=readonly","-trimpath","-buildvcs=false","-ldflags",flags,"-o",binary,"./cmd/accessweaver"],env=environment)
        native_info=macho_identity(binary.read_bytes(),arch)
        private=stage/"user";private.mkdir()
        child_env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":str(private),"TMPDIR":str(private),"LANG":"C","LC_ALL":"C","TZ":"UTC"}
        actual=json.loads(run([binary,"version","--json"],env=child_env,timeout=30).stdout)
        require(actual==identity,"Executed package payload differs from its build identity")
        encode(resources/"BUILD-INFO.json",identity)
        with (bundle/"Contents/Info.plist").open("wb") as stream:plistlib.dump(bundle_plist(version,native_info["minimumOSVersion"]),stream,sort_keys=True)
        for name in ("LICENSE","README.md","README.tr.md","THIRD_PARTY.md","SECURITY.md"):
            shutil.copyfile(REPO/name,resources/name)
        docs=resources/"docs";docs.mkdir()
        for name in ("MACOS_MANAGED_POLICY.md","MANAGED_CONFIGURATION.md","RELEASE_PROVENANCE.md"):
            shutil.copyfile(REPO/"docs"/name,docs/name)
        notices=resources/"licenses"
        bom=generate(binary,REPO,"./cmd/accessweaver",identity,notices,go)
        encode(resources/"SBOM.cdx.json",bom)
        for root,dirs,files in os.walk(payload):
            os.chmod(root,0o755)
            for name in files:os.chmod(Path(root)/name,0o755 if Path(root)/name==binary else 0o644)
        manifest=bundle_manifest(bundle);encode(resources/"INSTALL-MANIFEST.json",manifest);os.chmod(resources/"INSTALL-MANIFEST.json",0o644)
        verify_bundle(bundle,manifest,identity)
        components=[{"RootRelativeBundlePath":"Applications/"+BUNDLE_NAME,"BundleIsRelocatable":False,"BundleHasStrictIdentifier":True,"BundleIsVersionChecked":True,"BundleOverwriteAction":"upgrade"}]
        component_file=stage/"components.plist"
        with component_file.open("wb") as stream:plistlib.dump(components,stream)
        scripts=stage/"scripts";scripts.mkdir()
        # This first experimental package deliberately refuses every existing
        # app/receipt. Upgrade/downgrade and endpoint qualification are pending.
        preinstall=scripts/"preinstall"
        preinstall.write_text("#!/bin/sh\nset -eu\nPATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH\nLC_ALL=C; export LC_ALL\n[ \"$(/usr/bin/id -u)\" -eq 0 ] || exit 1\n[ \"${3:-}\" = / ] || exit 1\nif [ -e /Applications/AccessWeaver.app ] || [ -L /Applications/AccessWeaver.app ]; then echo 'AccessWeaver experimental package refuses an existing app.' >&2; exit 1; fi\nif /usr/sbin/pkgutil --pkg-info io.github.yunushan.accessweaver >/dev/null 2>&1; then echo 'AccessWeaver experimental package refuses an existing receipt.' >&2; exit 1; fi\nexit 0\n",encoding="utf-8")
        preinstall.chmod(0o755)
        package=output/("accessweaver-"+version+"-darwin-"+arch+"-experimental.pkg")
        pkgbuild=Path("/usr/bin/pkgbuild")
        help_result=run([pkgbuild,"--help"],env=child_env,codes=(0,1))
        require(b"--component-plist" in help_result.stdout+help_result.stderr,"Native pkgbuild component contract is unavailable")
        tool={"name":"Apple pkgbuild","sha256":digest(pkgbuild.read_bytes()),"osVersion":run(["/usr/bin/sw_vers","-productVersion"],env=child_env).stdout.decode().strip(),"osBuild":run(["/usr/bin/sw_vers","-buildVersion"],env=child_env).stdout.decode().strip()}
        run([pkgbuild,"--root",payload,"--identifier",BUNDLE_ID,"--version",version,"--install-location","/","--ownership","recommended","--component-plist",component_file,"--scripts",scripts,package],env=child_env)
        require(package.read_bytes()[:4]==b"xar!","Expected an Apple flat package")
        expanded=stage/"expanded";run(["/usr/sbin/pkgutil","--expand-full",package,expanded],env=child_env)
        installed=expanded/"Payload/Applications"/BUNDLE_NAME
        verify_bundle(installed,manifest,identity)
        extracted_scripts=expanded/"Scripts"
        require(extracted_scripts.is_dir() and {p.name for p in extracted_scripts.iterdir()}=={"preinstall"},"Unexpected package scripts")
        require((extracted_scripts/"preinstall").read_bytes()==preinstall.read_bytes(),"Actual package preinstall differs from the staged guard")
        info=expanded/"PackageInfo"
        require(info.is_file() and info.stat().st_size<1<<20,"Missing bounded native package metadata")
        import xml.etree.ElementTree as ET
        metadata=ET.fromstring(info.read_bytes())
        require(metadata.tag=="pkg-info" and metadata.get("identifier")==BUNDLE_ID and metadata.get("version")==version and metadata.get("install-location")=="/","Native package metadata differs from requested target")
        signature=run(["/usr/sbin/pkgutil","--check-signature",package],env=child_env,codes=(0,1))
        require(signature.returncode!=0 and b"no signature" in (signature.stdout+signature.stderr).lower(),"Experimental package must report no publisher signature")
        archive_inspection=inspect_flat_package(package.read_bytes(),manifest,identity)
        require(archive_inspection["preinstallSHA256"]==digest(preinstall.read_bytes()),"Independent package script inspection differs")
        package_bom=macos_package(package,bom,manifest,tool)
        encode(Path(str(package)+".cdx.json"),package_bom)
        validator=stage/"sbom-schema"
        run([go,"-C",REPO/"scripts/sbom-tools","build","-mod=readonly","-trimpath","-o",validator,"."],env=environment)
        run([validator,"--schemas",REPO/"scripts/sbom/schema",resources/"SBOM.cdx.json",str(package)+".cdx.json"],env=child_env)
        encode(output/"INSTALL-MANIFEST.json",manifest)
        encode(output/"BUILD-INFO.json",identity)
        encode(output/"payload-SBOM.cdx.json",bom)
        report={"schemaVersion":1,"sourceCommit":commit,"sourceState":identity["sourceState"],"target":"darwin/"+arch,"payloadBuild":identity,"payloadSHA256":digest(binary.read_bytes()),"macho":native_info,"packageFile":package.name,"packageSHA256":digest(package.read_bytes()),"packageBytes":package.stat().st_size,"bundleManifestSHA256":digest((resources/"INSTALL-MANIFEST.json").read_bytes()),"bundleInfoSHA256":digest((bundle/"Contents/Info.plist").read_bytes()),"preinstallSHA256":digest(preinstall.read_bytes()),"pkgbuild":tool,"nativePayloadIdentityVerified":True,"actualExpandedPayloadVerified":True,"archiveInspection":archive_inspection,"bundleRelocationDisabled":True,"unsigned":True,"publisherSignatureVerified":False,"notarized":False,"experimentalCleanInstallOnly":True,"installationExecuted":False,"upgradeQualified":False,"downgradeQualified":False,"finderInteractionQualified":False,"managedEndpointQualified":False,"productionQualificationComplete":False}
        encode(output/"compiler-artifact.json",report)
        return report
    finally:
        require(stage.resolve().parent==(REPO/"build").resolve() and stage.name.startswith("macos-installer-stage-"),"Unsafe package staging cleanup")
        shutil.rmtree(stage)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--version",default="0.1.0-alpha");parser.add_argument("--architecture",choices=("amd64","arm64"),required=True);parser.add_argument("--go",default="go")
    args=parser.parse_args();report=build(args.version,args.architecture,args.go)
    print(json.dumps({"sourceCommit":report["sourceCommit"],"target":report["target"],"actualExpandedPayloadVerified":True,"productionQualificationComplete":False}))

if __name__=="__main__":main()
