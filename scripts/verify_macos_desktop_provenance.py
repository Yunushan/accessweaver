#!/usr/bin/env python3
"""Authenticate all public-desktop subjects before parsing; never execute targets."""
import argparse
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

from macos_installer import BUNDLE_NAME,MAX_BYTES,digest,require
from macos_desktop import BINARY,component_name,record_name,validate_record,inspect_component,package_sbom
from macos_launcher import archive_name,inspect_launcher
from macos_product import component_inputs,product_name,product_members,inspect_product,product_sbom,expanded_inventory
from macos_package_archive import flat_members,cpio,inflate
from sbom import validate,prop_map
from verify_macos_deployment_provenance import VERSIONS,subjects as core_subjects,validate_packages,copy_subject,check_rejections as shared_rejections
from verify_release_provenance import BUNDLE_NAME as PROVENANCE_BUNDLE,REPOSITORY,validate_identity,verification_command as portable_command
from verify_release_rebuild import snapshot

WORKFLOW=REPOSITORY+"/.github/workflows/macos-desktop.yml"


def subjects(arch):
    require(arch in ("amd64","arm64"),"Expected native desktop architecture")
    result={"desktop-lifecycle-artifact.json":Path("desktop-lifecycle-artifact.json")}
    for name,(version,original) in core_subjects(arch).items():
        if version is not None:result[name]=Path(version)/original
    for version in VERSIONS:
        name=archive_name(arch,None if version==VERSIONS[-1] else version);result[name]=Path(name)
        for role in ("metadata","application"):
            name=component_name(version,arch,role)
            result[name]=Path("desktop")/version/name;result[name+".cdx.json"]=Path("desktop")/version/(name+".cdx.json")
        for original in ("BUILD-INFO.json","DESKTOP-RECORD.json","compiler-artifact.json","metadata-SCRIPT-MANIFEST.json","application-SCRIPT-MANIFEST.json","metadata-helper-SBOM.cdx.json","application-helper-SBOM.cdx.json"):
            result["desktop-"+version+"-"+original]=Path("desktop")/version/original
        name=product_name(version,arch)
        result[name]=Path("product")/version/name;result[name+".cdx.json"]=Path("product")/version/(name+".cdx.json")
        for original in ("DISTRIBUTION.xml","compiler-artifact.json"):result["product-"+version+"-"+original]=Path("product")/version/original
    require(len(result)==49,"Desktop known subject extent changed")
    return result


def verification_command(path,bundle,commit,ref,gh="gh"):
    command=portable_command(path,bundle,commit,ref,gh);command[command.index("--signer-workflow")+1]=WORKFLOW;return command


def authenticate(path,bundle,commit,ref,gh):
    try:subprocess.run(verification_command(path,bundle,commit,ref,gh),check=True,capture_output=True,timeout=120)
    except subprocess.CalledProcessError as error:raise ValueError("Desktop cryptographic provenance verification failed") from error


def check_rejections(path,bundle,commit,ref,gh):
    return shared_rejections(path,bundle,commit,ref,gh,command_builder=verification_command)


def check_metadata(metadata,identity,main):
    settings={v["Key"]:v["Value"] for v in metadata["Settings"]}
    require(metadata.get("GoVersion")==identity["goVersion"] and metadata.get("Path")=="github.com/Yunushan/accessweaver/cmd/"+main and settings.get("GOOS")=="darwin" and settings.get("GOARCH")==identity["arch"] and settings.get("CGO_ENABLED")=="0" and settings.get("-trimpath")=="true" and "-ldflags" not in settings,"Desktop native compiled metadata differs")


def validate_contents(root,commit,arch):
    read=lambda name:json.loads((root/name).read_text(encoding="utf-8"))
    cores,core_bindings,_=validate_packages(root,commit,arch);records={};public_bindings={};outputs=[];identities={}
    for version in VERSIONS:
        identity=read(version+"-BUILD-INFO.json");identities[version]=identity
        prefix="desktop-"+version+"-";require(read(prefix+"BUILD-INFO.json")==identity,"Public/core build identities differ")
        encoded=(root/(prefix+"DESKTOP-RECORD.json")).read_bytes();record=validate_record(encoded,identity);records[version]=digest(encoded)
        report=read(prefix+"compiler-artifact.json")
        archive=archive_name(arch,None if version==VERSIONS[-1] else version);archive_bytes=(root/archive).read_bytes();launcher=inspect_launcher(archive_bytes,identity)
        require(report.get("schemaVersion")==1 and report.get("sourceCommit")==commit and report.get("build")==identity and report.get("recordFile")==record_name(encoded) and report.get("recordSHA256")==digest(encoded) and report.get("launcherArchiveSHA256")==digest(archive_bytes) and report.get("launcherBinarySHA256")==launcher["binarySHA256"],"Desktop construction/launcher subjects differ")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as source:
            require(source.read("SBOM.cdx.json")==record["compiledSBOM"].encode("utf-8"),"Desktop compiled graph raw bytes differ from launcher archive")
        require(all(report.get(k) is True for k in ("nativeBundleConstructionVerified","actualExpandedPayloadAndScriptsVerified","allCompiledAndPackageGraphsSchemaValidated","metadataOutsideAppVerified","packagePayloadWritesAreOSInstallerOnly","unsigned")),"Desktop construction incomplete")
        require(all(report.get(k) is False for k in ("installationExecuted","launchServicesQualified","publisherSignatureVerified","notarized","productUninstallQualified","managedEndpointQualified","productionQualificationComplete")),"Unqualified desktop construction scope changed")
        items=report["components"];require(type(items) is list and [c.get("component") for c in items]==["metadata","application"],"Desktop component inventory differs")
        public_bindings[version]={};inspections=[]
        for role,item in zip(("metadata","application"),items):
            name=component_name(version,arch,role);raw=(root/name).read_bytes();scripts=read(prefix+role+"-SCRIPT-MANIFEST.json")
            inspected=inspect_component(raw,encoded,identity,role,scripts,item["scriptArchiveOwner"])
            require(item.get("file")==name and item.get("bytes")==len(raw) and item.get("sha256")==digest(raw) and item.get("archiveInspection")==inspected and item.get("helperSHA256")==inspected["helperSHA256"],"Actual desktop component differs from producer inspection")
            check_metadata(item["helperBuildMetadata"],identity,"accessweaver-desktop-installer")
            stamps={"Version":version,"Commit":commit,"SourceState":"clean","BuiltAt":identity["builtAt"]}
            flags=["-X github.com/Yunushan/accessweaver/internal/buildinfo."+k+"="+v for k,v in stamps.items()]
            flags.extend("-X github.com/Yunushan/accessweaver/internal/packageupgrade."+k+"="+v for k,v in {"sealedDesktopRecordSHA256":digest(encoded),"sealedDesktopComponent":role}.items())
            require(item.get("helperLinkerFlags")==" ".join(flags),"Desktop compiled component/seal invocation differs")
            members=flat_members(raw);payload=cpio(inflate(members["Payload"],MAX_BYTES,31));script_data=cpio(inflate(members["Scripts"],32<<20,31))
            helper=script_data["preinstall"]["data"];helper_graph=read(prefix+role+"-helper-SBOM.cdx.json");validate(helper_graph,helper,identity)
            graph=json.loads(record["compiledSBOM"]) if role=="application" else None
            payload_records=[dict(f,path=BUNDLE_NAME+"/"+f["path"]) for f in record["manifest"]["files"]] if role=="application" else [{"path":record_name(encoded),"bytes":len(encoded),"sha256":digest(encoded),"mode":"0644"}]
            bom=read(name+".cdx.json");validate(bom,raw,identity)
            require(bom==package_sbom(raw,identity,helper_graph,graph,payload_records,scripts,report["pkgbuild"]),"Desktop actual payload/script compiled graphs differ")
            for c in [bom["metadata"]["component"]]+bom["components"]:
                for evidence in json.loads(prop_map(c).get("accessweaver:license-evidence","[]")):
                    path=evidence["path"];require(path in script_data and digest(script_data[path]["data"])==evidence["sha256"],"Desktop compiled component notice differs")
            if role=="application":require(digest(payload[BUNDLE_NAME+"/Contents/MacOS/"+BINARY]["data"])==launcher["binarySHA256"],"Actual public launcher and standalone archive differ")
            public_bindings[version][role]=digest(raw);inspections.append(inspected)
        product=product_name(version,arch);product_raw=(root/product).read_bytes();product_report=read("product-"+version+"-compiler-artifact.json")
        inputs=component_inputs(version,arch,encoded);input_packages={name:(root/name).read_bytes() for _,_,name in inputs}
        product_inspection=inspect_product(product_raw,version,arch,inputs,input_packages)
        require(product_report.get("schemaVersion")==1 and product_report.get("sourceCommit")==commit and product_report.get("build")==identity and product_report.get("productFile")==product and product_report.get("productBytes")==len(product_raw) and product_report.get("productSHA256")==digest(product_raw) and product_report.get("archiveInspection")==product_inspection,"Actual product construction differs")
        require(product_report.get("componentInspections")==dict(core=cores[VERSIONS.index(version)],**{i["component"]:i for i in inspections}),"Product component construction differs")
        require(all(product_report.get(k) is True for k in ("actualExpandedPayloadAndScriptsVerified","productGraphSchemaValidated","unsigned")),"Product construction incomplete")
        expected_files,_=expanded_inventory((root/("product-"+version+"-DISTRIBUTION.xml")).read_bytes(),input_packages)
        expanded=product_report.get("expandedInspection",{});require(type(expanded.get("files")) is int and expanded["files"]==len(expected_files) and all(expanded.get(k) is True for k in ("payloadAndScriptDirectoryModesVerified","payloadAndScriptFileModesVerified","allExpandedBytesVerified")) and expanded.get("targetExecutionPerformed") is False,"Native expanded product inspection incomplete")
        require(all(product_report.get(k) is False for k in ("installationExecuted","singleProductLifecycleQualified","publisherSignatureVerified","notarized","productUninstallQualified","managedEndpointQualified","productionQualificationComplete")),"Unqualified product construction scope changed")
        tool=product_report["productbuild"];core_tool=read(version+"-compiler-artifact.json")["pkgbuild"]
        require(set(tool)=={"sha256","osVersion","osBuild"} and re.fullmatch("[a-f0-9]{64}",tool["sha256"]) is not None and all(tool[k]==core_tool[k] for k in ("osVersion","osBuild")),"Product builder observation differs")
        require((root/("product-"+version+"-DISTRIBUTION.xml")).read_bytes()==product_members(product_raw,list(input_packages))["Distribution"],"Retained product distribution bytes differ")
        input_graphs={role:read(name+".cdx.json") for role,_,name in inputs};product_graph=read(product+".cdx.json");validate(product_graph,product_raw,identity)
        require(product_graph==product_sbom(product_raw,identity,inputs,input_packages,input_graphs,tool),"Product compiled/input/member graph differs")
        outputs.append({"version":version,"launcher":launcher,"components":inspections,"recordSHA256":digest(encoded),"productArchiveConstruction":product_inspection})
    life=read("desktop-lifecycle-artifact.json")
    require(life.get("schemaVersion")==1 and life.get("sourceCommit")==commit and life.get("target")=="darwin/"+arch and life.get("stage")=="deactivation-and-owned-cleanup" and life.get("failureType") is None and life.get("failureSourceLine") is None and re.fullmatch("[1-9][0-9]{0,19}",str(life.get("runID",""))) is not None,"Desktop native lifecycle identity/completion differs")
    require(life.get("corePackageSHA256")=={v:b["packageSHA256"] for v,b in core_bindings.items()} and life.get("desktopRecordSHA256")==records and life.get("desktopPackageSHA256")==public_bindings,"Desktop native lifecycle is not bound to actual subjects")
    require(all(life.get(k) is True for k in ("passed","actualOrderedComponentsExecuted","publicAppAndProtectedRegistrationsVerified","coreUpgradeWithPublicEntryVerified","actualUserDataAndContainerProtectionPreserved","ownedFixturesRemoved")),"Actual public component lifecycle incomplete")
    require(all(life.get(k) is False for k in ("installedProductCodeExecutedAsRoot","publisherSignatureVerified","notarized","finderInteractiveQualificationComplete","singleProductDistributionQualified","productUninstallQualified","managedEndpointQualified","productionQualificationComplete")),"Unqualified public component lifecycle scope changed")
    old,new=VERSIONS
    expected=[("core-clean-install",old,"core",True),("app-without-metadata-refused",old,"application",False),("metadata-clean-install",old,"metadata",True),("public-app-clean-install",old,"application",True),("launchservices-live-core-upgrade-refused",new,"core",False),("core-upgrade-with-public-v1",new,"core",True),("metadata-upgrade",new,"metadata",True),("public-app-upgrade",new,"application",True),("metadata-equal-reinstall",new,"metadata",True),("public-app-equal-reinstall",new,"application",True),("older-metadata-refused",old,"metadata",False),("older-public-app-refused",old,"application",False),("changed-public-info-core-refused",new,"core",False),("changed-public-info-desktop-refused",new,"application",False),("changed-registration-core-refused",new,"core",False),("changed-registration-desktop-refused",new,"metadata",False),("public-alias-core-refused",new,"core",False),("public-alias-app-refused",new,"application",False),("registration-alias-core-refused",new,"core",False),("registration-alias-metadata-refused",new,"metadata",False),("restored-public-reinstall",new,"application",True)]
    ops=life.get("operations");require(type(ops) is list and len(ops)==len(expected),"Public component operation extent differs")
    for item,(name,version,role,success) in zip(ops,expected):
        require(item.get("name")==name and item.get("version")==version and item.get("component")==role and item.get("passed") is True and type(item.get("exitCode")) is int and (item["exitCode"]==0 if success else 1<=item["exitCode"]<=255),"Public component operation result differs")
        require(item.get("nativeReceiptVerified") is success and item.get("refusedStatePreserved") is (not success) and type(item.get("elapsedMilliseconds")) is int and 0<=item["elapsedMilliseconds"]<=180000,"Public component preservation/receipt/timing differs")
        require(item.get("packageSHA256")== (core_bindings[version]["packageSHA256"] if role=="core" else public_bindings[version][role]),"Native component operation subject differs")
    choices=life.get("selections");names=["initial-active","core-upgraded-public-v1","public-upgraded","restored-active","inactive-refused"]
    require(type(choices) is list and [v.get("name") for v in choices]==names,"Public app active selection coverage differs")
    for c in choices:
        expected_build=identities[old] if c["name"]=="initial-active" else None if c["name"]=="inactive-refused" else identities[new]
        require(c.get("expectedCoreBuild")==expected_build and c.get("installationAndUserDataPreserved") is True and c.get("passed") is True and type(c.get("exitCode")) is int and (c["exitCode"]==0 if expected_build is not None else 1<=c["exitCode"]<=255) and type(c.get("elapsedMilliseconds")) is int and 0<=c["elapsedMilliseconds"]<=30000,"Public app selection/refusal differs")
    launched=life.get("launchServices",{});require(all(launched.get(k) is True for k in ("defaultNoArgumentLaunch","kernelImageAndOrdinaryOwnerVerified","dashboardHTTPVerified","privateProfileLockVerified","authenticatedSavedProfileVerified","installerRefusalWhileServingVerified","controllerRemainedRunning","cleanShutdownVerified","passed")) and type(launched.get("elapsedMilliseconds")) is int and 0<=launched["elapsedMilliseconds"]<=300000,"Actual LaunchServices controller acceptance incomplete")
    deactivated=life.get("deactivation",{});require(deactivated.get("generation")==3 and deactivated.get("state")=="inactive" and deactivated.get("operationRecordPublished") is True and deactivated.get("exitCode")==0 and type(deactivated.get("elapsedMilliseconds")) is int and 0<=deactivated["elapsedMilliseconds"]<=60000,"Public/core deactivation fence differs")
    return {"lifecycleRunID":str(life["runID"]),"corePackages":cores,"desktop":outputs,"actualInstallerOperations":21,"actualCoreDeactivationOperations":1,"publicAppSelectionCases":5,"launchServicesDefaultControllerVerified":True,"productArchiveConstructionVerified":True,"singleProductLifecycleQualified":False,"finderInteractiveQualificationComplete":False,"singleProductDistributionQualified":False,"publisherSignatureVerified":False,"productionQualificationComplete":False}


def limit(name):return 64<<20 if name.endswith(".pkg") else 16<<20 if name.endswith(".zip") or name==PROVENANCE_BUNDLE else 8<<20


def stage(build_root,destination,commit,ref,arch,run_id=None):
    validate_identity(commit,ref);mapping=subjects(arch);destination.mkdir(mode=0o700)
    for name,relative in mapping.items():copy_subject(build_root/relative,destination/name,limit(name))
    result=validate_contents(destination,commit,arch)
    if run_id is not None:require(result["lifecycleRunID"]==run_id,"Native desktop producer run differs")
    return {"producerValidation":result,"sourceCommit":commit,"cryptographicAuthenticationPerformed":False}


def verify(directory,commit,ref,arch,gh="gh",rejections=False,run_id=None):
    validate_identity(commit,ref);names=set(subjects(arch))
    with tempfile.TemporaryDirectory(prefix="accessweaver-desktop-verify-") as temporary:
        root=Path(temporary);present=snapshot(directory,root,len(names)+1)
        require(present==names|{PROVENANCE_BUNDLE},"Desktop input inventory differs")
        for name in present:require((root/name).stat().st_size<=limit(name),"Desktop input exceeds budget")
        for name in sorted(names):authenticate(root/name,root/PROVENANCE_BUNDLE,commit,ref,gh)
        result=validate_contents(root,commit,arch)
        if run_id is not None:require(result["lifecycleRunID"]==run_id,"Authenticated desktop native run differs")
        negative=check_rejections(root/next(n for n in sorted(names) if n.endswith(".pkg")),root/PROVENANCE_BUNDLE,commit,ref,gh) if rejections else None
        return {"schemaVersion":1,"repository":REPOSITORY,"workflow":WORKFLOW,"sourceCommit":commit,"sourceRef":ref,"target":"darwin/"+arch,"subjectsVerified":len(names),"subjects":[{"file":n,"sha256":digest((root/n).read_bytes())} for n in sorted(names)],"authenticatedBeforeParsing":True,"hostedRunnerRequired":True,"desktop":result,"rejectionChecks":negative,"localTargetExecution":False,"publisherSignatureVerified":False,"notarized":False,"productionQualificationComplete":False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("directory",type=Path);p.add_argument("--source-commit",required=True);p.add_argument("--source-ref",required=True);p.add_argument("--architecture",choices=("amd64","arm64"),required=True);p.add_argument("--run-id");p.add_argument("--gh",default="gh");p.add_argument("--check-rejections",action="store_true");p.add_argument("--stage-build-root",type=Path);a=p.parse_args()
    try:result=stage(a.stage_build_root,a.directory,a.source_commit,a.source_ref,a.architecture,a.run_id) if a.stage_build_root else verify(a.directory,a.source_commit,a.source_ref,a.architecture,a.gh,a.check_rejections,a.run_id)
    except Exception as e:raise SystemExit("Desktop provenance refused: "+type(e).__name__)
    print(json.dumps(result,indent=2))

if __name__=="__main__":main()
