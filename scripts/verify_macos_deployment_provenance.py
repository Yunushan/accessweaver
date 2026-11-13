#!/usr/bin/env python3
"""Authenticate every known versioned-package subject before parsing; never execute targets."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from macos_deployment import BUNDLE_NAME,MANIFEST,PAYLOAD_SBOM,inspect_deployment,deployment_sbom
from macos_installer import MAX_BYTES,require,digest
from macos_launcher import archive_name,inspect_launcher
from macos_package_archive import flat_members,cpio,inflate
from sbom import validate,prop_map
from verify_release_provenance import BUNDLE_NAME as PROVENANCE_BUNDLE,REPOSITORY,validate_identity,verification_command as portable_command
from verify_release_rebuild import snapshot

VERSIONS=("0.1.0-alpha","0.1.1-alpha")
WORKFLOW=REPOSITORY+"/.github/workflows/macos-deployment.yml"


def subjects(arch):
    require(arch in ("amd64","arm64"),"Expected a native deployment architecture")
    files={"lifecycle-artifact.json":(None,"lifecycle-artifact.json"),archive_name(arch):(None,archive_name(arch))}
    for version in VERSIONS:
        package="accessweaver-"+version+"-darwin-"+arch+"-deployment-experimental.pkg"
        files[package]=(version,package);files[package+".cdx.json"]=(version,package+".cdx.json")
        for name in ("BUILD-INFO.json","INSTALL-MANIFEST.json","SCRIPT-MANIFEST.json","payload-SBOM.cdx.json","helper-SBOM.cdx.json","compiler-artifact.json"):
            files[version+"-"+name]=(version,name)
    return files


def verification_command(path,bundle,commit,ref,gh="gh"):
    command=portable_command(path,bundle,commit,ref,gh);command[command.index("--signer-workflow")+1]=WORKFLOW
    return command


def authenticate(path,bundle,commit,ref,gh):
    try:subprocess.run(verification_command(path,bundle,commit,ref,gh),check=True,capture_output=True,timeout=120)
    except subprocess.CalledProcessError as error:raise ValueError("Deployment cryptographic provenance verification failed") from error


def validate_packages(root,commit,arch):
    read=lambda name:json.loads((root/name).read_text(encoding="utf-8"))
    outputs=[];package_bindings={}
    for version in VERSIONS:
        package="accessweaver-"+version+"-darwin-"+arch+"-deployment-experimental.pkg"
        identity=read(version+"-BUILD-INFO.json");report=read(version+"-compiler-artifact.json")
        require(set(identity)=={"version","commit","sourceState","builtAt","goVersion","platform","arch"} and all(identity.get(k)==v for k,v in {"version":version,"commit":commit,"sourceState":"clean","goVersion":"go1.27.4","platform":"darwin","arch":arch}.items()),"Deployment build identity differs")
        stamp=datetime.datetime.strptime(identity["builtAt"],"%Y-%m-%dT%H:%M:%SZ");require(stamp.strftime("%Y-%m-%dT%H:%M:%SZ")==identity["builtAt"],"Deployment build timestamp differs")
        encoded=(root/(version+"-INSTALL-MANIFEST.json")).read_bytes();manifest=json.loads(encoded);scripts=read(version+"-SCRIPT-MANIFEST.json");binary=(root/package).read_bytes()
        inspected=inspect_deployment(binary,encoded,identity,scripts)
        require(report.get("schemaVersion")==1 and report.get("sourceCommit")==commit and report.get("sourceState")=="clean" and report.get("target")=="darwin/"+arch and report.get("payloadBuild")==identity and report.get("helperBuild")==identity,"Deployment compiler/helper identity differs")
        require(report.get("packageFile")==package and report.get("packageBytes")==len(binary) and report.get("archiveInspection")==inspected,"Deployment actual package inspection differs")
        for key in ("packageSHA256","payloadSHA256","manifestSHA256","helperSHA256","payloadSBOMSHA256"):require(report.get(key)==inspected[key],"Deployment subject differs")
        require(report.get("helperMachO")==inspected["helperMachO"] and all(report.get(k) is True for k in ("packageScriptsIntegrated","actualExpandedPayloadAndScriptsVerified","detachedManifestOutsideAppVerified","detachedPayloadSBOMOutsideAppVerified","unsigned")),"Deployment construction incomplete")
        for key in ("publisherSignatureVerified","notarized","installationExecuted","upgradeQualified","productUninstallQualified","launcherIntegrated","managedEndpointQualified","productionQualificationComplete"):require(report.get(key) is False,"Unqualified deployment construction scope changed")
        metadata=report["helperBuildMetadata"];settings={v["Key"]:v["Value"] for v in metadata["Settings"]}
        names={"Version":version,"Commit":commit,"SourceState":"clean","BuiltAt":identity["builtAt"]}
        flags=["-X github.com/Yunushan/accessweaver/internal/buildinfo."+k+"="+v for k,v in names.items()]
        flags.extend("-X github.com/Yunushan/accessweaver/internal/packageupgrade."+k+"="+v for k,v in {"sealedVersion":version,"sealedManifestSHA256":inspected["manifestSHA256"],"sealedPayloadSHA256":inspected["payloadSHA256"]}.items())
        require(metadata.get("GoVersion")==identity["goVersion"] and metadata.get("Path")=="github.com/Yunushan/accessweaver/cmd/accessweaver-installer" and settings.get("GOOS")=="darwin" and settings.get("GOARCH")==arch and settings.get("CGO_ENABLED")=="0" and settings.get("-trimpath")=="true" and "-ldflags" not in settings and report.get("helperLinkerFlags")==" ".join(flags),"Authenticated helper build metadata/seals differ")
        members=flat_members(binary);payload=cpio(inflate(members["Payload"],MAX_BYTES,31));script_data=cpio(inflate(members["Scripts"],32<<20,31))
        core=payload[BUNDLE_NAME+"/Contents/MacOS/accessweaver"]["data"];helper=script_data["preinstall"]["data"]
        payload_bom=read(version+"-payload-SBOM.cdx.json");helper_bom=read(version+"-helper-SBOM.cdx.json");bom=read(package+".cdx.json")
        require(payload[PAYLOAD_SBOM]["data"]==(root/(version+"-payload-SBOM.cdx.json")).read_bytes(),"Actual payload SBOM differs")
        validate(payload_bom,core,identity);validate(helper_bom,helper,identity);validate(bom,binary,identity)
        require(bom==deployment_sbom(binary,(root/(version+"-payload-SBOM.cdx.json")).read_bytes(),helper_bom,encoded,scripts,report["pkgbuild"],core,helper),"Deployment compiled/file graph differs")
        for document,available,prefix in ((payload_bom,payload,BUNDLE_NAME+"/Contents/Resources/"),(helper_bom,script_data,"")):
            for component in [document["metadata"]["component"]]+document["components"]:
                for evidence in json.loads(prop_map(component).get("accessweaver:license-evidence","[]")):
                    entry=available.get(prefix+evidence["path"]);require(entry is not None and not entry["directory"] and digest(entry["data"])==evidence["sha256"],"Packaged compiled-component notice differs")
        package_bindings[version]={"file":package,"bytes":len(binary),**{key:inspected[key] for key in ("packageSHA256","payloadSHA256","manifestSHA256","helperSHA256","payloadSBOMSHA256")}}
        outputs.append(inspected)
    return outputs,package_bindings,identity


def validate_managed_detection(cases, bindings, *, writer_lease_required=False):
    expected = (
        ("absent", VERSIONS[0], False, False),
        ("initial-active", VERSIONS[0], True, False),
        ("descriptor-hint", VERSIONS[0], False, False),
        ("superseded", VERSIONS[0], False, False),
        ("upgraded-active", VERSIONS[1], True, True),
        ("reinstalled-active", VERSIONS[1], True, False),
        ("changed-active", VERSIONS[1], False, False),
        ("restored-active", VERSIONS[1], True, False),
        ("inactive", VERSIONS[1], False, False),
    )
    if writer_lease_required:
        expected = expected[:2] + (
            ("writer-lease-held", VERSIONS[0], False, False),
            ("writer-lease-released", VERSIONS[0], True, False),
        ) + expected[2:]
    require(isinstance(cases, list) and len(cases) == len(expected), "Incomplete deployment detection coverage")
    for case, (name, version, detected, elevated) in zip(cases, expected):
        require(isinstance(case, dict) and case.keys() == {"name", "version", "detected", "elevated", "helperSHA256", "statePreserved"}
                and case["name"] == name and case["version"] == version
                and case["detected"] is detected and case["elevated"] is elevated
                and case["helperSHA256"] == bindings[version]["helperSHA256"]
                and case["statePreserved"] is True, "Deployment detection case differs")
    return {"managedDetectionChecksVerified": len(expected)}


def validate_contents(root,commit,arch):
    read=lambda name:json.loads((root/name).read_text(encoding="utf-8"))
    outputs,package_bindings,identity=validate_packages(root,commit,arch)
    launcher=inspect_launcher((root/archive_name(arch)).read_bytes(),identity)
    life=read("lifecycle-artifact.json")
    require(type(life.get("schemaVersion")) is int and life["schemaVersion"] in (1,2,3) and life.get("sourceCommit")==commit and life.get("target")=="darwin/"+arch and life.get("stage")=="deactivation-and-owned-cleanup" and life.get("failureType") is None and life.get("failureSourceLine") is None,"Deployment lifecycle identity/completion differs")
    require(life.get("packages")==package_bindings and re.fullmatch("[1-9][0-9]{0,19}",str(life.get("runID",""))) is not None,"Native lifecycle is not bound to the actual package subjects/run")
    for key in ("passed","packageScriptsIntegrated","actualApplePackageUpgradeExecuted","actualUserProfilePreservationVerified","retainedPriorCopiesVerified","ownedFixturesRemoved","detachedManifestSealingVerified","detachedPayloadSBOMSealingVerified"):require(life.get(key) is True,"Actual deployment lifecycle did not pass")
    for key in ("installedCodeExecutedAsRoot","publicLauncherIntegrated","runtimeLeaseQualified","publisherSignatureVerified","notarized","productUninstallQualified","managedEndpointQualified","abruptTerminationQualified","rebootOrPowerLossQualified","productionQualificationComplete"):require(life.get(key) is False,"Unqualified deployment lifecycle scope changed")
    detection = {}
    if life["schemaVersion"] >= 2:
        detection = validate_managed_detection(life.get("managedDetectionCases"), package_bindings,
                                               writer_lease_required=life["schemaVersion"] >= 3)
    lease_cases=life.get("runtimeLeaseCases",[])
    require(life.get("installedControllerLeaseRefusalVerified") is True and len(lease_cases)==4 and [c.get("kind") for c in lease_cases]==["direct","inherited","alias","launcher"],"Installed controller lease coverage differs")
    for case in lease_cases:
        require(type(case.get("installerExitCode")) is int and 1<=case["installerExitCode"]<=255 and type(case.get("elapsedMilliseconds")) is int and 0<=case["elapsedMilliseconds"]<=180000,"Runtime lease refusal exit/timing differs")
        require(all(case.get(k) is True for k in ("servingControllerVerified","activeRecordAndReceiptBytesPreserved","actualProfilePreserved","controllerRemainedRunning","passed")) and case.get("parentInheritedDescriptorClosed") is (case["kind"]=="inherited"),"Runtime lease did not preserve the serving controller")
    require(life.get("activeCopyLauncherVerified") is True and life.get("launcherCandidate")==launcher,"Actual launcher candidate differs")
    launcher_cases=life.get("launcherCases",[]);names=["absent-refused","elevated-refused","descriptor-hint-refused","initial-active","upgraded-active","inactive-refused"]
    require(type(launcher_cases) is list and [c.get("name") for c in launcher_cases]==names,"Launcher selection/refusal coverage differs")
    for case in launcher_cases:
        expected_build=read(VERSIONS[0]+"-BUILD-INFO.json") if case["name"]=="initial-active" else read(VERSIONS[1]+"-BUILD-INFO.json") if case["name"]=="upgraded-active" else None
        require(case.get("expectedCoreBuild")==expected_build and type(case.get("exitCode")) is int and (case["exitCode"]==0 if expected_build is not None else 1<=case["exitCode"]<=255),"Launcher selected an unexpected core/refusal")
        require(type(case.get("elapsedMilliseconds")) is int and 0<=case["elapsedMilliseconds"]<=30000 and all(case.get(k) is True for k in ("activeRecordAndReceiptBytesPreserved","actualUserDataPreserved","passed")),"Launcher selection mutated protected/user data")
    expected=[("clean-install",VERSIONS[0],1),("upgrade",VERSIONS[1],2),("same-version-reinstall",VERSIONS[1],3),("older-version-refused",VERSIONS[0],None),("changed-detached-sbom-refused",VERSIONS[1],None),("changed-detached-manifest-refused",VERSIONS[1],None),("changed-staging-refused",VERSIONS[1],None),("restored-reinstall",VERSIONS[1],4),("deactivate-for-cleanup",VERSIONS[1],5)]
    operations=life.get("operations",[]);require(len(operations)==len(expected),"Deployment lifecycle operation extent differs")
    slots=set()
    for op,(name,version,generation) in zip(operations,expected):
        require(op.get("operation")==name and op.get("version")==version and op.get("passed") is True and type(op.get("elapsedMilliseconds")) is int and 0<=op["elapsedMilliseconds"]<=180000,"Deployment operation differs")
        if generation is None:require(type(op.get("exitCode")) is int and 1<=op["exitCode"]<=255 and op.get("activeRecordAndReceiptBytesPreserved") is True,"Refused package changed deployment state")
        else:
            require(op.get("exitCode")==0 and op.get("generation")==generation,"Actual package activation generation differs")
            if generation<5:
                require(op.get("activeIdentity")=={"version":version,"manifestSHA256":package_bindings[version]["manifestSHA256"],"payloadSHA256":package_bindings[version]["payloadSHA256"]},"Activated compiled seal differs from actual package")
                require(op.get("actualUnelevatedRuntimeVerified") is True and op.get("retainedPriorCopiesVerified") is True and re.fullmatch("[a-f0-9]{32}",op.get("slotID","")) is not None and op["slotID"] not in slots,"Activated package copy identity differs");slots.add(op["slotID"])
    return {"packages":outputs,**detection,"lifecycleRunID":str(life["runID"]),"actualApplePackageOperations":13,"launcher":launcher,"retainedIndependentCopies":4,"publisherSignatureVerified":False,"productionQualificationComplete":False}


def copy_subject(source,destination,limit):
    before=source.lstat();identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=limit and not getattr(before,"st_file_attributes",0)&0x400,"Expected a bounded regular build subject")
    fd=os.open(source,os.O_RDONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0))
    try:
        require(identity(os.fstat(fd))==identity(before),"Build subject changed before staging")
        with destination.open("xb") as stream:
            copied=0
            while True:
                block=os.read(fd,min(1<<20,before.st_size+1-copied))
                if not block:break
                copied+=len(block);require(copied<=before.st_size,"Build subject grew during staging");stream.write(block)
        require(copied==before.st_size and identity(os.fstat(fd))==identity(before),"Build subject changed during staging")
    finally:os.close(fd)


def stage(build_root,destination,commit,ref,arch,run_id=None):
    validate_identity(commit,ref);mapping=subjects(arch);destination.mkdir(mode=0o700)
    for name,(version,original) in mapping.items():copy_subject(build_root/version/original if version else build_root/original,destination/name,64<<20 if name.endswith(".pkg") else 16<<20 if name.endswith(".zip") else 8<<20)
    result=validate_contents(destination,commit,arch)
    if run_id is not None:require(result.get("lifecycleRunID")==run_id,"Native producer run differs from caller expectation")
    return {"producerValidation":result,"cryptographicAuthenticationPerformed":False,"sourceCommit":commit,"target":"darwin/"+arch}


def check_rejections(path,bundle,commit,ref,gh,command_builder=None):
    base=(command_builder or verification_command)(path,bundle,commit,ref,gh)
    def run(command,success):require((subprocess.run(command,capture_output=True,timeout=120).returncode==0)==success,"Unexpected deployment provenance rejection outcome")
    run(base,True);rejected=[]
    for flag,value in (("--source-digest","0"*len(commit)),("--source-ref","refs/tags/invalid-deployment-probe"),("--signer-workflow",REPOSITORY+"/.github/workflows/ci.yml"),("--repo","octocat/Hello-World")):
        command=list(base);command[command.index(flag)+1]=value;run(command,False);rejected.append(flag)
    with tempfile.TemporaryDirectory(prefix="accessweaver-deployment-rejection-") as temp:
        changed=Path(temp)/path.name;changed.write_bytes(path.read_bytes()+b"changed");command=list(base);command[3]=str(changed);run(command,False);rejected.append("changed-subject-digest")
    run(base,True)
    return {"rejected":rejected,"realBundleVerifiedBeforeAndAfter":True}


def verify(directory,commit,ref,arch,gh="gh",rejections=False,run_id=None):
    validate_identity(commit,ref);names=set(subjects(arch))
    with tempfile.TemporaryDirectory(prefix="accessweaver-deployment-verify-") as temporary:
        root=Path(temporary);present=snapshot(directory,root,len(names)+1)
        require(present==names|{PROVENANCE_BUNDLE},"Deployment input inventory differs")
        for name in present:require((root/name).stat().st_size<=(64<<20 if name.endswith(".pkg") else 16<<20 if name==PROVENANCE_BUNDLE or name.endswith(".zip") else 8<<20),"Deployment verification input exceeds budget")
        for name in sorted(names):authenticate(root/name,root/PROVENANCE_BUNDLE,commit,ref,gh)
        result=validate_contents(root,commit,arch)
        if run_id is not None:require(result.get("lifecycleRunID")==run_id,"Authenticated native run differs from caller expectation")
        negative=check_rejections(root/next(n for n in sorted(names) if n.endswith(".pkg")),root/PROVENANCE_BUNDLE,commit,ref,gh) if rejections else None
        return {"schemaVersion":1,"repository":REPOSITORY,"workflow":WORKFLOW,"sourceCommit":commit,"sourceRef":ref,"target":"darwin/"+arch,"subjectsVerified":len(names),"subjects":[{"file":name,"sha256":digest((root/name).read_bytes())} for name in sorted(names)],"authenticatedBeforeParsing":True,"hostedRunnerRequired":True,"deployment":result,"rejectionChecks":negative,"publisherSignatureVerified":False,"notarized":False,"localTargetExecution":False,"productionQualificationComplete":False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("directory",type=Path);parser.add_argument("--source-commit",required=True);parser.add_argument("--source-ref",required=True);parser.add_argument("--architecture",choices=("amd64","arm64"),required=True);parser.add_argument("--gh",default="gh");parser.add_argument("--check-rejections",action="store_true");parser.add_argument("--stage-build-root",type=Path);parser.add_argument("--run-id")
    args=parser.parse_args()
    try:result=stage(args.stage_build_root,args.directory,args.source_commit,args.source_ref,args.architecture,args.run_id) if args.stage_build_root else verify(args.directory,args.source_commit,args.source_ref,args.architecture,args.gh,args.check_rejections,args.run_id)
    except Exception as error:raise SystemExit("Deployment provenance refused: "+type(error).__name__)
    print(json.dumps(result,indent=2))

if __name__=="__main__":main()
