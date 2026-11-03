#!/usr/bin/env python3
"""Authenticate native macOS package subjects before parsing; never install/run them."""
import argparse
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile

from macos_installer import BUNDLE_ID,MAX_BYTES,digest,require,version_parts
from macos_package_archive import inspect,flat_members,cpio,inflate
from sbom import validate,prop_map
from verify_release_provenance import BUNDLE_NAME,REPOSITORY,validate_identity,verification_command as portable_command
from verify_release_rebuild import snapshot

WORKFLOW=REPOSITORY+"/.github/workflows/macos-installer.yml"


def subject_names(version,arch):
    version_parts(version);require(arch in ("amd64","arm64"),"Expected an approved native macOS architecture")
    package="accessweaver-"+version+"-darwin-"+arch+"-experimental.pkg"
    require(len(package.encode("utf-8"))<=255,"Package name exceeds filesystem limit")
    return package,{package,package+".cdx.json","BUILD-INFO.json","INSTALL-MANIFEST.json","compiler-artifact.json","lifecycle-artifact.json","payload-SBOM.cdx.json"}


def verification_command(path,bundle,commit,ref,gh="gh"):
    command=portable_command(path,bundle,commit,ref,gh)
    command[command.index("--signer-workflow")+1]=WORKFLOW
    return command


def authenticate(path,bundle,commit,ref,gh):
    try:
        subprocess.run(verification_command(path,bundle,commit,ref,gh),check=True,capture_output=True,timeout=120)
    except subprocess.CalledProcessError as error:
        raise ValueError("Native package cryptographic provenance verification failed") from error


def validate_contents(root,package,commit,version,arch):
    read=lambda name:json.loads((root/name).read_text(encoding="utf-8"))
    identity=read("BUILD-INFO.json");manifest=read("INSTALL-MANIFEST.json")
    require(all(identity.get(k)==v for k,v in {"commit":commit,"sourceState":"clean","version":version,"platform":"darwin","arch":arch}.items()),"Authenticated package build identity differs")
    binary=(root/package).read_bytes();actual=inspect(binary,manifest,identity)
    require(manifest.get("bundleIdentifier")==BUNDLE_ID,"Authenticated bundle identifier differs")
    require(actual["preinstallSHA256"]==digest(Path(__file__).with_name("macos-installer-preinstall.sh").read_bytes()),"Package guard differs from approved verifier source")
    report=read("compiler-artifact.json");life=read("lifecycle-artifact.json")
    require(report.get("sourceCommit")==commit and report.get("sourceState")=="clean" and report.get("target")=="darwin/"+arch and report.get("payloadBuild")==identity,"Authenticated compiler identity differs")
    require(report.get("packageFile")==package and report.get("packageBytes")==len(binary) and report.get("archiveInspection")==actual,"Authenticated package inspection differs")
    for key in ("packageSHA256","payloadSHA256","preinstallSHA256","bundleManifestSHA256","bundleInfoSHA256","macho"):
        require(report.get(key)==actual[key],"Authenticated package subject differs")
    require(all(report.get(k) is True for k in ("unsigned","experimentalCleanInstallOnly","nativePayloadIdentityVerified","actualExpandedPayloadVerified","bundleRelocationDisabled")) and report.get("installationExecuted") is False,"Native construction scope differs")
    entries=cpio(inflate(flat_members(binary)["Payload"],MAX_BYTES,31))
    prefix="Applications/AccessWeaver.app/Contents/"
    core=entries[prefix+"MacOS/accessweaver"]["data"]
    payload=(root/"payload-SBOM.cdx.json").read_bytes()
    require(payload==entries[prefix+"Resources/SBOM.cdx.json"]["data"],"Payload SBOM differs from sealed package")
    payload_bom=json.loads(payload);bom=read(package+".cdx.json")
    validate(payload_bom,core,identity);validate(bom,binary,identity)
    components={c["bom-ref"]:c for c in bom["components"]}
    expected=dict(payload_bom["metadata"]["component"]);expected["bom-ref"]="payload-application"
    require(components.get("payload-application")==expected,"Package SBOM payload graph identity differs")
    for item in payload_bom["components"]:
        require(components.get(item["bom-ref"])==item,"Package SBOM compiled component differs")
    files={"bundle-file:"+item["path"]:item for item in manifest["files"]}
    require(set(components)==set(files)|{"payload-application"}|{c["bom-ref"] for c in payload_bom["components"]},"Unexpected package SBOM component")
    for ref,item in files.items():
        require(components[ref].get("type")=="file" and components[ref].get("name")==item["path"] and components[ref].get("hashes")==[{"alg":"SHA-256","content":item["sha256"]}],"Package SBOM file subject differs")
    graph={edge["ref"]:edge["dependsOn"] for edge in bom["dependencies"]}
    require(set(graph["application"])==set(files)|{"payload-application"},"Package SBOM root graph differs")
    tool=report["pkgbuild"];measured=bom["metadata"]["tools"]["components"]
    require(re.fullmatch("[a-f0-9]{64}",tool["sha256"]) is not None and len(measured)==1 and measured[0].get("name")==tool.get("name")=="Apple pkgbuild" and measured[0].get("version")==tool["osBuild"] and measured[0].get("hashes")==[{"alg":"SHA-256","content":tool["sha256"]}] and prop_map(measured[0]).get("accessweaver:host-os-version")==tool["osVersion"],"Package build-tool evidence differs")
    for component in [payload_bom["metadata"]["component"]]+payload_bom["components"]:
        for evidence in json.loads(prop_map(component).get("accessweaver:license-evidence","[]")):
            entry=entries.get(prefix+"Resources/"+evidence["path"])
            require(entry is not None and not entry["directory"] and digest(entry["data"])==evidence["sha256"],"Payload notice bytes differ from SBOM evidence")
    require(prop_map(bom["metadata"]["component"]).get("accessweaver:experimental-clean-install-only")=="true","Experimental package label missing")
    require(life.get("schemaVersion")==2 and life.get("sourceCommit")==commit and life.get("target")=="darwin/"+arch and life.get("packageSHA256")==digest(binary) and life.get("payloadSHA256")==digest(core),"Authenticated lifecycle identity differs")
    require(all(life.get(k) is True for k in ("passed","cleanInstallExecuted","actualUserProfilePreservationVerified","ownedFixturesRemoved","unsigned")) and life.get("stage")=="owned-fixture-cleanup" and life.get("failureType") is None and life.get("failureSourceLine") is None,"Native lifecycle acceptance did not pass")
    cases=life.get("preflightRefusalCases",[])
    expected_cases={"existing-app-directory","existing-app-file","existing-app-symlink","dangling-app-symlink","partial-plist-receipt","partial-bom-receipt","plist-receipt-symlink","bom-receipt-symlink"}
    require(len(cases)==8 and {c.get("name") for c in cases}==expected_cases,"Native refusal coverage differs")
    for case in cases:
        require(all(case.get(k) is True for k in ("passed","fixtureIdentityAndBytesPreserved","aliasDestinationAndUnrelatedDataPreserved","noAdditionalAppOrReceiptCreated","ownedFixtureRemoved")) and 1<=case.get("exitCode",0)<=255,"Native refusal case did not pass")
    operations=life.get("operations",[])
    require([o.get("operation") for o in operations]==["clean-install","existing-install-refused","valid-receipt-only-refused"] and operations[0].get("exitCode")==0 and all(1<=o.get("exitCode",0)<=255 for o in operations[1:]),"Native install/refusal operations differ")
    for key in ("publisherSignatureVerified","notarized","upgradeQualified","downgradeQualified","finderInteractionQualified","managedEndpointQualified","productionQualificationComplete"):
        require(report.get(key) is False and life.get(key) is False,"Unqualified package scope changed")
    require(life.get("productUninstallQualified") is False and life.get("rebootOrPowerLossQualified") is False,"Unqualified lifecycle scope changed")
    validate_deployment_transactions(life.get("protectedDeploymentTransactions"),actual["bundleManifestSHA256"],digest(core),version)
    return {"packageSHA256":digest(binary),"payloadSHA256":digest(core),"macho":actual["macho"],"isolatedRefusalCases":8,"nativeInstallationOperations":3}


def validate_deployment_transactions(deployment,manifest_hash,payload_hash,version):
    require(type(deployment) is dict,"Missing native protected deployment transactions")
    require(type(deployment.get("schemaVersion")) is int and deployment["schemaVersion"]==1 and deployment.get("manifestSHA256")==manifest_hash and deployment.get("payloadSHA256")==payload_hash and deployment.get("version")==version and type(deployment.get("finalGeneration")) is int and deployment["finalGeneration"]==4,"Native protected deployment identity differs")
    for key in ("fixedProtectedParentVerified","partialCopyPreservedAndRefused","completeCopyRecovered","concurrentPreparationFenced","postPublicationRemovalRecovered","oldCompleteSlotFencedAfterRemoval","restoredRetryVerified","payloadIsIndependentCopy","installedObjectsAndReceiptsPreserved"):
        require(deployment.get(key) is True,"Native protected deployment transaction did not pass")
    require(deployment.get("copiedCodeExecuted") is False and deployment.get("packageScriptsIntegrated") is False and deployment.get("productionQualificationComplete") is False and deployment.get("fixtureParent")=="private-exclusive-temporary-directory" and re.fullmatch("[a-f0-9]{64}",deployment.get("testExecutableSHA256","")) is not None,"Native protected deployment scope differs")
    require(type(deployment.get("elapsedMilliseconds")) is int and 0<=deployment["elapsedMilliseconds"]<=150000,"Native protected deployment timing differs")


def check_rejections(path,bundle,commit,ref,gh):
    base=verification_command(path,bundle,commit,ref,gh)
    def run(command,success):
        result=subprocess.run(command,capture_output=True,timeout=120)
        require((result.returncode==0)==success,"Unexpected native package provenance rejection outcome")
    run(base,True);rejected=[]
    for flag,value in (("--source-digest","0"*len(commit)),("--source-ref","refs/tags/invalid-native-package-probe"),("--signer-workflow",REPOSITORY+"/.github/workflows/ci.yml"),("--repo","octocat/Hello-World")):
        command=list(base);command[command.index(flag)+1]=value;run(command,False);rejected.append(flag)
    with tempfile.TemporaryDirectory(prefix="accessweaver-native-provenance-negative-") as temporary:
        changed=Path(temporary)/path.name;changed.write_bytes(path.read_bytes()+b"changed")
        command=list(base);command[3]=str(changed.resolve());run(command,False);rejected.append("changed-subject-digest")
    run(base,True)
    return {"rejected":rejected,"realBundleVerifiedBeforeAndAfter":True}


def verify(directory,commit,ref,version,arch,gh="gh",rejections=False):
    validate_identity(commit,ref);package,names=subject_names(version,arch)
    with tempfile.TemporaryDirectory(prefix="accessweaver-native-package-auth-") as temporary:
        root=Path(temporary);actual=snapshot(Path(directory),root,8)
        require(actual==names|{BUNDLE_NAME},"Expected seven native package subjects and one provenance bundle")
        for name in actual:
            maximum=(64<<20) if name==package else (16<<20) if name==BUNDLE_NAME else (4<<20)
            require((root/name).stat().st_size<=maximum,"Native package input exceeds its type limit")
        # Every known subject must authenticate before any JSON/archive parsing.
        for name in sorted(names):authenticate(root/name,root/BUNDLE_NAME,commit,ref,gh)
        checked=validate_contents(root,package,commit,version,arch)
        result={"schemaVersion":1,"repository":REPOSITORY,"workflow":WORKFLOW,"sourceCommit":commit,"sourceRef":ref,"target":"darwin/"+arch,"subjectsVerified":7,"hostedRunnerRequired":True,"authenticatedBeforeParsing":True,"subjects":[{"file":name,"sha256":digest((root/name).read_bytes())} for name in sorted(names)],"package":checked,"publisherSignatureVerified":False,"notarized":False,"productionQualificationComplete":False,"localTargetExecution":False}
        if rejections:result["rejectionChecks"]=check_rejections(root/package,root/BUNDLE_NAME,commit,ref,gh)
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("directory",type=Path)
    for name in ("source-commit","source-ref","version","architecture"):parser.add_argument("--"+name,required=True)
    parser.add_argument("--gh",default="gh");parser.add_argument("--check-rejections",action="store_true")
    args=parser.parse_args()
    try:
        result=verify(args.directory,args.source_commit,args.source_ref,args.version,args.architecture,args.gh,args.check_rejections)
        print(json.dumps(result));return 0
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print("Native package provenance verification failed ("+type(error).__name__+")",file=sys.stderr)
        return 1

if __name__=="__main__":sys.exit(main())
