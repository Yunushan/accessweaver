#!/usr/bin/env python3
"""Authenticate the two-version native Windows acceptance family. Never execute it."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile

from sbom import validate,prop_map
from verify_release_provenance import BUNDLE_NAME,REPOSITORY,validate_identity,verification_command as portable_command
from verify_release_rebuild import snapshot

WORKFLOW=REPOSITORY+"/.github/workflows/installer-lifecycle.yml"
DEFAULT_VERSIONS=("0.1.0-alpha","0.1.1-alpha")
RELEASE=re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
SHA=re.compile(r"[a-f0-9]{64}")
PHASES=["baseline","after-install","after-upgrade","after-reinstall","after-active-setup-uninstall","after-lifecycle-locks","after-refused-downgrade","after-version-policy","after-registry-read-boundaries","after-registry-view-policy","after-registry-access-policy","after-restoration-launch-failures","after-restoration-ownership-contracts","before-uninstall","after-uninstall"]

def require(ok,message):
    if not ok:raise ValueError(message)

def digest(data):return hashlib.sha256(data).hexdigest()

def subject_names(arch,versions):
    require(arch in ("amd64","arm64") and len(versions)==2 and len(set(versions))==2,"Expected approved architecture and two distinct acceptance versions")
    names={arch+".json"}
    for version in versions:
        require(isinstance(version,str) and len(version)<=256,"Invalid approved release version")
        match=RELEASE.fullmatch(version)
        require(match is not None,"Expected canonical approved SemVer")
        require(not match[4] or all(not p.isdigit() or p=="0" or not p.startswith("0") for p in match[4].split(".")),"Numeric prerelease has a leading zero")
        name="accessweaver-"+version+"-windows-"+arch+"-setup.exe"
        require(len((name+".cdx.json").encode("utf-8"))<=255,"Installer subject name exceeds filesystem limit")
        names.update((name,name+".cdx.json"))
    return names

def verification_command(path,bundle,commit,ref,gh="gh"):
    command=portable_command(path,bundle,commit,ref,gh)
    command[command.index("--signer-workflow")+1]=WORKFLOW
    return command

def authenticate(path,bundle,commit,ref,gh):
    try:subprocess.run(verification_command(path,bundle,commit,ref,gh),check=True,capture_output=True,timeout=120)
    except subprocess.CalledProcessError as error:raise ValueError("Windows installer cryptographic verification failed") from error

def load(root,name):
    data=(root/name).read_bytes();require(len(data)<=4<<20,"Installer metadata exceeds budget")
    return json.loads(data.decode("utf-8-sig"))

def validate_build(identity,commit,arch,version):
    require(set(identity)=={"version","commit","sourceState","builtAt","goVersion","platform","arch"},"Incomplete native payload build fields")
    require(all(identity.get(k)==v for k,v in {"version":version,"commit":commit,"sourceState":"clean","goVersion":"go1.27.4","platform":"windows","arch":arch}.items()),"Native payload build identity differs")
    require(isinstance(identity["builtAt"],str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",identity["builtAt"]) is not None,"Invalid canonical build timestamp")
    datetime.datetime.strptime(identity["builtAt"],"%Y-%m-%dT%H:%M:%SZ")


def validate_state_observations(observations):
    require(type(observations) is list and len(observations)==len(PHASES) and all(type(o) is dict for o in observations),"Incomplete native state checkpoints")
    require([o.get("phase") for o in observations]==PHASES,"Expected all fifteen ordered native state checkpoints")
    baseline=observations[0].get("comparison")
    require(type(baseline) is dict and type(baseline.get("domains")) is dict and set(baseline["domains"])=={"services","firewall","dns"},"Incomplete native state baseline")
    for observation in observations:
        require(set(observation)=={"phase","comparison","transition"},"Incomplete native state checkpoint envelope")
        for key in ("comparison","transition"):
            comparison=observation.get(key)
            require(type(comparison) is dict and set(comparison)=={"exactMatch","beforeSHA256","afterSHA256","domains"},"Incomplete native state comparison")
            require(comparison.get("exactMatch") is True and type(comparison.get("beforeSHA256")) is str and comparison.get("beforeSHA256")==comparison.get("afterSHA256")==baseline.get("beforeSHA256") and SHA.fullmatch(comparison["beforeSHA256"]) is not None,"Native state checkpoint changed")
            require(type(comparison.get("domains")) is dict and set(comparison["domains"])=={"services","firewall","dns"},"Incomplete native state domains")
            for name,domain in comparison["domains"].items():
                initial=baseline["domains"][name]
                require(type(domain) is dict and type(initial) is dict and set(domain)=={"beforeSHA256","afterSHA256","serializedEqual","beforeRows","afterRows","added","removed","changed","rowSerializationChanges","recordOrderingChanged","changes","changesTruncated"},"Invalid native state domain")
                require(domain.get("serializedEqual") is True and type(domain.get("beforeSHA256")) is str and domain.get("beforeSHA256")==domain.get("afterSHA256")==initial.get("beforeSHA256") and SHA.fullmatch(domain["beforeSHA256"]) is not None,"Native state domain changed")
                require(type(domain.get("beforeRows")) is int and type(domain.get("afterRows")) is int and domain["beforeRows"]==domain["afterRows"]==initial.get("beforeRows") and 0<=domain["beforeRows"]<=10000,"Native state row count differs")
                require(all(type(domain.get(k)) is int and domain[k]==0 for k in ("added","removed","changed","rowSerializationChanges")) and domain.get("recordOrderingChanged") is False and domain.get("changes")==[] and domain.get("changesTruncated") is False,"Native state diagnostics report a change")
    return {"nativeStateCheckpointsVerified":len(PHASES),"nativeStateComparisonsVerified":2*len(PHASES)}


def validate_firewall_origin_diagnostics(value):
    expected={"schemaVersion":1,"source":"captured-rule-properties","maxRecords":16,"maxPropertyBytes":4096,"records":[],"truncated":False,"unavailable":False,"extraNativeQueriesPerformed":False,"processOriginEstablished":False}
    require(type(value) is dict and set(value)==set(expected),"Incomplete captured firewall metadata envelope")
    for key,wanted in expected.items():
        require(type(value[key]) is type(wanted) and value[key]==wanted,"Qualified unchanged state must have complete empty captured firewall metadata")
    return {"nativeFirewallOriginRecordsVerified":0}


def validate_firewall_event_diagnostics(value):
    expected={"schemaVersion":1,"source":"existing-local-firewall-event-log","status":"not-needed","queryAttempted":False,"queryDeadlineMilliseconds":10000,"queryElapsedMilliseconds":0,"maxEvents":128,"maxRecords":16,"maxXmlBytes":65536,"maxFieldBytes":4096,"windowStartUtc":None,"windowEndUtc":None,"eventsExamined":0,"invalidEvents":0,"eventsLimitReached":False,"records":[],"recordsTruncated":False,"unavailable":False,"eventLogConfigurationChanged":False,"extraFirewallRuleQueriesPerformed":False,"processOriginEstablished":False}
    require(type(value) is dict and set(value)==set(expected),"Incomplete firewall event diagnostic envelope")
    for key,wanted in expected.items():
        require(type(value[key]) is type(wanted) and value[key]==wanted,"Qualified unchanged state must not run or claim event correlation")
    return {"nativeFirewallEventQueriesVerified":0}


def validate_native_attempt(value):
    expected={"schemaVersion","toolClass","timeoutMilliseconds","elapsedMilliseconds","invocationReturned","operationAccepted","exitCode","outputComplete","failureCategory"}
    require(type(value) is dict and set(value)==expected,"Incomplete native-attempt metadata")
    require(type(value.get("schemaVersion")) is int and value["schemaVersion"]==1 and value.get("toolClass")=="uninstaller","Final native attempt was not the uninstaller")
    require(type(value.get("timeoutMilliseconds")) is int and value["timeoutMilliseconds"]==180000 and type(value.get("elapsedMilliseconds")) is int and 0<=value["elapsedMilliseconds"]<180000,"Final native attempt exceeded its original deadline")
    require(value.get("invocationReturned") is True and value.get("operationAccepted") is True and type(value.get("exitCode")) is int and value["exitCode"]==0 and value.get("outputComplete") is True and value.get("failureCategory")=="none","Final native attempt did not complete successfully")
    return {"finalNativeAttemptVerified":True}

def validate_managed_detection(report):
    expected = [
        ("before-install", False), ("after-install", True), ("wrong-digest", False),
        ("after-upgrade", True), ("superseded-version", False), ("after-reinstall", True),
        ("after-refused-downgrade", True), ("after-refused-uninstall", True), ("after-uninstall", False),
    ]
    source = Path(__file__).with_name("detect-windows-installer.ps1")
    require(report.get("managedDetectionSourceSHA256") == digest(source.read_bytes()),
            "Managed detection differs from the approved source")
    cases = report.get("managedDetectionCases")
    require(isinstance(cases, list) and len(cases) == len(expected), "Incomplete managed detection coverage")
    for case, (phase, detected) in zip(cases, expected):
        require(isinstance(case, dict) and case.keys() == {"phase", "detected"}
                and case["phase"] == phase and case["detected"] is detected,
                "Unexpected managed detection result")
    return {"managedDetectionChecksVerified": len(expected)}


def validate_contents(root,commit,ref,arch,versions):
    report=load(root,arch+".json")
    require(type(report.get("schemaVersion")) is int and report.get("schemaVersion") in (11,12) and report.get("sourceCommit")==commit and report.get("sourceRef")==ref and report.get("target")=="windows/"+arch,"Native lifecycle source/target differs")
    require(report.get("compilerVersion")=="6.7.1" and report.get("stage")=="cleanup" and report.get("failureType") is None and report.get("failureSourceLine") is None and report.get("assertionFailure") is None,"Native lifecycle did not finish cleanly")
    for key in ("passed","actualUserProfilePreservationVerified","childEnvironmentSanitized","selectedServiceFirewallDNSStateUnchanged","ownedFixturesRemoved","unsigned","downgradeTested"):
        require(report.get(key) is True,"Native lifecycle acceptance is incomplete")
    for key in ("publisherSignatureVerified","rebootTested","crashOrPowerLossTested","vendorDriverOrRoutingQualified","productionQualificationComplete"):
        require(report.get(key) is False,"Unqualified native scope changed")
    require(re.fullmatch(r"[1-9][0-9]{0,19}",str(report.get("runID",""))) is not None,"Missing native invocation identity")
    require(report.get("stateDiagnosticsSourceSHA256")==digest(Path(__file__).with_name("windows-installer-state.ps1").read_bytes()),"State diagnostics differ from approved verifier source")
    require(report.get("nativeDiagnosticsSourceSHA256")==digest(Path(__file__).with_name("windows-installer-native-state.ps1").read_bytes()),"Native-attempt diagnostics differ from approved verifier source")
    require(report.get("eventDiagnosticsSourceSHA256")==digest(Path(__file__).with_name("windows-installer-event-state.ps1").read_bytes()),"Event diagnostics differ from approved verifier source")
    detection_counts = validate_managed_detection(report) if report["schemaVersion"] == 12 else {}
    event_counts=validate_firewall_event_diagnostics(report.get("firewallEventDiagnostics"))
    attempt_counts=validate_native_attempt(report.get("lastNativeAttempt"))
    state_counts=validate_state_observations(report.get("stateObservations"))
    origin_counts=validate_firewall_origin_diagnostics(report.get("firewallOriginDiagnostics"))
    operations=report.get("operations",[])
    expected=["install","upgrade","reinstall","refused-downgrade","refused-uninstall","uninstall"]
    require([o.get("operation") for o in operations]==expected,"Native lifecycle operation coverage differs")
    for operation in operations:
        require(operation.get("exitCode")== (1 if operation["operation"].startswith("refused-") else 0) and operation.get("deadlineMilliseconds")==180000 and type(operation.get("elapsedMilliseconds")) is int and 0<=operation["elapsedMilliseconds"]<180000,"Native lifecycle operation failed")
    builds=report.get("builds",[]);require([b.get("version") for b in builds]==list(versions),"Authenticated family differs from independently approved versions")
    candidates=[]
    for build,version in zip(builds,versions):
        name="accessweaver-"+version+"-windows-"+arch+"-setup.exe";binary=(root/name).read_bytes()
        require(64<=len(binary)<=64<<20 and build.get("installerName")==name and build.get("installerBytes")==len(binary) and build.get("installerSHA256")==digest(binary) and binary[:2]==b"MZ","Installer bytes differ from native report")
        offset=struct.unpack_from("<I",binary,0x3c)[0]
        require(64<=offset<=len(binary)-6 and binary[offset:offset+4]==b"PE\0\0" and struct.unpack_from("<H",binary,offset+4)[0]==0x14c,"Expected the qualified x86 Inno bootstrap")
        identity=build["payloadBuild"]
        validate_build(identity,commit,arch,version)
        require(SHA.fullmatch(build["payloadSha256"]) is not None and SHA.fullmatch(build["compilerSHA256"]) is not None,"Native payload/compiler subject is missing")
        bom=load(root,name+".cdx.json");validate(bom,binary,identity)
        require(bom["metadata"].get("timestamp")==identity["builtAt"],"Installer SBOM build timestamp differs")
        components={c["bom-ref"]:c for c in bom["components"]};payload=components.get("payload-application",{});compiler=components.get("inno-setup",{})
        require(payload.get("version")==version and payload.get("hashes")==[{"alg":"SHA-256","content":build["payloadSha256"]}],"Installer SBOM payload subject differs")
        require(compiler.get("version")=="6.7.1" and prop_map(compiler).get("accessweaver:compiler-sha256")==build["compilerSHA256"],"Installer SBOM compiler subject differs")
        candidates.append({"file":name,"sha256":digest(binary),"bytes":len(binary),"payloadSHA256":build["payloadSha256"],"payloadTarget":"windows/"+arch,"bootstrapPEMachine":"0x014c","sbomSHA256":digest((root/(name+".cdx.json")).read_bytes())})
    return {"candidates":candidates,**detection_counts,**state_counts,**origin_counts,**event_counts,**attempt_counts,"nativeLifecycleOperationsVerified":len(expected),"nativeRunID":str(report["runID"]),"nativeDependencyClosureComplete":False}

def stage(build_root,destination,commit,ref,arch,versions):
    validate_identity(commit,ref);names=subject_names(arch,versions)
    require(not destination.exists() and not destination.is_symlink(),"Staging destination must be new")
    destination.mkdir(parents=True,mode=0o700)
    for name in sorted(names):
        source=build_root/("installer-lifecycle-checks/"+name if name==arch+".json" else name)
        before=source.lstat();maximum=(64<<20) if name.endswith(".exe") else (4<<20)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not getattr(before,"st_file_attributes",0)&0x400 and 0<before.st_size<=maximum,"Expected bounded regular native subject")
        flags=os.O_RDONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0)
        descriptor=os.open(source,flags)
        try:
            identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_nlink)
            require(identity(os.fstat(descriptor))==identity(before),"Native subject changed before staging")
            with os.fdopen(descriptor,"rb",closefd=False) as stream:data=stream.read(maximum+1)
            require(len(data)==before.st_size and identity(os.fstat(descriptor))==identity(before),"Native subject changed during staging")
        finally:os.close(descriptor)
        with (destination/name).open("xb") as stream:stream.write(data)
    # Producer validation precedes signing; it is not cryptographic authentication.
    return validate_contents(destination,commit,ref,arch,versions)

def check_rejections(path,bundle,commit,ref,gh):
    base=verification_command(path,bundle,commit,ref,gh)
    def run(command,success):
        result=subprocess.run(command,capture_output=True,timeout=120)
        require((result.returncode==0)==success,"Unexpected Windows provenance rejection result")
    run(base,True);rejected=[]
    for flag,value in (("--source-digest","0"*len(commit)),("--source-ref","refs/tags/invalid-installer-probe"),("--signer-workflow",REPOSITORY+"/.github/workflows/ci.yml"),("--repo","octocat/Hello-World")):
        command=list(base);command[command.index(flag)+1]=value;run(command,False);rejected.append(flag)
    with tempfile.TemporaryDirectory(prefix="accessweaver-installer-negative-") as temporary:
        changed=Path(temporary)/path.name;changed.write_bytes(path.read_bytes()+b"changed")
        command=list(base);command[3]=str(changed.resolve());run(command,False);rejected.append("changed-subject-digest")
    run(base,True);return {"rejected":rejected,"realBundleVerifiedBeforeAndAfter":True}

def verify(directory,commit,ref,arch,versions=DEFAULT_VERSIONS,gh="gh",rejections=False):
    validate_identity(commit,ref);names=subject_names(arch,versions)
    with tempfile.TemporaryDirectory(prefix="accessweaver-installer-auth-") as temporary:
        root=Path(temporary);require(snapshot(Path(directory),root,6)==names|{BUNDLE_NAME},"Expected five native subjects and one provenance bundle")
        for name in names|{BUNDLE_NAME}:
            maximum=(64<<20) if name.endswith(".exe") else (16<<20) if name==BUNDLE_NAME else (4<<20)
            require((root/name).stat().st_size<=maximum,"Native subject exceeds its type limit")
        for name in sorted(names):authenticate(root/name,root/BUNDLE_NAME,commit,ref,gh)
        contents=validate_contents(root,commit,ref,arch,versions)
        result={"schemaVersion":1,"repository":REPOSITORY,"workflow":WORKFLOW,"sourceCommit":commit,"sourceRef":ref,"target":"windows/"+arch,"approvedVersions":list(versions),"subjectsVerified":5,"hostedRunnerRequired":True,"authenticatedBeforeParsing":True,"subjects":[{"file":name,"sha256":digest((root/name).read_bytes())} for name in sorted(names)],"nativeAcceptance":contents,"publisherSignatureVerified":False,"targetExecutionPerformedByVerifier":False,"productionQualificationComplete":False}
        if rejections:result["rejectionChecks"]=check_rejections(root/(arch+".json"),root/BUNDLE_NAME,commit,ref,gh)
        return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("directory",type=Path)
    parser.add_argument("--source-commit",required=True);parser.add_argument("--source-ref",required=True);parser.add_argument("--architecture",required=True)
    parser.add_argument("--versions",nargs=2,default=DEFAULT_VERSIONS);parser.add_argument("--gh",default="gh");parser.add_argument("--check-rejections",action="store_true");parser.add_argument("--stage-build-root",type=Path)
    args=parser.parse_args()
    try:
        if args.stage_build_root is not None:
            result=stage(args.stage_build_root,args.directory,args.source_commit,args.source_ref,args.architecture,args.versions)
            print(json.dumps({"producerContentsValidatedBeforeSigning":True,"cryptographicProvenanceAuthenticated":False,"publisherSignatureVerified":False,"productionQualificationComplete":False,"nativeAcceptance":result}));return 0
        print(json.dumps(verify(args.directory,args.source_commit,args.source_ref,args.architecture,args.versions,args.gh,args.check_rejections)));return 0
    except (ValueError,OSError,KeyError,TypeError,RecursionError,subprocess.SubprocessError,struct.error) as error:
        print("Windows installer provenance verification failed ("+type(error).__name__+")",file=sys.stderr);return 1

if __name__=="__main__":sys.exit(main())
