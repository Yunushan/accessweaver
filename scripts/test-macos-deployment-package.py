#!/usr/bin/env python3
"""Actual experimental component-package lifecycle on opted-in disposable Macs."""
import importlib.util
import fcntl
import time
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from macos_deployment import PACKAGE_ID,INCOMING,inspect_deployment,DETACHED_MANIFEST,PAYLOAD_SBOM,verify_deployment_bundle
from macos_installer import BUNDLE_NAME,digest,require,MAX_BYTES
from macos_package_archive import flat_members,cpio,inflate

REPO=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location("accessweaver_mac_fixture_support",Path(__file__).with_name("test-macos-installer-lifecycle.py"))
support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
run=support.run;no_alias=support.no_alias
AUTHORITY=Path("/Library/Application Support/AccessWeaver")
INPUT=Path(INCOMING)
RECEIPTS=[Path("/private/var/db/receipts")/(PACKAGE_ID+suffix) for suffix in (".plist",".bom")]
VERSIONS=("0.1.0-alpha","0.1.1-alpha")


def receipt_snapshot():
    values=[]
    for path in RECEIPTS:
        no_alias(path);info=path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0 and info.st_nlink==1 and info.st_size<=4<<20,"Unexpected deployment receipt")
        values.append({"suffix":path.suffix,"sha256":digest(path.read_bytes()),"bytes":info.st_size})
    return values


def main():
    require(support.platform.system()=="Darwin" and os.geteuid()!=0,"Native ordinary-user Mac driver required")
    require(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted" and os.environ.get("GITHUB_REPOSITORY")=="Yunushan/accessweaver" and os.environ.get("ACCESSWEAVER_DISPOSABLE_MACOS_DEPLOYMENT_PACKAGE_TEST")=="1","Explicit disposable native package opt-in required")
    source=os.environ.get("GITHUB_SHA","");arch=os.environ.get("ACCESSWEAVER_MACOS_INSTALLER_ARCH","")
    require(re.fullmatch("[a-f0-9]{40}",source) is not None and arch in ("amd64","arm64"),"Missing native package source/target")
    require(support.subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO,text=True).strip()==source and not support.subprocess.check_output(["git","status","--porcelain","--untracked-files=no"],cwd=REPO).strip(),"Expected a clean exact-source checkout")
    for path in (AUTHORITY,INPUT,support.APP,Path("/Library/Preferences/AccessWeaver"),*RECEIPTS,*support.RECEIPTS):
        no_alias(path);require(not path.exists(),"Existing app/managed/deployment state must never become a fixture")
    root=REPO/"build/macos-deployment-checks"/arch;candidates={}
    for version in VERSIONS:
        output=root/version;identity=json.loads((output/"BUILD-INFO.json").read_bytes());report=json.loads((output/"compiler-artifact.json").read_bytes())
        require(identity["commit"]==source and identity["version"]==version and identity["arch"]==arch and identity["sourceState"]=="clean" and report["payloadBuild"]==identity,"Candidate source/target differs")
        filename="accessweaver-"+version+"-darwin-"+arch+"-deployment-experimental.pkg"
        require(report["packageFile"]==filename,"Unexpected deployment package filename")
        package=output/filename;encoded=(output/"INSTALL-MANIFEST.json").read_bytes();scripts=json.loads((output/"SCRIPT-MANIFEST.json").read_bytes())
        require(inspect_deployment(package.read_bytes(),encoded,identity,scripts)==report["archiveInspection"],"Actual deployment package changed after construction")
        candidates[version]={"identity":identity,"report":report,"package":package,"manifest":json.loads(encoded),"manifestBytes":encoded}
    temporary=Path(os.environ["RUNNER_TEMP"]);no_alias(temporary)
    capsule=Path(tempfile.mkdtemp(prefix="accessweaver-deployment-package-",dir=temporary));user=capsule/"user";user.mkdir();private_temp=capsule/"tmp";private_temp.mkdir()
    environment={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":str(user),"TMPDIR":str(private_temp),"LANG":"C","LC_ALL":"C","TZ":"UTC","ACCESSWEAVER_NO_BROWSER":"1"}
    marker=user/"preserve";marker.write_bytes(b"unrelated deployment package fixture");marker_hash=digest(marker.read_bytes())
    complete=False;cleaned=False;failure=None;failure_line=None;stage="clean-install";operations=[];profile_path=None;profile_hash=None;known_slots={};lease_cases=[]
    def state():
        path=AUTHORITY/"state/deployment.json";no_alias(path);info=path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0 and info.st_nlink==1 and info.st_size<=16384,"Unexpected protected deployment state")
        return json.loads(path.read_bytes()),digest(path.read_bytes())
    def active(version,generation):
        candidate=candidates[version];value,_=state();slot=value["active"]
        require(value["generation"]==generation and value["highWaterVersion"]==version and value["pending"]==[] and slot["identity"]=={"version":version,"manifestSHA256":candidate["report"]["manifestSHA256"],"payloadSHA256":candidate["report"]["payloadSHA256"]} and re.fullmatch("[a-f0-9]{32}",slot["id"]) is not None,"Activated package state differs")
        app=AUTHORITY/"versions"/slot["id"]/BUNDLE_NAME;verify_deployment_bundle(app,candidate["manifest"],candidate["identity"],candidate["manifestBytes"])
        actual,_=run([app/"Contents/MacOS/accessweaver","version","--json"],environment,30)
        require(json.loads(actual.stdout)==candidate["identity"],"Actual unelevated active runtime differs")
        for prior,(prior_version,prior_app) in known_slots.items():verify_deployment_bundle(prior_app,candidates[prior_version]["manifest"],candidates[prior_version]["identity"],candidates[prior_version]["manifestBytes"])
        known_slots[slot["id"]]=(version,app)
        info,_=run(["/usr/sbin/pkgutil","--pkg-info",PACKAGE_ID],environment,30)
        values=dict(line.split(": ",1) if ": " in line else (line.rstrip(":"),"") for line in info.stdout.decode().splitlines() if line)
        location=candidate["report"]["archiveInspection"]["installLocation"]
        require(values.get("package-id")==PACKAGE_ID and values.get("version")==version and values.get("volume")=="/" and values.get("location") in (location,location.lstrip("/")),"Native package receipt does not match active version/input location")
        return app,slot["id"]
    def install(name,version,generation,success=True):
        nonlocal stage
        stage=name;before_state=state()[1] if AUTHORITY.exists() else None;before_receipts=receipt_snapshot() if all(p.exists() for p in RECEIPTS) else None
        candidate=candidates[version]
        require(digest(candidate["package"].read_bytes())==candidate["report"]["packageSHA256"],"Actual package changed before Installer execution")
        result,elapsed=run(["/usr/bin/sudo","-n","/usr/sbin/installer","-pkg",candidates[version]["package"],"-target","/"],environment,180,codes=tuple(range(256)))
        require(digest(candidate["package"].read_bytes())==candidate["report"]["packageSHA256"],"Actual package changed during Installer execution")
        entry={"operation":name,"version":version,"exitCode":result.returncode,"elapsedMilliseconds":elapsed,"passed":False};operations.append(entry)
        if (result.returncode==0)!=success:
            diagnostic=(result.stdout+result.stderr).decode("utf-8",errors="replace")[-12000:].replace(str(capsule),"[owned-capsule]")
            print(diagnostic,flush=True)
            log,_=run(["/usr/bin/sudo","-n","/usr/bin/tail","-n","200","/var/log/install.log"],environment,30,codes=tuple(range(256)))
            lines=[line for line in log.stdout.decode("utf-8",errors="replace").splitlines() if PACKAGE_ID in line or "installer operation refused:" in line]
            print("\n".join(lines[-40:]).replace(str(capsule),"[owned-capsule]"),flush=True)
        require((result.returncode==0)==success,"Unexpected actual package operation result: "+name)
        if success:
            app,slot=active(version,generation);entry.update({"generation":generation,"slotID":slot,"activeIdentity":state()[0]["active"]["identity"],"actualUnelevatedRuntimeVerified":True,"retainedPriorCopiesVerified":True})
        else:
            require(state()[1]==before_state and receipt_snapshot()==before_receipts,"Refused package changed active record/receipt bytes")
            entry.update({"activeRecordAndReceiptBytesPreserved":True})
        if profile_path is not None:require(digest(profile_path.read_bytes())==profile_hash,"Actual package operation changed saved profile")
        require(digest(marker.read_bytes())==marker_hash,"Actual package operation changed unrelated user data")
        entry["passed"]=True
    try:
        install("clean-install",VERSIONS[0],1)
        app,_=active(VERSIONS[0],1)
        template,_=run([app/"Contents/MacOS/accessweaver","show","discord-proxy"],environment,30);profile=json.loads(template.stdout);profile["id"]="deployment-preserve";profile["name"]="Preserved native deployment profile"
        request=capsule/"profile.json";request.write_text(json.dumps(profile),encoding="utf-8")
        run([app/"Contents/MacOS/accessweaver","import",request],environment,30)
        profile_path=user/"Library/Application Support/AccessWeaver/profiles/deployment-preserve.json";no_alias(profile_path);profile_hash=digest(profile_path.read_bytes())
        stage="running-controller-runtime-lease"
        core=app/"Contents/MacOS/accessweaver"
        for kind in ("direct","inherited","alias"):
            output=capsule/("runtime-"+kind+".stdout");child_environment=dict(environment);descriptor=None
            command=core
            if kind=="alias":
                command=capsule/"alias-core";command.symlink_to(core)
            if kind=="inherited":
                descriptor=os.open(AUTHORITY/".runtime.lock",os.O_RDONLY)
                fcntl.flock(descriptor,fcntl.LOCK_SH|fcntl.LOCK_NB)
                child_environment["ACCESSWEAVER_RUNTIME_LEASE_FD"]=str(descriptor)
            before_state=state()[1];before_receipts=receipt_snapshot();child=None;serving=False
            try:
                with output.open("xb") as stream:
                    child=support.subprocess.Popen([str(command),"ui"],cwd=REPO,env=child_environment,stdout=stream,stderr=support.subprocess.STDOUT,pass_fds=(() if descriptor is None else (descriptor,)))
                if descriptor is not None:os.close(descriptor);descriptor=None
                deadline=time.monotonic()+30
                while time.monotonic()<deadline:
                    require(output.stat().st_size<=65536,"Controller startup output exceeds limit")
                    if b"AccessWeaver is running at" in output.read_bytes():break
                    require(child.poll() is None,"Installed controller failed to acquire its runtime lease")
                    time.sleep(0.05)
                require(b"AccessWeaver is running at" in output.read_bytes(),"Installed controller did not reach serving state")
                serving=True
                result,elapsed=run(["/usr/bin/sudo","-n","/usr/sbin/installer","-pkg",candidates[VERSIONS[1]]["package"],"-target","/"],environment,180,codes=tuple(range(256)))
                require(1<=result.returncode<=255 and state()[1]==before_state and receipt_snapshot()==before_receipts,"Running controller did not fence actual package mutation")
                verify_deployment_bundle(app,candidates[VERSIONS[0]]["manifest"],candidates[VERSIONS[0]]["identity"],candidates[VERSIONS[0]]["manifestBytes"])
                require(child.poll() is None and digest(profile_path.read_bytes())==profile_hash,"Refused upgrade disturbed the live controller/profile")
                lease_cases.append({"kind":kind,"installerExitCode":result.returncode,"elapsedMilliseconds":elapsed,"servingControllerVerified":True,"activeRecordAndReceiptBytesPreserved":True,"actualProfilePreserved":True,"controllerRemainedRunning":True,"parentInheritedDescriptorClosed":kind=="inherited","passed":True})
            except Exception:
                if output.exists():print(output.read_bytes()[:65536].decode("utf-8",errors="replace").replace(str(capsule),"[owned-capsule]"),flush=True)
                raise
            finally:
                if descriptor is not None:os.close(descriptor)
                if child is not None and child.poll() is None:child.terminate()
                if child is not None:
                    stopped=child.wait(timeout=30)
                    if serving:require(stopped==0,"Owned controller did not stop cleanly")
        install("upgrade",VERSIONS[1],2)
        install("same-version-reinstall",VERSIONS[1],3)
        install("older-version-refused",VERSIONS[0],3,False)
        candidate=candidates[VERSIONS[1]];incoming=INPUT/candidate["report"]["manifestSHA256"]/BUNDLE_NAME;verify_deployment_bundle(incoming,candidate["manifest"],candidate["identity"],candidate["manifestBytes"])
        payload_sbom=incoming.parent/PAYLOAD_SBOM;original_sbom=capsule/"saved-payload-sbom";original_sbom.write_bytes(payload_sbom.read_bytes())
        changed_sbom=capsule/"changed-payload-sbom";changed_sbom.write_bytes(original_sbom.read_bytes()+b" ")
        run(["/usr/bin/sudo","-n","/bin/cp",changed_sbom,payload_sbom],environment)
        install("changed-detached-sbom-refused",VERSIONS[1],3,False)
        require(payload_sbom.read_bytes()==changed_sbom.read_bytes(),"Refused package overwrote a changed detached SBOM")
        run(["/usr/bin/sudo","-n","/bin/cp",original_sbom,payload_sbom],environment)
        verify_deployment_bundle(incoming,candidate["manifest"],candidate["identity"],candidate["manifestBytes"])
        sidecar=incoming.parent/DETACHED_MANIFEST;original_manifest=capsule/"saved-detached-manifest";original_manifest.write_bytes(sidecar.read_bytes())
        changed_manifest=capsule/"changed-detached-manifest";changed_manifest.write_bytes(original_manifest.read_bytes()+b" ")
        run(["/usr/bin/sudo","-n","/bin/cp",changed_manifest,sidecar],environment)
        install("changed-detached-manifest-refused",VERSIONS[1],3,False)
        require(sidecar.read_bytes()==changed_manifest.read_bytes(),"Refused package overwrote a changed detached manifest")
        run(["/usr/bin/sudo","-n","/bin/cp",original_manifest,sidecar],environment)
        verify_deployment_bundle(incoming,candidate["manifest"],candidate["identity"],candidate["manifestBytes"])
        leaf=incoming/"Contents/Resources/README.md";original=capsule/"saved-readme";original.write_bytes(leaf.read_bytes());changed=capsule/"changed-readme";changed.write_bytes(original.read_bytes()+b"changed")
        run(["/usr/bin/sudo","-n","/bin/cp",changed,leaf],environment)
        install("changed-staging-refused",VERSIONS[1],3,False)
        require(digest(leaf.read_bytes())==digest(changed.read_bytes()),"Refused package overwrote changed staging input")
        run(["/usr/bin/sudo","-n","/bin/cp",original,leaf],environment)
        install("restored-reinstall",VERSIONS[1],4)
        stage="deactivation-and-owned-cleanup"
        scripts=cpio(inflate(flat_members(candidate["package"].read_bytes())["Scripts"],32<<20,31));helper=capsule/"accessweaver-installer";helper.write_bytes(scripts["postinstall"]["data"]);helper.chmod(0o755)
        require(digest(helper.read_bytes())==candidate["report"]["helperSHA256"],"Recovery helper differs from actual package bytes")
        stopped,elapsed=run(["/usr/bin/sudo","-n",helper,"deactivate-deployment"],environment,60);value=json.loads(stopped.stdout)
        require(value["generation"]==5 and value["state"]=="inactive" and value["operationRecordPublished"] is True,"Packaged recovery helper did not publish deactivation")
        operations.append({"operation":"deactivate-for-cleanup","version":VERSIONS[1],"exitCode":stopped.returncode,"elapsedMilliseconds":elapsed,"generation":5,"passed":True})
        final,_=state();require(final["active"]["id"]=="" and final["pending"]==[] and len(known_slots)==4,"Unexpected retained deployment fixture state")
        for version,app in known_slots.values():verify_deployment_bundle(app,candidates[version]["manifest"],candidates[version]["identity"],candidates[version]["manifestBytes"])
        for path in (AUTHORITY,INPUT):
            no_alias(path);info=path.stat();require(path.parent==Path("/Library/Application Support") and path.name in ("AccessWeaver","AccessWeaver Incoming") and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755,"Unsafe newly owned fixture cleanup")
            aliases,_=run(["/usr/bin/sudo","-n","/usr/bin/find",path,"-type","l","-print"],environment);require(not aliases.stdout.strip(),"Unexpected fixture alias")
        run(["/usr/bin/sudo","-n","/usr/sbin/pkgutil","--forget",PACKAGE_ID],environment)
        run(["/usr/bin/sudo","-n","/bin/rm","-rf","--",AUTHORITY,INPUT],environment)
        require(not AUTHORITY.exists() and not INPUT.exists() and not support.APP.exists() and all(not p.exists() for p in RECEIPTS+support.RECEIPTS),"Owned deployment package state remains")
        require(digest(profile_path.read_bytes())==profile_hash and digest(marker.read_bytes())==marker_hash,"Cleanup changed user data")
        require(capsule.resolve().parent==temporary.resolve() and capsule.name.startswith("accessweaver-deployment-package-"),"Unsafe capsule cleanup")
        no_alias(capsule);shutil.rmtree(capsule);cleaned=True;complete=True
    except Exception as error:
        failure=type(error).__name__;trace=error.__traceback__
        while trace:
            if trace.tb_frame.f_code.co_filename==__file__:failure_line=trace.tb_lineno
            trace=trace.tb_next
    report={"schemaVersion":1,"sourceCommit":source,"runID":os.environ["GITHUB_RUN_ID"],"target":"darwin/"+arch,"packages":{v:{"file":c["report"]["packageFile"],"bytes":c["report"]["packageBytes"],"packageSHA256":c["report"]["packageSHA256"],"payloadSHA256":c["report"]["payloadSHA256"],"manifestSHA256":c["report"]["manifestSHA256"],"helperSHA256":c["report"]["helperSHA256"],"payloadSBOMSHA256":c["report"]["payloadSBOMSHA256"]} for v,c in candidates.items()},"stage":stage,"passed":complete,"failureType":failure,"failureSourceLine":failure_line,"operations":operations,"runtimeLeaseCases":lease_cases,"installedControllerLeaseRefusalVerified":complete,"packageScriptsIntegrated":True,"detachedManifestSealingVerified":complete,"detachedPayloadSBOMSealingVerified":complete,"actualApplePackageUpgradeExecuted":complete,"actualUserProfilePreservationVerified":complete,"retainedPriorCopiesVerified":complete,"ownedFixturesRemoved":cleaned,"installedCodeExecutedAsRoot":False,"publicLauncherIntegrated":False,"runtimeLeaseQualified":False,"publisherSignatureVerified":False,"notarized":False,"productUninstallQualified":False,"managedEndpointQualified":False,"abruptTerminationQualified":False,"rebootOrPowerLossQualified":False,"productionQualificationComplete":False}
    (root/"lifecycle-artifact.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    require(complete,"Native deployment package acceptance failed at "+stage+"; owned disposable state retained")
    print(json.dumps({"target":report["target"],"actualApplePackageOperations":len(operations)+len(lease_cases),"passed":True,"productionQualificationComplete":False}))

if __name__=="__main__":main()
