#!/usr/bin/env python3
"""Guarded driver-free clean-install acceptance on disposable hosted Macs only."""
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from macos_installer import BUNDLE_ID,BUNDLE_NAME,bundle_manifest,digest,require,verify_bundle
from macos_package_archive import inspect
from macos_deployment import DETACHED_MANIFEST,verify_deployment_bundle

REPO=Path(__file__).resolve().parent.parent
APP=Path("/Applications")/BUNDLE_NAME
RECEIPTS=[Path("/private/var/db/receipts")/(BUNDLE_ID+suffix) for suffix in (".plist",".bom")]

def no_alias(path):
    path=Path(path)
    for item in (path,)+tuple(path.parents):
        if item.exists() or item.is_symlink():require(not item.is_symlink(),"Fixture path aliases are not supported")

def run(args,env,timeout=120,codes=(0,)):
    start=time.monotonic();result=subprocess.run([str(v) for v in args],cwd=REPO,env=env,capture_output=True,timeout=timeout)
    require(len(result.stdout)+len(result.stderr)<=4<<20,"Native acceptance output exceeds limit")
    require(result.returncode in codes,"Unexpected native package operation exit")
    return result,int((time.monotonic()-start)*1000)

def snapshot_receipts():
    values=[]
    for path in RECEIPTS:
        no_alias(path);info=path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and info.st_size<=4<<20,"Unexpected owned receipt object")
        values.append({"suffix":path.suffix,"bytes":info.st_size,"sha256":digest(path.read_bytes())})
    return values


def fixture_snapshot(path):
    # Leaf aliases are deliberate refusal fixtures; ancestors never may be.
    no_alias(path.parent);info=path.lstat()
    # macOS creates objects with their parent directory's group. These are
    # root-owned refusal fixtures, not installed root:wheel payload files.
    # Capture the actual group and require it unchanged across refusal.
    require(info.st_uid==0 and info.st_gid in (0,path.parent.stat().st_gid) and (info.st_nlink==1 or stat.S_ISDIR(info.st_mode)) and info.st_size<=4<<20,"Unexpected fixed fixture ownership/type")
    value={"inode":info.st_ino,"mode":info.st_mode,"uid":info.st_uid,"gid":info.st_gid}
    if stat.S_ISLNK(info.st_mode):value["target"]=os.readlink(path)
    elif stat.S_ISDIR(info.st_mode):
        require(not list(path.iterdir()),"Refusal fixture directory changed")
    else:
        require(stat.S_ISREG(info.st_mode),"Unsupported refusal fixture")
        value["sha256"]=digest(path.read_bytes())
    return value

def preflight_refusals(package,capsule,environment,marker,results):
    fixed=[APP]+RECEIPTS
    target=capsule/"alias-target";target.mkdir()
    target_marker=target/"preserve";target_marker.write_bytes(b"unrelated alias destination")
    source=capsule/"receipt-fixture";source.write_bytes(b"deliberately invalid package receipt")
    expected_marker=digest(marker.read_bytes());expected_target=digest(target_marker.read_bytes())
    cases=[
        ("existing-app-directory",APP,"directory"),
        ("existing-app-file",APP,"file"),
        ("existing-app-symlink",APP,"symlink"),
        ("dangling-app-symlink",APP,"dangling"),
        ("partial-plist-receipt",RECEIPTS[0],"file"),
        ("partial-bom-receipt",RECEIPTS[1],"file"),
        ("plist-receipt-symlink",RECEIPTS[0],"symlink"),
        ("bom-receipt-symlink",RECEIPTS[1],"dangling"),
    ]
    for name,path,kind in cases:
        results.append({"name":name,"passed":False})
        for item in fixed:
            no_alias(item);require(not item.exists() and not item.is_symlink(),"Unexpected fixed state before refusal fixture")
        require(path in fixed,"Unapproved fixed fixture target")
        if kind=="directory":run(["/usr/bin/sudo","-n","/bin/mkdir","-m","755",path],environment)
        elif kind=="file":run(["/usr/bin/sudo","-n","/bin/cp",source,path],environment)
        else:run(["/usr/bin/sudo","-n","/bin/ln","-s",target if kind=="symlink" else capsule/"absent-alias-target",path],environment)
        observed=path.lstat()
        results[-1].update({"fixtureUID":observed.st_uid,"fixtureGID":observed.st_gid,"parentGID":path.parent.stat().st_gid})
        before=fixture_snapshot(path)
        refused,elapsed=run(["/usr/bin/sudo","-n","/usr/sbin/installer","-pkg",package,"-target","/"],environment,codes=tuple(range(1,256)))
        require(fixture_snapshot(path)==before,"Refused native package changed existing fixture")
        require(all(item==path or not item.exists() and not item.is_symlink() for item in fixed),"Refused native package created unrelated fixed state")
        require(digest(marker.read_bytes())==expected_marker and digest(target_marker.read_bytes())==expected_target and set(target.iterdir())=={target_marker},"Refused native package changed alias destination or unrelated data")
        # Remove only the exact one root-owned object created in this iteration;
        # never traverse a link or recursively delete a refusal fixture.
        require(fixture_snapshot(path)==before,"Fixture changed before cleanup")
        run(["/usr/bin/sudo","-n","/bin/rmdir" if kind=="directory" else "/bin/rm","--",path],environment)
        require(not path.exists() and not path.is_symlink(),"Owned refusal fixture was not removed")
        results[-1].update({"passed":True,"exitCode":refused.returncode,"elapsedMilliseconds":elapsed,"fixtureIdentityAndBytesPreserved":True,"aliasDestinationAndUnrelatedDataPreserved":True,"noAdditionalAppOrReceiptCreated":True,"ownedFixtureRemoved":True})


def owned_bundle_snapshot():
    no_alias(APP);values={};total=0
    for root,dirs,files in os.walk(APP,followlinks=False):
        for item in [Path(root)]+[Path(root)/name for name in files+dirs]:
            name=item.relative_to(APP).as_posix()
            if name in values:continue
            info=item.lstat();require(len(values)<4096 and info.st_size<=64<<20,"Owned snapshot exceeds limits")
            record={"mode":info.st_mode,"uid":info.st_uid,"gid":info.st_gid,"links":info.st_nlink,"inode":info.st_ino,"mtime":info.st_mtime_ns,"ctime":info.st_ctime_ns}
            if stat.S_ISLNK(info.st_mode):record["target"]=os.readlink(item)
            elif stat.S_ISREG(info.st_mode):
                total+=info.st_size;require(total<=128<<20,"Owned snapshot exceeds byte limit");record["sha256"]=digest(item.read_bytes())
            else:require(stat.S_ISDIR(info.st_mode),"Unexpected owned snapshot object")
            values[name]=record
    return values

def upgrade_preflight(capsule,environment,identity,manifest,profile_path,marker,cases,helpers):
    go=shutil.which("go");require(go is not None,"Native SDK missing for upgrade preflight")
    compiler_environment=dict(os.environ,GOTOOLCHAIN="local",GOFLAGS="",GOOS="darwin",GOARCH=identity["arch"],CGO_ENABLED="0")
    binaries={}
    for version in ("0.1.1-alpha","0.1.0-alpha","0.0.9"):
        binary=capsule/("upgrade-preflight-"+version)
        expected=dict(identity,version=version)
        names={"Version":version,"Commit":identity["commit"],"SourceState":"clean","BuiltAt":identity["builtAt"]}
        flags=" ".join("-X github.com/Yunushan/accessweaver/internal/buildinfo."+key+"="+value for key,value in names.items())
        run([go,"build","-mod=readonly","-trimpath","-buildvcs=false","-ldflags",flags,"-o",binary,"./cmd/accessweaver-installer"],compiler_environment,240)
        actual,_=run([binary,"version","--json"],environment,30);require(json.loads(actual.stdout)==expected,"Native upgrade helper build identity differs")
        binaries[version]=binary;helpers.append({"build":expected,"sha256":digest(binary.read_bytes())})
    profile_hash=digest(profile_path.read_bytes());marker_hash=digest(marker.read_bytes())
    def receipts():
        values=[]
        for path in RECEIPTS:
            no_alias(path)
            if path.exists():
                info=path.stat();require(stat.S_ISREG(info.st_mode) and info.st_size<=4<<20,"Unexpected owned receipt fixture")
                values.append({"exists":True,"mode":info.st_mode,"uid":info.st_uid,"gid":info.st_gid,"inode":info.st_ino,"mtime":info.st_mtime_ns,"ctime":info.st_ctime_ns,"sha256":digest(path.read_bytes())})
            else:values.append({"exists":False})
        return values
    def check(name,version,mode=None,elevated=True):
        cases.append({"name":name,"passed":False,"incomingVersion":version})
        before=owned_bundle_snapshot();receipt_before=receipts()
        command=(["/usr/bin/sudo","-n"] if elevated else [])+[binaries[version],"preflight-upgrade"]
        result,elapsed=run(command,environment,30,codes=tuple(range(256)))
        cases[-1].update({"exitCode":result.returncode,"elapsedMilliseconds":elapsed})
        if result.returncode:
            cases[-1]["refusalDiagnosticSHA256"]=digest(result.stderr)
            for text,label in ((b"receipt","receipt"),(b"Applications container","container"),(b"root:wheel","ownership"),(b"ACL","acl"),(b"manifest","inventory"),(b"plist","plist"),(b"root","root-required")):
                if text in result.stderr:cases[-1]["refusalCategory"]=label;break
        require(result.returncode==0 if mode else 1<=result.returncode<=255,"Unexpected native upgrade preflight acceptance")
        if mode:
            value=json.loads(result.stdout)
            require(value["mode"]==mode and value["incomingVersion"]==version and value["installedBuild"]==identity and value["completeProtectedInventoryVerified"] is True,"Native upgrade preflight identity/inventory differs")
            require(value["manifestSHA256"]==digest((APP/"Contents/Resources/INSTALL-MANIFEST.json").read_bytes()) and value["payloadSHA256"]==digest((APP/"Contents/MacOS/accessweaver").read_bytes()),"Native upgrade preflight subject differs")
            require(value["receiptSHA256"]=={r["suffix"]:r["sha256"] for r in snapshot_receipts()},"Native upgrade preflight receipt binding differs")
            require(all(value[k] is False for k in ("mutationPerformed","upgradeExecuted","productionQualificationComplete")),"Read-only preflight scope changed")
            cases[-1]["verifiedDecision"]=value
        require(owned_bundle_snapshot()==before and receipts()==receipt_before,"Read-only upgrade preflight changed app or receipts")
        require(digest(profile_path.read_bytes())==profile_hash and digest(marker.read_bytes())==marker_hash,"Read-only upgrade preflight changed user data")
        require(all(digest(binaries[h["build"]["version"]].read_bytes())==h["sha256"] for h in helpers),"Owned helper bytes changed")
        cases[-1].update({"passed":True,"installedObjectsAndReceiptsPreserved":True,"actualUserProfilePreserved":True,"installedCodeExecutedAsRoot":False,"upgradeExecuted":False})
    check("newer-release-preflight","0.1.1-alpha","upgrade")
    check("same-release-preflight","0.1.0-alpha","reinstall")
    check("older-release-refused","0.0.9")
    check("ordinary-user-refused","0.1.1-alpha",elevated=False)
    core=APP/"Contents/MacOS/accessweaver";saved_core=capsule/"saved-preflight-core";saved_core.write_bytes(core.read_bytes());changed=capsule/"changed-preflight-core";changed.write_bytes(saved_core.read_bytes()+b"changed")
    run(["/usr/bin/sudo","-n","/bin/cp",changed,core],environment)
    check("changed-core-refused","0.1.1-alpha")
    run(["/usr/bin/sudo","-n","/bin/cp",saved_core,core],environment);run(["/usr/bin/sudo","-n","/bin/chmod","755",core],environment);verify_bundle(APP,manifest,identity)
    leaf=APP/"Contents/Resources/README.md";saved_leaf=capsule/"saved-preflight-readme";saved_leaf.write_bytes(leaf.read_bytes())
    extra=APP/"Contents/Resources/upgrade-preflight-extra";require(not extra.exists() and not extra.is_symlink(),"Unexpected preflight fixture leaf")
    run(["/usr/bin/sudo","-n","/bin/cp",saved_leaf,extra],environment);check("unexpected-file-refused","0.1.1-alpha");no_alias(extra);require(digest(extra.read_bytes())==digest(saved_leaf.read_bytes()),"Extra fixture changed before cleanup");run(["/usr/bin/sudo","-n","/bin/rm","--",extra],environment)
    run(["/usr/bin/sudo","-n","/bin/chmod","666",leaf],environment);check("writable-file-refused","0.1.1-alpha");run(["/usr/bin/sudo","-n","/bin/chmod","644",leaf],environment)
    no_alias(leaf);require(digest(leaf.read_bytes())==digest(saved_leaf.read_bytes()),"Readme fixture changed before alias")
    run(["/usr/bin/sudo","-n","/bin/rm","--",leaf],environment);run(["/usr/bin/sudo","-n","/bin/ln","-s",marker,leaf],environment);check("file-alias-refused","0.1.1-alpha")
    require(leaf.is_symlink() and os.readlink(leaf)==str(marker),"Owned alias changed before cleanup");run(["/usr/bin/sudo","-n","/bin/rm","--",leaf],environment);run(["/usr/bin/sudo","-n","/bin/cp",saved_leaf,leaf],environment);run(["/usr/bin/sudo","-n","/bin/chmod","644",leaf],environment)
    acl_before,_=run(["/bin/ls","-le",leaf],environment);require(b"everyone allow write" not in acl_before.stdout,"Do not replace an existing ACL fixture")
    run(["/usr/bin/sudo","-n","/bin/chmod","+a","everyone allow write",leaf],environment);check("acl-mutation-grant-refused","0.1.1-alpha");run(["/usr/bin/sudo","-n","/bin/chmod","-a","everyone allow write",leaf],environment)
    acl_after,_=run(["/bin/ls","-le",leaf],environment);require(acl_after.stdout==acl_before.stdout,"Owned ACL fixture was not restored")
    receipt=RECEIPTS[1];backup=capsule/"saved-owned-package.bom";no_alias(backup);require(not backup.exists() and backup.parent.resolve()==capsule.resolve(),"Unsafe owned receipt backup")
    original_receipt=snapshot_receipts();run(["/usr/bin/sudo","-n","/bin/mv",receipt,backup],environment);check("missing-bom-receipt-refused","0.1.1-alpha")
    no_alias(backup);require(not receipt.exists() and digest(backup.read_bytes())==original_receipt[1]["sha256"],"Owned receipt backup changed");run(["/usr/bin/sudo","-n","/bin/mv",backup,receipt],environment);require(snapshot_receipts()==original_receipt,"Owned receipt fixture was not restored")
    verify_bundle(APP,manifest,identity);check("restored-state-preflight","0.1.1-alpha","upgrade")

def deployment_failure_diagnostic(output):
    # Go prints assertion details before its potentially long subtest summary.
    # Keep those details as well as the final status within the existing 12 KB
    # diagnostic budget. Input is only the guarded source-built fixture output.
    text=output.decode("utf-8",errors="replace")
    text=re.sub(r"/private/tmp/accessweaver-deployment-[^\s/:]+","[owned-fixture]",text)
    lines=text.splitlines();selected=set()
    for index,line in enumerate(lines):
        if re.search(r"\b[A-Za-z0-9_]+\.go:[0-9]+:|--- FAIL:|^panic:|^fatal error:",line):
            selected.update(range(index,min(index+4,len(lines))))
    def bounded(value,limit,tail=False):
        data=value.encode("utf-8")
        return (data[-limit:] if tail else data[:limit]).decode("utf-8",errors="ignore")
    if not selected:return bounded(text,12000,True)
    assertions="\n".join(lines[index] for index in sorted(selected))
    return "Native fixture assertions:\n"+bounded(assertions,7900)+"\nNative fixture tail:\n"+bounded(text,4000,True)


def deployment_transactions(capsule,environment,identity):
    go=shutil.which("go");require(go is not None,"Native SDK missing for deployment transactions")
    compiler_environment=dict(os.environ,GOTOOLCHAIN="local",GOFLAGS="",GOOS="darwin",GOARCH=identity["arch"],CGO_ENABLED="0")
    binary=capsule/"deployment-transactions.test"
    run([go,"test","-c","-mod=readonly","-trimpath","-buildvcs=false","-o",binary,"./internal/packageupgrade"],compiler_environment,240)
    before=owned_bundle_snapshot();receipts=snapshot_receipts()
    # The outer driver has already required the explicit hosted/disposable
    # opt-in. Pass only fixed fixture guards, not workflow credentials, to root.
    command=["/usr/bin/sudo","-n","/usr/bin/env","-i","PATH=/usr/bin:/bin:/usr/sbin:/sbin","LANG=C","LC_ALL=C","TZ=UTC","GITHUB_ACTIONS=true","RUNNER_ENVIRONMENT=github-hosted","RUNNER_OS=macOS","ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST=1",binary,"-test.run=^TestDarwinDeploymentRootCopyRecovery$","-test.v","-test.timeout=120s"]
    result,elapsed=run(command,environment,150,codes=tuple(range(256)))
    if result.returncode:
        # Only this trusted test binary's bounded fixture diagnostics enter the
        # job log. No inherited credentials or user profile contents are input.
        print(deployment_failure_diagnostic(result.stdout+b"\nNative fixture stderr:\n"+result.stderr),flush=True)
    require(result.returncode==0,"Native protected deployment transaction fixture failed")
    lines=[line.split("DEPLOYMENT-RESULT ",1)[1] for line in result.stdout.decode("utf-8").splitlines() if "DEPLOYMENT-RESULT " in line]
    require(len(lines)==1 and b"--- PASS: TestDarwinDeploymentRootCopyRecovery" in result.stdout,"Native deployment test did not execute to completion")
    value=json.loads(lines[0])
    require(value["manifestSHA256"]==digest((APP/"Contents/Resources/INSTALL-MANIFEST.json").read_bytes()) and value["payloadSHA256"]==digest((APP/"Contents/MacOS/accessweaver").read_bytes()) and value["version"]==identity["version"],"Copied deployment subjects differ from installed package")
    require(owned_bundle_snapshot()==before and snapshot_receipts()==receipts,"Deployment transaction fixture changed installed app/receipts")
    value.update({"testExecutableSHA256":digest(binary.read_bytes()),"elapsedMilliseconds":elapsed,"installedObjectsAndReceiptsPreserved":True,"fixtureParent":"private-exclusive-temporary-directory","packageScriptsIntegrated":False})
    return value


AUTHORITY=Path("/Library/Application Support/AccessWeaver")
INCOMING=Path("/Library/Application Support/AccessWeaver Incoming")

def prepare_fixed_deployment(capsule,environment,identity,manifest):
    for path in (AUTHORITY,INCOMING):
        no_alias(path);require(not path.exists(),"Existing deployment authority/staging must never become a fixture")
    binary=capsule/"sealed-deployment-helper"
    manifest_hash=digest((APP/"Contents/Resources/INSTALL-MANIFEST.json").read_bytes())
    payload_hash=digest((APP/"Contents/MacOS/accessweaver").read_bytes())
    names={"Version":identity["version"],"Commit":identity["commit"],"SourceState":"clean","BuiltAt":identity["builtAt"]}
    flags=["-X github.com/Yunushan/accessweaver/internal/buildinfo."+key+"="+value for key,value in names.items()]
    flags.extend("-X github.com/Yunushan/accessweaver/internal/packageupgrade."+key+"="+value for key,value in {"sealedVersion":identity["version"],"sealedManifestSHA256":manifest_hash,"sealedPayloadSHA256":payload_hash}.items())
    compiler_environment=dict(os.environ,GOTOOLCHAIN="local",GOFLAGS="",GOOS="darwin",GOARCH=identity["arch"],CGO_ENABLED="0")
    go=shutil.which("go");require(go is not None,"Native SDK missing for sealed deployment helper")
    run([go,"build","-mod=readonly","-trimpath","-buildvcs=false","-ldflags"," ".join(flags),"-o",binary,"./cmd/accessweaver-installer"],compiler_environment,240)
    actual,_=run([binary,"version","--json"],environment,30);require(json.loads(actual.stdout)==identity,"Sealed helper runtime identity differs")
    ordinary,_=run([binary,"prepare-deployment"],environment,30,codes=tuple(range(1,256)))
    legacy,_=run(["/usr/bin/sudo","-n",binary,"prepare-deployment"],environment,30,codes=tuple(range(1,256)))
    require(b"native deployment operation requires root" in ordinary.stderr,"Missing native root refusal")
    require(b"legacy receipt exists; explicit migration is required" in legacy.stderr,"Missing native legacy receipt refusal")
    require(not AUTHORITY.exists() and not INCOMING.exists(),"Refused helper created authority/staging")
    candidate=capsule/"deployment-candidate.app";shutil.copytree(APP,candidate);verify_bundle(candidate,manifest,identity)
    stage=INCOMING/manifest_hash
    run(["/usr/bin/sudo","-n","/bin/mkdir","-m","755",INCOMING],environment)
    run(["/usr/bin/sudo","-n","/usr/sbin/chown","root:wheel",INCOMING],environment)
    run(["/usr/bin/sudo","-n","/bin/mkdir","-m","755",stage],environment)
    run(["/usr/bin/sudo","-n","/bin/cp","-R",APP,stage/"AccessWeaver.app"],environment)
    verify_bundle(stage/"AccessWeaver.app",manifest,identity)
    return {"binary":binary,"candidate":candidate,"stage":stage,"identity":identity,"manifest":manifest,"manifestSHA256":manifest_hash,"payloadSHA256":payload_hash,"sha256":digest(binary.read_bytes()),"rootAndLegacyRefusalsPreservedAbsentAuthority":True}

def fixed_deployment_lifecycle(context,capsule,environment):
    binary=context["binary"];identity=context["identity"];stage=context["stage"];cases=[]
    require(not APP.exists() and all(not path.exists() for path in RECEIPTS),"Legacy cleanup is required before versioned deployment")
    def record():
        path=AUTHORITY/"state/deployment.json"
        if not path.exists():return None
        no_alias(path);info=path.stat();require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0 and info.st_nlink==1 and info.st_size<=16384,"Unexpected deployment record")
        return {"inode":info.st_ino,"mtime":info.st_mtime_ns,"ctime":info.st_ctime_ns,"sha256":digest(path.read_bytes())}
    def operation(name,op,generation=None,state=None,published=None,success=True,helper=None):
        before=record()
        result,elapsed=run(["/usr/bin/sudo","-n",helper or binary,op],environment,90,codes=tuple(range(256)))
        require((result.returncode==0)==success,"Unexpected fixed deployment helper result: "+name)
        value=json.loads(result.stdout) if result.stdout.strip() else None
        if success:
            require(value["schemaVersion"]==1 and value["operation"]==op and value["generation"]==generation and value["state"]==state and value["operationRecordPublished"] is published,"Fixed deployment transition differs: "+name)
            require(value["version"]==identity["version"] and value["manifestSHA256"]==context["manifestSHA256"] and value["payloadSHA256"]==context["payloadSHA256"],"Fixed deployment subject differs")
            require(re.fullmatch("[a-f0-9]{32}",value["slotID"]) is not None and value["publisherSignatureVerified"] is False and value["productionQualificationComplete"] is False,"Fixed deployment scope differs")
        if not success or published is False:require(record()==before,"Refused/idempotent deployment changed active record: "+name)
        cases.append({"name":name,"operation":op,"exitCode":result.returncode,"elapsedMilliseconds":elapsed,"passed":True,"result":value,"recordPreserved":record()==before})
        return value
    operation("activation-without-authority-refused","activate-deployment",success=False)
    require(not AUTHORITY.exists(),"Activation initialized absent authority")
    operation("unsealed-helper-refused","prepare-deployment",success=False,helper=capsule/"upgrade-preflight-0.1.0-alpha")
    require(not AUTHORITY.exists(),"Unsealed helper initialized absent authority")
    prepared=operation("prepared","prepare-deployment",0,"prepared",True)
    again=operation("prepare-retry-idempotent","prepare-deployment",0,"prepared",False)
    require(again["slotID"]==prepared["slotID"],"Prepare retry allocated a different transaction")
    leaf=stage/"AccessWeaver.app/Contents/Resources/README.md"
    original=capsule/"deployment-readme";original.write_bytes(leaf.read_bytes())
    changed=capsule/"deployment-readme-changed";changed.write_bytes(original.read_bytes()+b"changed")
    run(["/usr/bin/sudo","-n","/bin/cp",changed,leaf],environment)
    operation("changed-incoming-refused","activate-deployment",success=False)
    run(["/usr/bin/sudo","-n","/bin/cp",original,leaf],environment)
    verify_bundle(stage/"AccessWeaver.app",context["manifest"],identity)
    active=operation("activated","activate-deployment",1,"active",True)
    operation("activation-retry-idempotent","activate-deployment",1,"active",False)
    active_app=AUTHORITY/"versions"/active["slotID"]/"AccessWeaver.app"
    verify_bundle(active_app,context["manifest"],identity)
    runtime,_=run([active_app/"Contents/MacOS/accessweaver","version","--json"],environment,30)
    require(json.loads(runtime.stdout)==identity,"Ordinary-user active runtime identity differs")
    # Simulated package-receipt staging removal: only this exact newly copied,
    # fully inventoried input is removed. The active independent copy remains.
    run(["/usr/bin/sudo","-n","/bin/rm","-rf","--",stage/"AccessWeaver.app"],environment)
    require(not (stage/"AccessWeaver.app").exists(),"Owned incoming fixture was not removed")
    operation("active-survives-staging-removal","activate-deployment",1,"active",False)
    verify_bundle(active_app,context["manifest"],identity)
    stale=operation("reinstall-prepared","prepare-deployment",1,"prepared",True)
    operation("missing-incoming-refused","activate-deployment",success=False)
    operation("deactivated-with-pending","deactivate-deployment",2,"inactive",True)
    operation("stale-activation-fenced","activate-deployment",success=False)
    operation("stale-prepare-fenced","prepare-deployment",success=False)
    abandoned=operation("stale-preparation-abandoned","abandon-deployment",2,"abandoned",True)
    require(abandoned["slotID"]==stale["slotID"],"Abandon changed a different transaction")
    require((AUTHORITY/"versions"/stale["slotID"]).is_dir(),"Abandon deleted retained slot")
    operation("abandon-retry-refused","abandon-deployment",success=False)
    operation("restored-retry-prepared","prepare-deployment",2,"prepared",True)
    run(["/usr/bin/sudo","-n","/bin/cp","-R",context["candidate"],stage/"AccessWeaver.app"],environment)
    verify_bundle(stage/"AccessWeaver.app",context["manifest"],identity)
    # Migrate only this newly restored owned incoming copy. The retained first
    # slot stays in its original embedded layout and must continue to verify.
    sidecar=stage/DETACHED_MANIFEST;no_alias(sidecar);require(not sidecar.exists(),"Unexpected detached fixture manifest")
    embedded=stage/"AccessWeaver.app/Contents/Resources/INSTALL-MANIFEST.json"
    run(["/usr/bin/sudo","-n","/bin/mv","--",embedded,sidecar],environment)
    encoded=(context["candidate"]/"Contents/Resources/INSTALL-MANIFEST.json").read_bytes()
    require(digest(encoded)==context["manifestSHA256"],"Restored fixture manifest changed")
    verify_deployment_bundle(stage/"AccessWeaver.app",context["manifest"],identity,encoded)
    restored=operation("restored-retry-activated","activate-deployment",3,"active",True)
    restored_app=AUTHORITY/"versions"/restored["slotID"]/"AccessWeaver.app"
    verify_deployment_bundle(restored_app,context["manifest"],identity,encoded)
    verify_bundle(active_app,context["manifest"],identity)
    operation("restored-activation-idempotent","activate-deployment",3,"active",False)
    operation("final-deactivation","deactivate-deployment",4,"inactive",True)
    final=json.loads((AUTHORITY/"state/deployment.json").read_bytes())
    require(final["generation"]==4 and final["active"]["id"]=="" and final["pending"]==[],"Unexpected retained tombstone")
    # Explicit fixture cleanup is separate from the product's conservative
    # retention policy. Both roots were absent at entry and created by this test.
    for path in (AUTHORITY,INCOMING):
        no_alias(path);info=path.stat();require(path.parent==Path("/Library/Application Support") and path.name in ("AccessWeaver","AccessWeaver Incoming") and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755,"Unsafe fixed fixture cleanup")
        aliases,_=run(["/usr/bin/sudo","-n","/usr/bin/find",path,"-type","l","-print"],environment)
        require(not aliases.stdout.strip(),"Alias found in owned deployment fixture")
    run(["/usr/bin/sudo","-n","/bin/rm","-rf","--",AUTHORITY,INCOMING],environment)
    require(not AUTHORITY.exists() and not INCOMING.exists() and not APP.exists() and all(not p.exists() for p in RECEIPTS),"Owned fixed deployment state was not removed")
    require(digest(binary.read_bytes())==context["sha256"],"Sealed deployment helper changed")
    return {"schemaVersion":1,"build":identity,"helperSHA256":context["sha256"],"manifestSHA256":context["manifestSHA256"],"payloadSHA256":context["payloadSHA256"],"cases":cases,"rootAndLegacyRefusalsPreservedAbsentAuthority":True,"ordinaryUserActiveRuntimeVerified":True,"stagingRemovalPreservedActiveCopy":True,"detachedManifestBridgeVerified":True,"ownedFixedFixtureCleanupVerified":True,"installedCodeExecutedAsRoot":False,"actualApplePackageUpgradeExecuted":False,"packageScriptsIntegrated":False,"productionQualificationComplete":False}


def main():
    require(platform.system()=="Darwin" and os.geteuid()!=0,"Acceptance requires an ordinary-user native Mac host")
    require(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted" and os.environ.get("GITHUB_REPOSITORY")=="Yunushan/accessweaver" and os.environ.get("ACCESSWEAVER_DISPOSABLE_MACOS_INSTALLER_TEST")=="1","Explicit disposable hosted Mac opt-in required")
    source=os.environ.get("GITHUB_SHA","");require(re.fullmatch("[a-f0-9]{40}",source) is not None,"Expected exact hosted source")
    arch=os.environ.get("ACCESSWEAVER_MACOS_INSTALLER_ARCH","");require(arch in ("amd64","arm64"),"Missing native package target")
    require(subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO,text=True).strip()==source and not subprocess.check_output(["git","status","--porcelain","--untracked-files=no"],cwd=REPO).strip(),"Expected clean exact-source checkout")
    output=REPO/"build/macos-installer-checks"/arch/"0.1.0-alpha"
    report=json.loads((output/"compiler-artifact.json").read_text(encoding="utf-8"));identity=json.loads((output/"BUILD-INFO.json").read_text(encoding="utf-8"));manifest=json.loads((output/"INSTALL-MANIFEST.json").read_text(encoding="utf-8"))
    require(report["sourceCommit"]==source and report["sourceState"]=="clean" and identity["commit"]==source and identity["arch"]==arch and report["target"]=="darwin/"+arch,"Package source/target mismatch")
    package=output/report["packageFile"];no_alias(package)
    require(digest(package.read_bytes())==report["packageSHA256"],"Package changed after construction")
    inspected=inspect(package.read_bytes(),manifest,identity);require(inspected==report["archiveInspection"],"Independent package inspection differs")
    no_alias(APP)
    require(str(APP)=="/Applications/AccessWeaver.app" and not APP.exists() and not APP.is_symlink(),"Existing applications must never become fixture state")
    for path in RECEIPTS:
        no_alias(path);require(not path.exists() and not path.is_symlink(),"Existing package receipts must never become fixture state")
    require(not Path("/Library/Preferences/AccessWeaver").exists(),"Managed endpoints must never be used as fixtures")
    temporary=Path(os.environ["RUNNER_TEMP"]);no_alias(temporary)
    capsule=Path(tempfile.mkdtemp(prefix="accessweaver-macos-installer-",dir=temporary));user=capsule/"user";user.mkdir();private_temp=capsule/"tmp";private_temp.mkdir()
    environment={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":str(user),"TMPDIR":str(private_temp),"LANG":"C","LC_ALL":"C","TZ":"UTC","ACCESSWEAVER_NO_BROWSER":"1"}
    marker=user/"preserve.json";marker.write_text('{"preserve":"unrelated"}',encoding="utf-8");marker_hash=digest(marker.read_bytes())
    complete=False;stage="preflight-refusals";failure=None;operations=[];profile_hash=None;cleaned=False;refusal_cases=[];failure_line=None;upgrade_cases=[];upgrade_helpers=[];deployment_report=None;fixed_deployment_report=None;fixed_context=None
    try:
        preflight_refusals(package,capsule,environment,marker,refusal_cases)
        stage="install"
        installed,elapsed=run(["/usr/bin/sudo","-n","/usr/sbin/installer","-pkg",package,"-target","/"],environment)
        verify_bundle(APP,manifest,identity)
        for root,dirs,files in os.walk(APP):
            for item in [Path(root)]+[Path(root)/name for name in files]:
                info=item.lstat();require(info.st_uid==0 and info.st_gid==0 and not info.st_mode&0o6022,"Installed app ownership/modes differ")
        binary=APP/"Contents/MacOS/accessweaver"
        actual,_=run([binary,"version","--json"],environment,30);require(json.loads(actual.stdout)==identity,"Installed native runtime identity differs")
        receipt_before=snapshot_receipts();operations.append({"operation":"clean-install","exitCode":installed.returncode,"elapsedMilliseconds":elapsed,"payloadAndReceiptsVerified":True})
        stage="profile-preservation"
        template,_=run([binary,"show","discord-proxy"],environment,30);profile=json.loads(template.stdout);profile["id"]="package-preserve";profile["name"]="Preserved package acceptance profile"
        request=capsule/"profile.json";request.write_text(json.dumps(profile),encoding="utf-8")
        run([binary,"import",request],environment,30)
        profile_path=user/"Library/Application Support/AccessWeaver/profiles/package-preserve.json"
        no_alias(profile_path);require(profile_path.is_file(),"Real ordinary-user profile was not saved")
        profile_hash=digest(profile_path.read_bytes())
        check,_=run([binary,"show","package-preserve"],environment,30);require(json.loads(check.stdout)["name"]==profile["name"],"Installed core did not round-trip actual saved profile")
        before=bundle_manifest(APP)
        stage="native-upgrade-preflight"
        upgrade_preflight(capsule,environment,identity,manifest,profile_path,marker,upgrade_cases,upgrade_helpers)
        stage="protected-deployment-transactions"
        deployment_report=deployment_transactions(capsule,environment,identity)
        require(digest(profile_path.read_bytes())==profile_hash and digest(marker.read_bytes())==marker_hash,"Deployment transactions changed user data")
        stage="sealed-deployment-helper-preparation"
        fixed_context=prepare_fixed_deployment(capsule,environment,identity,manifest)
        stage="existing-install-refusal"
        refused,elapsed=run(["/usr/bin/sudo","-n","/usr/sbin/installer","-pkg",package,"-target","/"],environment,codes=tuple(range(1,256)))
        require(bundle_manifest(APP)==before and snapshot_receipts()==receipt_before,"Refused experimental reinstall changed app or receipt bytes")
        require(digest(profile_path.read_bytes())==profile_hash and digest(marker.read_bytes())==marker_hash,"Refused package changed user data")
        actual,_=run([binary,"version","--json"],environment,30);require(json.loads(actual.stdout)==identity,"Refused reinstall changed actual runtime")
        operations.append({"operation":"existing-install-refused","exitCode":refused.returncode,"elapsedMilliseconds":elapsed,"installedFilesAndReceiptBytesPreserved":True,"actualUserProfilePreserved":True})
        stage="owned-fixture-cleanup"
        # This is test cleanup, not a product uninstaller. Refuse unexpected
        # contents before the one fixed owned app and receipt are removed.
        verify_bundle(APP,manifest,identity);require(snapshot_receipts()==receipt_before,"Owned receipt changed before cleanup")
        no_alias(APP);require(APP.parent==Path("/Applications") and APP.name==BUNDLE_NAME,"Unexpected cleanup target")
        run(["/usr/bin/sudo","-n","/bin/rm","-rf","--",APP],environment)
        # The independently installed valid receipt must also block a package
        # when the app is absent. The app was removed as verified test cleanup;
        # the receipt and real profile remain unchanged until this check passes.
        require(not APP.exists() and not APP.is_symlink(),"App fixture remains before receipt-only refusal")
        refused,elapsed=run(["/usr/bin/sudo","-n","/usr/sbin/installer","-pkg",package,"-target","/"],environment,codes=tuple(range(1,256)))
        require(not APP.exists() and not APP.is_symlink() and snapshot_receipts()==receipt_before,"Receipt-only refusal changed installed receipt or recreated app")
        require(digest(profile_path.read_bytes())==profile_hash and digest(marker.read_bytes())==marker_hash,"Receipt-only refusal changed user data")
        operations.append({"operation":"valid-receipt-only-refused","exitCode":refused.returncode,"elapsedMilliseconds":elapsed,"receiptBytesPreserved":True,"appNotRecreated":True,"actualUserProfilePreserved":True})
        run(["/usr/bin/sudo","-n","/usr/sbin/pkgutil","--forget",BUNDLE_ID],environment)
        require(not APP.exists() and all(not path.exists() for path in RECEIPTS),"Owned package fixtures were not removed")
        require(digest(profile_path.read_bytes())==profile_hash and digest(marker.read_bytes())==marker_hash,"Owned cleanup changed user data")
        stage="fixed-deployment-helper-lifecycle"
        fixed_deployment_report=fixed_deployment_lifecycle(fixed_context,capsule,environment)
        require(digest(profile_path.read_bytes())==profile_hash and digest(marker.read_bytes())==marker_hash,"Fixed deployment helper changed user data")
        stage="owned-fixture-cleanup"
        require(capsule.resolve().parent==temporary.resolve() and capsule.name.startswith("accessweaver-macos-installer-"),"Unsafe capsule cleanup")
        no_alias(capsule);shutil.rmtree(capsule);cleaned=True;complete=True
    except Exception as error:
        failure=type(error).__name__
        trace=error.__traceback__
        while trace is not None:
            if trace.tb_frame.f_code.co_filename==__file__:failure_line=trace.tb_lineno
            trace=trace.tb_next
    result={"schemaVersion":2,"sourceCommit":source,"runID":os.environ["GITHUB_RUN_ID"],"target":"darwin/"+arch,"packageSHA256":report["packageSHA256"],"payloadSHA256":report["payloadSHA256"],"operations":operations,"preflightRefusalCases":refusal_cases,"nativeUpgradePreflightCases":upgrade_cases,"nativeUpgradePreflightHelpers":upgrade_helpers,"nativeUpgradeExecuted":False,"protectedDeploymentTransactions":deployment_report,"fixedDeploymentHelper":fixed_deployment_report,"passed":complete,"stage":stage,"failureType":failure,"failureSourceLine":failure_line,"cleanInstallExecuted":bool(operations),"actualUserProfilePreservationVerified":complete,"ownedFixturesRemoved":cleaned,"unsigned":True,"publisherSignatureVerified":False,"notarized":False,"upgradeQualified":False,"downgradeQualified":False,"productUninstallQualified":False,"finderInteractionQualified":False,"managedEndpointQualified":False,"rebootOrPowerLossQualified":False,"productionQualificationComplete":False}
    (output/"lifecycle-artifact.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    require(complete,"Disposable native package acceptance failed at "+stage+"; owned fixture retained on disposable host")
    print(json.dumps({"target":result["target"],"cleanInstallAndExistingRefusalPassed":True,"preflightRefusalCases":len(refusal_cases),"productionQualificationComplete":False}))

if __name__=="__main__":main()
