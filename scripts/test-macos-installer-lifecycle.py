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
    require(info.st_uid==0 and info.st_gid==0 and (info.st_nlink==1 or stat.S_ISDIR(info.st_mode)) and info.st_size<=4<<20,"Unexpected fixed fixture ownership/type")
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
    complete=False;stage="preflight-refusals";failure=None;operations=[];profile_hash=None;cleaned=False;refusal_cases=[]
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
        require(capsule.resolve().parent==temporary.resolve() and capsule.name.startswith("accessweaver-macos-installer-"),"Unsafe capsule cleanup")
        no_alias(capsule);shutil.rmtree(capsule);cleaned=True;complete=True
    except Exception as error:failure=type(error).__name__
    result={"schemaVersion":2,"sourceCommit":source,"runID":os.environ["GITHUB_RUN_ID"],"target":"darwin/"+arch,"packageSHA256":report["packageSHA256"],"payloadSHA256":report["payloadSHA256"],"operations":operations,"preflightRefusalCases":refusal_cases,"passed":complete,"stage":stage,"failureType":failure,"cleanInstallExecuted":bool(operations),"actualUserProfilePreservationVerified":complete,"ownedFixturesRemoved":cleaned,"unsigned":True,"publisherSignatureVerified":False,"notarized":False,"upgradeQualified":False,"downgradeQualified":False,"productUninstallQualified":False,"finderInteractionQualified":False,"managedEndpointQualified":False,"rebootOrPowerLossQualified":False,"productionQualificationComplete":False}
    (output/"lifecycle-artifact.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    require(complete,"Disposable native package acceptance failed at "+stage+"; owned fixture retained on disposable host")
    print(json.dumps({"target":result["target"],"cleanInstallAndExistingRefusalPassed":True,"preflightRefusalCases":len(refusal_cases),"productionQualificationComplete":False}))

if __name__=="__main__":main()
