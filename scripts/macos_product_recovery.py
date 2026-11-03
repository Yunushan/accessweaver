"""Test-only real write-fault support; never installed or used by product code."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

from macos_installer import digest,require
from macos_deployment import inspect_deployment
from macos_package_archive import flat_members,cpio,inflate

REPO=Path(__file__).resolve().parent.parent
AUTHORITY=Path("/Library/Application Support/AccessWeaver")
LATEST="0.1.1-alpha"
LIMITS=(4096,1<<20)


def identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def no_alias(path):
    for item in (path,)+tuple(path.parents):
        require(not item.is_symlink(),"Partial-copy observer refuses aliases")


def partial_inventory(root,expected,owner=0,group=0):
    root=Path(root);no_alias(root)
    require("" in expected and expected[""]["directory"] and len(expected)<=4096,"Partial-copy source inventory differs")
    initial=root.lstat();records=[];partial=[];total=0;stack=[(root,"")]
    while stack:
        path,name=stack.pop();no_alias(path);before=path.lstat()
        require(name in expected and before.st_uid==owner and before.st_gid==group and before.st_dev==initial.st_dev,"Unknown or unowned partial-copy object")
        require(not getattr(before,"st_flags",0),"Flagged partial-copy object "+name+": "+str(getattr(before,"st_flags",0)))
        source=expected[name];mode=stat.S_IMODE(before.st_mode)
        row={"path":name,"mode":format(mode,"04o"),"uid":before.st_uid,"gid":before.st_gid,"device":before.st_dev,"inode":before.st_ino,"links":before.st_nlink,"mtimeNs":before.st_mtime_ns,"ctimeNs":before.st_ctime_ns}
        if source["directory"]:
            require(stat.S_ISDIR(before.st_mode) and mode in (0o700,0o755),"Partial-copy directory differs")
            names=sorted(p.name for p in path.iterdir());require(len(names)<=4096 and len(records)+len(stack)+len(names)<=4096,"Partial-copy inventory exceeds budget")
            for child in reversed(names):stack.append((path/child,child if not name else name+"/"+child))
            row["kind"]="directory"
        else:
            require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and mode in (0o600,source["mode"]),"Partial-copy file ownership/type/mode differs")
            expected_bytes=source["data"];require(0<=before.st_size<=len(expected_bytes)<=64<<20,"Partial-copy file size differs")
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                require(identity(os.fstat(fd))==identity(before),"Partial-copy file changed before read")
                with os.fdopen(fd,"rb",closefd=False) as stream:data=stream.read(before.st_size+1)
                require(identity(os.fstat(fd))==identity(before),"Partial-copy file changed during read")
            finally:os.close(fd)
            require(len(data)==before.st_size and data==expected_bytes[:len(data)],"Partial-copy bytes are not an authenticated source prefix")
            total+=len(data);require(total<=64<<20,"Partial-copy bytes exceed budget")
            row.update(kind="file",bytes=len(data),expectedBytes=len(expected_bytes),sha256=digest(data),complete=len(data)==len(expected_bytes))
            if not row["complete"]:partial.append(name)
        require(identity(path.lstat())==identity(before),"Partial-copy object changed during inspection")
        records.append(row)
    require(identity(root.lstat())==identity(initial),"Partial-copy root changed during inspection")
    records.sort(key=lambda r:r["path"])
    value={"entries":records,"partialFiles":sorted(partial),"allKnownSourcePrefixesVerified":True,"bytes":total}
    return value


def root_guard():
    require(platform.system()=="Darwin" and os.geteuid()==0,"Root recovery observation requires native macOS")
    required={"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted","RUNNER_OS":"macOS","GITHUB_REPOSITORY":"Yunushan/accessweaver","ACCESSWEAVER_DISPOSABLE_MACOS_PRODUCT_RECOVERY_TEST":"1"}
    require(all(os.environ.get(k)==v for k,v in required.items()),"Explicit disposable recovery opt-in required")
    require(Path(os.environ.get("GITHUB_WORKSPACE","")).resolve()==REPO and re.fullmatch("[a-f0-9]{40}",os.environ.get("GITHUB_SHA","")) is not None,"Recovery source workspace differs")


def source():
    root_guard();arch=os.environ.get("ACCESSWEAVER_MACOS_INSTALLER_ARCH","")
    require(arch in ("amd64","arm64"),"Recovery architecture differs")
    base=REPO/"build/macos-deployment-checks"/arch/LATEST
    report=json.loads((base/"compiler-artifact.json").read_bytes());build=json.loads((base/"BUILD-INFO.json").read_bytes())
    require(report["sourceCommit"]==os.environ["GITHUB_SHA"]==build["commit"] and build["sourceState"]=="clean" and build["arch"]==arch and build["version"]==LATEST,"Recovery package source differs")
    package=base/("accessweaver-"+LATEST+"-darwin-"+arch+"-deployment-experimental.pkg");no_alias(package);info=package.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=64<<20,"Recovery package type/size differs")
    raw=package.read_bytes()
    require(digest(raw)==report["packageSHA256"] and inspect_deployment(raw,(base/"INSTALL-MANIFEST.json").read_bytes(),build,json.loads((base/"SCRIPT-MANIFEST.json").read_bytes()))==report["archiveInspection"],"Recovery package changed")
    return report,cpio(inflate(flat_members(raw)["Payload"],64<<20,31))


def inspect_root_slot(slot):
    report,expected=source()
    require(type(slot) is dict and set(slot)=={"id","device","inode","identity"} and re.fullmatch("[a-f0-9]{32}",slot["id"]) is not None,"Recovery slot identity differs")
    require(slot["identity"]=={"version":LATEST,"manifestSHA256":report["manifestSHA256"],"payloadSHA256":report["payloadSHA256"]},"Recovery slot seal differs")
    root=AUTHORITY/"versions"/slot["id"];no_alias(root);info=root.lstat()
    require(info.st_dev==slot["device"] and info.st_ino==slot["inode"],"Recovery slot directory identity changed")
    return partial_inventory(root,expected)


def limited_exec(helper,limit):
    report,_=source();require(type(limit) is int and limit in LIMITS,"Unexpected write-fault limit")
    helper=Path(helper);no_alias(helper);parent=helper.parent
    require(parent.parent==Path(os.environ["RUNNER_TEMP"]).resolve() and parent.name.startswith("accessweaver-desktop-package-") and helper.name=="core-helper","Write-fault helper escaped owned fixture")
    info=helper.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==parent.stat().st_uid!=0 and stat.S_IMODE(info.st_mode)==0o755 and digest(helper.read_bytes())==report["helperSHA256"],"Write-fault helper differs from actual package")
    import resource
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
    require(resource.getrlimit(resource.RLIMIT_FSIZE)==(limit,limit),"Kernel file-size limit not applied")
    print(json.dumps({"schemaVersion":1,"euid":os.geteuid(),"softFileSizeBytes":limit,"hardFileSizeBytes":limit,"coreDumpLimitBytes":resource.getrlimit(resource.RLIMIT_CORE)[0],"scope":"owned-helper-process"}),flush=True)
    os.execv(helper,[str(helper),"activate-deployment"])
