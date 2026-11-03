#!/usr/bin/env python3
"""Actual public desktop components and LaunchServices on opted-in disposable Macs."""
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

from macos_installer import BUNDLE_NAME,digest,require
from macos_deployment import PACKAGE_ID,INCOMING,inspect_deployment,verify_deployment_bundle
from macos_desktop import DESKTOP_ID,ROOT,BINARY,record_name,package_id,component_name,validate_record,verify_bundle,inspect_component
from macos_package_archive import flat_members,cpio,inflate
from macos_product import component_inputs,product_name,inspect_product,product_installer_observation,product_install_log_window

REPO=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location("accessweaver_desktop_fixture_support",Path(__file__).with_name("test-macos-installer-lifecycle.py"))
support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
no_alias=support.no_alias

def run(args,env,timeout=120,codes=(0,)):
    result,elapsed=support.run(args,env,timeout,codes=tuple(range(256)))
    if result.returncode not in codes:
        diagnostic=(result.stdout+result.stderr)[-8000:].decode("utf-8",errors="replace")
        if env.get("HOME"):diagnostic=diagnostic.replace(str(Path(env["HOME"]).parent),"[owned-capsule]")
        print("Native desktop command failed: "+Path(args[0]).name+"\n"+diagnostic,flush=True)
    require(result.returncode in codes,"Unexpected native desktop command exit")
    return result,elapsed
AUTHORITY=Path("/Library/Application Support/AccessWeaver");INPUT=Path(INCOMING);DESKTOP=Path(ROOT);APP=Path("/Applications")/BUNDLE_NAME
VERSIONS=("0.1.0-alpha","0.1.1-alpha");RECEIPTS=Path("/private/var/db/receipts")


def root_regular(path,limit):
    no_alias(path);info=path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0 and info.st_nlink==1 and info.st_size<=limit,"Unexpected owned desktop regular file")
    return path.read_bytes()


def main(product_mode=False):
    require(support.platform.system()=="Darwin" and os.geteuid()!=0,"Native ordinary-user desktop driver required")
    require(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted" and os.environ.get("GITHUB_REPOSITORY")=="Yunushan/accessweaver" and os.environ.get("ACCESSWEAVER_DISPOSABLE_MACOS_PRODUCT_PACKAGE_TEST" if product_mode else "ACCESSWEAVER_DISPOSABLE_MACOS_DESKTOP_PACKAGE_TEST")=="1","Explicit disposable desktop opt-in required")
    source=os.environ.get("GITHUB_SHA","");arch=os.environ.get("ACCESSWEAVER_MACOS_INSTALLER_ARCH","")
    require(re.fullmatch("[a-f0-9]{40}",source) is not None and arch in ("amd64","arm64"),"Missing native desktop source/architecture")
    require(subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO,text=True).strip()==source and not subprocess.check_output(["git","status","--porcelain","--untracked-files=no"],cwd=REPO).strip(),"Clean exact-source checkout required")
    base=REPO/"build/macos-deployment-checks"/arch;core={};desktop={};receipt_ids={PACKAGE_ID,DESKTOP_ID}
    for version in VERSIONS:
        output=base/version;identity=json.loads((output/"BUILD-INFO.json").read_bytes());report=json.loads((output/"compiler-artifact.json").read_bytes())
        require(identity["commit"]==source and identity["arch"]==arch and identity["version"]==version and identity["sourceState"]=="clean","Core source/build differs")
        package=output/("accessweaver-"+version+"-darwin-"+arch+"-deployment-experimental.pkg");encoded=(output/"INSTALL-MANIFEST.json").read_bytes()
        require(inspect_deployment(package.read_bytes(),encoded,identity,json.loads((output/"SCRIPT-MANIFEST.json").read_bytes()))==report["archiveInspection"],"Core package changed")
        core[version]={"identity":identity,"report":report,"package":package,"manifest":json.loads(encoded),"manifestBytes":encoded}
        output=base/"desktop"/version;record=(output/"DESKTOP-RECORD.json").read_bytes();registration=validate_record(record,identity);compiler=json.loads((output/"compiler-artifact.json").read_bytes())
        require(compiler["sourceCommit"]==source and compiler["build"]==identity and compiler["recordSHA256"]==digest(record),"Public desktop construction identity differs")
        components={}
        for role in ("metadata","application"):
            package=output/component_name(version,arch,role);item=next(v for v in compiler["components"] if v["component"]==role)
            require(inspect_component(package.read_bytes(),record,identity,role,json.loads((output/(role+"-SCRIPT-MANIFEST.json")).read_bytes()),item["scriptArchiveOwner"])==item["archiveInspection"],"Public component changed")
            components[role]={"package":package,"sha256":digest(package.read_bytes())};receipt_ids.add(package_id(role,record))
        desktop[version]={"record":record,"registration":registration,"components":components}
    products={}
    if product_mode:
        for version in VERSIONS:
            output=base/"product"/version;package=output/product_name(version,arch);raw=package.read_bytes();compiler=json.loads((output/"compiler-artifact.json").read_bytes());inputs=component_inputs(version,arch,desktop[version]["record"])
            packages={name:(core[version]["package"] if role=="core" else desktop[version]["components"][role]["package"]).read_bytes() for role,_,name in inputs}
            inspected=inspect_product(raw,version,arch,inputs,packages)
            require(compiler["sourceCommit"]==source and compiler["build"]==core[version]["identity"] and compiler["productSHA256"]==digest(raw) and compiler["archiveInspection"]==inspected and compiler["actualExpandedPayloadAndScriptsVerified"] is True and compiler["productGraphSchemaValidated"] is True,"Product changed after native construction")
            products[version]={"package":package,"sha256":digest(raw)}
    receipt_paths=[RECEIPTS/(identifier+suffix) for identifier in sorted(receipt_ids) for suffix in (".plist",".bom")]
    for path in (AUTHORITY,INPUT,DESKTOP,APP,Path("/Library/Preferences/AccessWeaver"),*receipt_paths,*support.RECEIPTS):
        no_alias(path);require(not path.exists(),"Existing public/core/managed state must never become a fixture")
    temporary=Path(os.environ["RUNNER_TEMP"]);no_alias(temporary)
    capsule=Path(tempfile.mkdtemp(prefix="accessweaver-desktop-package-",dir=temporary));user=capsule/"user";user.mkdir();tmp=capsule/"tmp";tmp.mkdir()
    env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":str(user),"TMPDIR":str(tmp),"LANG":"C","LC_ALL":"C","TZ":"UTC","ACCESSWEAVER_NO_BROWSER":"1","ACCESSWEAVER_HOME":str(user/"Library/Application Support/AccessWeaver")}
    installer_logging=None
    if product_mode:
        help_result,_=run(["/usr/sbin/installer","-help"],env,30,codes=tuple(range(256)))
        help_bytes=help_result.stdout+help_result.stderr
        require(re.search(rb"(?<![A-Za-z0-9_-])-dumplog(?![A-Za-z0-9_-])",help_bytes) is not None,"Native Installer does not advertise scoped logging")
        installer_logging={"option":"-dumplog","nativeHelpSHA256":digest(help_bytes),"nativeHelpBytes":len(help_bytes),"nativeHelpExitCode":help_result.returncode}
    marker=user/"preserve";marker.write_bytes(b"unrelated public desktop fixture data");marker_hash=digest(marker.read_bytes())
    parent=Path("/Applications");no_alias(parent);info=parent.stat();parent_identity=(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
    parent_acl=run(["/bin/ls","-lde",parent],env,30)[0].stdout.splitlines()[1:]
    operations=[];selections=[];known_slots={};profile=None;profile_hash=None;stage="open-capabilities";complete=False;cleaned=False;failure=None;failure_line=None;ls=None;deactivation=None;current_generation=0;last_installer=None
    def preserved():
        require(digest(marker.read_bytes())==marker_hash and (profile is None or digest(profile.read_bytes())==profile_hash),"Desktop operation changed unrelated data/profile")
        now=parent.stat();require((now.st_dev,now.st_ino,now.st_uid,now.st_gid,stat.S_IMODE(now.st_mode))==parent_identity and run(["/bin/ls","-lde",parent],env,30)[0].stdout.splitlines()[1:]==parent_acl,"Desktop operation changed the Applications container")
    def snapshot():
        result={}
        def regular(path,limit):
            raw=root_regular(path,limit);st=path.stat()
            return {"sha256":digest(raw),"bytes":st.st_size,"device":st.st_dev,"inode":st.st_ino,"mode":stat.S_IMODE(st.st_mode),"uid":st.st_uid,"gid":st.st_gid}
        def alias(path):
            no_alias(path.parent);st=path.lstat();require(stat.S_ISLNK(st.st_mode) and st.st_uid==0 and st.st_nlink==1,"Unexpected alias fixture")
            return {"aliasSHA256":digest(os.readlink(path).encode()),"inode":st.st_ino,"mode":st.st_mode,"uid":st.st_uid,"gid":st.st_gid}
        for path in receipt_paths:
            if path.exists():result[path.name]=regular(path,4<<20)
        if AUTHORITY.exists():result["activeRecord"]=regular(AUTHORITY/"state/deployment.json",16384)
        if DESKTOP.exists():
            no_alias(DESKTOP);names=sorted(p.name for p in DESKTOP.iterdir());require(len(names)<=64,"Desktop registry exceeds budget")
            for name in names:result["registration/"+name]=alias(DESKTOP/name) if (DESKTOP/name).is_symlink() else regular(DESKTOP/name,64<<10)
        if APP.is_symlink():result["publicAlias"]=alias(APP)
        elif APP.exists():
            no_alias(APP)
            for name in ("Contents/Info.plist","Contents/MacOS/"+BINARY,"Contents/Resources/BUILD-INFO.json"):
                result["public/"+name]=regular(APP/name,16<<20)
        return result
    def active(version,generation):
        value=json.loads(root_regular(AUTHORITY/"state/deployment.json",16384));candidate=core[version];slot=value["active"]
        require(value["generation"]==generation and value["pending"]==[] and value["highWaterVersion"]==version and slot["identity"]=={"version":version,"manifestSHA256":candidate["report"]["manifestSHA256"],"payloadSHA256":candidate["report"]["payloadSHA256"]} and re.fullmatch("[a-f0-9]{32}",slot["id"]) is not None,"Core state differs")
        app=AUTHORITY/"versions"/slot["id"]/BUNDLE_NAME;verify_deployment_bundle(app,candidate["manifest"],candidate["identity"],candidate["manifestBytes"])
        known_slots[slot["id"]]=(version,app)
        for old_version,old_app in known_slots.values():verify_deployment_bundle(old_app,core[old_version]["manifest"],core[old_version]["identity"],core[old_version]["manifestBytes"])
        return app/"Contents/MacOS/accessweaver"
    def install(name,version,role,success=True,generation=None):
        nonlocal stage,current_generation,last_installer
        stage=name;before=snapshot();candidate=core[version] if role=="core" else products[version] if role=="product" else desktop[version]["components"][role]
        package=candidate["package"];expected=candidate["report"]["packageSHA256"] if role=="core" else candidate["sha256"]
        require(digest(package.read_bytes())==expected,"Package changed before desktop acceptance")
        with product_install_log_window(product_mode) as log_observation:
            result,elapsed=run(["/usr/bin/sudo","-n","/usr/sbin/installer",*(["-dumplog"] if product_mode else []),"-pkg",package,"-target","/"],env,180,codes=tuple(range(256)))
            last_installer={"name":name,"version":version,"component":role,"exitCode":result.returncode,"packageSHA256":expected}
            if product_mode:
                last_installer["diagnostics"]=product_installer_observation(result.stdout,result.stderr)
                last_installer["packageKitLog"]=log_observation()
        if (result.returncode==0)!=success:
            if product_mode:print(json.dumps({"lastInstaller":last_installer}),flush=True)
            else:print((result.stdout+result.stderr)[-12000:].decode("utf-8",errors="replace").replace(str(capsule),"[owned-capsule]"),flush=True)
        require((result.returncode==0)==success and digest(package.read_bytes())==expected,"Unexpected desktop component Installer result: "+name)
        if not success:require(snapshot()==before,"Refused desktop operation changed app/record/receipt bytes")
        if success and role in ("core","product"):active(version,generation);current_generation=generation
        if success and role in ("metadata","product"):require(root_regular(DESKTOP/record_name(desktop[version]["record"]),64<<10)==desktop[version]["record"],"Installed registration bytes differ")
        if success and role in ("application","product"):verify_bundle(APP,desktop[version]["record"],core[version]["identity"])
        if success:
            for receipt_role in (("core","metadata","application") if role=="product" else (role,)):
                identifier=PACKAGE_ID if receipt_role=="core" else package_id(receipt_role,desktop[version]["record"])
                for suffix in (".plist",".bom"):root_regular(RECEIPTS/(identifier+suffix),4<<20)
                queried,_=run(["/usr/sbin/pkgutil","--pkg-info",identifier],env,30)
                info=dict(line.split(": ",1) if ": " in line else (line.rstrip(":"),"") for line in queried.stdout.decode().splitlines() if line)
                location=core[version]["report"]["archiveInspection"]["installLocation"] if receipt_role=="core" else ROOT if receipt_role=="metadata" else "/Applications"
                require(info.get("package-id")==identifier and info.get("version")==version and info.get("volume")=="/" and info.get("location") in (location,location.lstrip("/")),"Native public/core receipt identity differs")
        preserved();operations.append({"nativeReceiptVerified":success,"name":name,"version":version,"component":role,"exitCode":result.returncode,"elapsedMilliseconds":elapsed,"packageSHA256":expected,"refusedStatePreserved":not success,"passed":True})
    def selection(name,version,success=True):
        before=snapshot();result,elapsed=run([APP/"Contents/MacOS"/BINARY,"version","--json"],env,30,codes=tuple(range(256)))
        require((result.returncode==0)==success and snapshot()==before,"Public app selection mutated installation or returned unexpected exit")
        expected=core[version]["identity"] if success else None
        if success:require(json.loads(result.stdout)==expected,"Public entry executed unexpected active core")
        else:require(b"not active" in result.stderr,"Inactive public entry did not refuse")
        preserved();selections.append({"name":name,"expectedCoreBuild":expected,"exitCode":result.returncode,"elapsedMilliseconds":elapsed,"installationAndUserDataPreserved":True,"passed":True})
    libproc=ctypes.CDLL("/usr/lib/libproc.dylib");pidpath=libproc.proc_pidpath;pidpath.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32];pidpath.restype=ctypes.c_int
    def kernel_image(pid):
        buf=ctypes.create_string_buffer(4096);length=pidpath(pid,buf,len(buf))
        if length<=0:return None
        image=buf.value.decode("utf-8")
        return image.removeprefix("/System/Volumes/Data") if image.startswith("/System/Volumes/Data/Library/Application Support/") else image
    def owner(pid):
        result,_=run(["/bin/ps","-p",str(pid),"-o","uid="],env,5,codes=(0,1));raw=result.stdout.strip();return int(raw) if raw.isdigit() else None
    def controller_pid(path):
        result,_=run(["/bin/ps","-axo","pid=,uid="],env,5);require(len(result.stdout)<=1<<20,"Process inventory exceeds bound")
        found=[]
        for line in result.stdout.splitlines():
            fields=line.split()
            if len(fields)==2 and all(f.isdigit() for f in fields) and int(fields[1])==os.getuid():
                pid=int(fields[0])
                if kernel_image(pid)==str(path):found.append(pid)
        require(len(found)==1,"LaunchServices did not produce exactly one owned controller image");return found[0]
    try:
        help_result,_=run(["/usr/bin/open","-h"],env,30,codes=(0,1));help_bytes=help_result.stdout+help_result.stderr
        require(all(option in help_bytes for option in (b"--env",b"--stdout",b"--stderr")),"Native LaunchServices client lacks required private-environment/output capabilities")
        if product_mode:
            install("app-without-metadata-refused",VERSIONS[0],"application",False)
            install("product-clean-install",VERSIONS[0],"product",generation=1)
        else:install("core-clean-install",VERSIONS[0],"core",generation=1)
        exe=active(VERSIONS[0],1);template,_=run([exe,"show","discord-proxy"],env,30);saved=json.loads(template.stdout);saved["id"]="desktop-preserve";saved["name"]="Preserved desktop fixture profile"
        request=capsule/"profile.json";request.write_text(json.dumps(saved),encoding="utf-8");run([exe,"import",request],env,30)
        profile=user/"Library/Application Support/AccessWeaver/profiles/desktop-preserve.json";no_alias(profile);profile_hash=digest(profile.read_bytes())
        if not product_mode:
            install("app-without-metadata-refused",VERSIONS[0],"application",False)
            install("metadata-clean-install",VERSIONS[0],"metadata");install("public-app-clean-install",VERSIONS[0],"application")
        selection("initial-active",VERSIONS[0])
        stage="launchservices-controller";log=capsule/"launchservices.log";core_path=active(VERSIONS[0],1);pid=None;serving=False
        command=["/usr/bin/open","-W","-n","--stdout",str(log),"--stderr",str(log)]
        for key in ("HOME","TMPDIR","ACCESSWEAVER_HOME","ACCESSWEAVER_NO_BROWSER","LANG","LC_ALL","TZ"):command.extend(["--env",key+"="+env[key]])
        command.append(str(APP));started=time.monotonic();client_log=capsule/"launchservices-client.log"
        with client_log.open("xb") as output:child=subprocess.Popen(command,cwd=REPO,env=env,stdout=output,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                if log.exists():
                    require(log.stat().st_size<=65536,"LaunchServices output exceeds limit")
                    if b"AccessWeaver is running at" in log.read_bytes() and b"Open this private launch file in your browser:" in log.read_bytes():break
                require(client_log.stat().st_size<=65536,"LaunchServices client output exceeds limit")
                if child.poll() is not None:print(client_log.read_bytes()[-8000:].decode("utf-8",errors="replace").replace(str(capsule),"[owned-capsule]"),flush=True)
                require(child.poll() is None,"LaunchServices exited before serving readiness");time.sleep(0.05)
            require(log.exists() and b"AccessWeaver is running at" in log.read_bytes(),"Public app did not reach serving readiness through LaunchServices")
            pid=controller_pid(core_path);require(owner(pid)==os.getuid(),"LaunchServices controller owner differs");serving=True
            line=next(line for line in log.read_text(encoding="utf-8").splitlines() if "AccessWeaver is running at" in line);url=line.split("AccessWeaver is running at",1)[1].strip();parsed=urllib.parse.urlsplit(url)
            require(parsed.scheme=="http" and parsed.hostname in ("127.0.0.1","::1","localhost") and parsed.username is None and parsed.password is None,"Unexpected controller URL")
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url,timeout=10) as response:
                body=response.read((1<<20)+1);require(response.status==200 and len(body)<=1<<20 and b"AccessWeaver" in body,"Actual LaunchServices controller did not serve dashboard")
            lock=profile.parent.parent/".controller.lock";no_alias(lock);lock_info=lock.stat()
            require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid==os.getuid() and lock_info.st_nlink==1,"Private controller lock ownership differs")
            with lock.open("rb") as probe:
                try:fcntl.flock(probe.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:pass
                else:fcntl.flock(probe.fileno(),fcntl.LOCK_UN);raise ValueError("LaunchServices ignored the private profile directory")
            launch_line=next(line for line in log.read_text(encoding="utf-8").splitlines() if line.startswith("Open this private launch file in your browser:"))
            launch_uri=urllib.parse.urlsplit(launch_line.split(":",1)[1].strip());launch_path=Path(urllib.parse.unquote(launch_uri.path))
            require(launch_uri.scheme=="file" and not launch_uri.netloc and not launch_uri.query and not launch_uri.fragment and launch_path.is_relative_to(user),"LaunchServices browser credential escaped private user directory")
            no_alias(launch_path);launch_info=launch_path.stat();require(stat.S_ISREG(launch_info.st_mode) and launch_info.st_uid==os.getuid() and launch_info.st_nlink==1 and stat.S_IMODE(launch_info.st_mode)==0o600 and launch_info.st_size<=16384,"Private browser credential file protection differs")
            credentials=set(re.findall(r"accessweaver-session=([A-Za-z0-9_-]{43})",launch_path.read_text(encoding="utf-8")));require(len(credentials)==1,"Missing private browser session credential")
            request=urllib.request.Request(urllib.parse.urljoin(url,"/api/v1/profiles"),headers={"X-AccessWeaver-Token":next(iter(credentials))})
            with opener.open(request,timeout=10) as response:
                body=response.read((1<<20)+1);require(response.status==200 and len(body)<=1<<20,"Authenticated private profile response exceeds bound")
                profiles=json.loads(body);require(type(profiles) is list and any(p.get("id")=="desktop-preserve" for p in profiles),"LaunchServices controller did not load private saved profile")
            install("launchservices-live-product-upgrade-refused" if product_mode else "launchservices-live-core-upgrade-refused",VERSIONS[1],"product" if product_mode else "core",False)
            require(child.poll() is None and kernel_image(pid)==str(core_path) and owner(pid)==os.getuid(),"Refused upgrade disturbed LaunchServices controller")
            ls={"defaultNoArgumentLaunch":True,"kernelImageAndOrdinaryOwnerVerified":True,"dashboardHTTPVerified":True,"privateProfileLockVerified":True,"authenticatedSavedProfileVerified":True,"installerRefusalWhileServingVerified":True,"controllerRemainedRunning":True,"passed":False}
        finally:
            if pid is None and log.exists() and b"AccessWeaver is running at" in log.read_bytes():pid=controller_pid(core_path)
            if pid is not None and kernel_image(pid)==str(core_path):
                require(owner(pid)==os.getuid(),"Refuse signaling an unowned controller");os.kill(pid,signal.SIGTERM)
            stopped=child.wait(timeout=30)
            if serving:require(stopped==0 and kernel_image(pid)!=str(core_path),"Owned LaunchServices controller did not terminate cleanly")
        require(ls is not None,"Missing actual LaunchServices evidence");ls.update({"cleanShutdownVerified":True,"elapsedMilliseconds":int((time.monotonic()-started)*1000),"passed":True})
        if product_mode:
            install("product-upgrade",VERSIONS[1],"product",generation=2);selection("product-upgraded",VERSIONS[1])
            install("product-equal-reinstall",VERSIONS[1],"product",generation=3);selection("product-reinstalled",VERSIONS[1])
            install("older-product-refused",VERSIONS[0],"product",False)
        else:
            install("core-upgrade-with-public-v1",VERSIONS[1],"core",generation=2);selection("core-upgraded-public-v1",VERSIONS[1])
            install("metadata-upgrade",VERSIONS[1],"metadata");install("public-app-upgrade",VERSIONS[1],"application");selection("public-upgraded",VERSIONS[1])
            install("metadata-equal-reinstall",VERSIONS[1],"metadata");install("public-app-equal-reinstall",VERSIONS[1],"application")
            install("older-metadata-refused",VERSIONS[0],"metadata",False);install("older-public-app-refused",VERSIONS[0],"application",False)
        for kind,path in (("public-info",APP/"Contents/Info.plist"),("registration",DESKTOP/record_name(desktop[VERSIONS[1]]["record"]))):
            stage="changed-"+kind;original=root_regular(path,64<<10);good=capsule/(kind+"-original");bad=capsule/(kind+"-changed");good.write_bytes(original);bad.write_bytes(original+b" ")
            run(["/usr/bin/sudo","-n","/bin/cp",bad,path],env)
            if product_mode:install("changed-"+kind+"-product-refused",VERSIONS[1],"product",False)
            else:
                install("changed-"+kind+"-core-refused",VERSIONS[1],"core",False)
                install("changed-"+kind+"-desktop-refused",VERSIONS[1],"application" if kind=="public-info" else "metadata",False)
            require(path.read_bytes()==original+b" ","Refused update repaired changed input")
            run(["/usr/bin/sudo","-n","/bin/cp",good,path],env);require(path.read_bytes()==original,"Owned original restoration failed")
        stage="public-app-alias";saved_app=capsule/"retained-public-app"
        verify_bundle(APP,desktop[VERSIONS[1]]["record"],core[VERSIONS[1]]["identity"])
        require(not saved_app.exists(),"Owned alias destination already exists");run(["/usr/bin/sudo","-n","/bin/mv",APP,saved_app],env)
        run(["/usr/bin/sudo","-n","/bin/ln","-s",saved_app,APP],env)
        if product_mode:install("public-alias-product-refused",VERSIONS[1],"product",False)
        else:install("public-alias-core-refused",VERSIONS[1],"core",False);install("public-alias-app-refused",VERSIONS[1],"application",False)
        require(APP.is_symlink() and os.readlink(APP)==str(saved_app),"Refusal changed public alias")
        verify_bundle(saved_app,desktop[VERSIONS[1]]["record"],core[VERSIONS[1]]["identity"])
        run(["/usr/bin/sudo","-n","/bin/rm","--",APP],env);require(not APP.exists() and not APP.is_symlink(),"Owned alias remains")
        run(["/usr/bin/sudo","-n","/bin/mv","-n",saved_app,APP],env)
        stage="registration-alias";record_path=DESKTOP/record_name(desktop[VERSIONS[1]]["record"]);saved_record=capsule/"retained-registration.json"
        original=root_regular(record_path,64<<10);run(["/usr/bin/sudo","-n","/bin/mv",record_path,saved_record],env)
        run(["/usr/bin/sudo","-n","/bin/ln","-s",saved_record,record_path],env)
        if product_mode:install("registration-alias-product-refused",VERSIONS[1],"product",False)
        else:install("registration-alias-core-refused",VERSIONS[1],"core",False);install("registration-alias-metadata-refused",VERSIONS[1],"metadata",False)
        require(record_path.is_symlink() and os.readlink(record_path)==str(saved_record) and root_regular(saved_record,64<<10)==original,"Registration alias/destination changed")
        run(["/usr/bin/sudo","-n","/bin/rm","--",record_path],env);require(not record_path.exists() and not record_path.is_symlink(),"Registration alias remains")
        run(["/usr/bin/sudo","-n","/bin/mv","-n",saved_record,record_path],env)
        if product_mode:install("restored-product-reinstall",VERSIONS[1],"product",generation=4)
        else:install("restored-public-reinstall",VERSIONS[1],"application")
        selection("restored-active",VERSIONS[1])
        stage="deactivation-and-owned-cleanup";candidate=core[VERSIONS[1]];scripts=cpio(inflate(flat_members(candidate["package"].read_bytes())["Scripts"],32<<20,31));helper=capsule/"core-helper";helper.write_bytes(scripts["postinstall"]["data"]);helper.chmod(0o755)
        require(digest(helper.read_bytes())==candidate["report"]["helperSHA256"],"Deactivation helper differs from actual package")
        result,elapsed=run(["/usr/bin/sudo","-n",helper,"deactivate-deployment"],env,60);value=json.loads(result.stdout)
        require(value["generation"]==current_generation+1 and value["state"]=="inactive" and value["operationRecordPublished"] is True,"Core deactivation did not retain fence")
        deactivation={"generation":current_generation+1,"state":"inactive","operationRecordPublished":True,"exitCode":result.returncode,"elapsedMilliseconds":elapsed}
        selection("inactive-refused",VERSIONS[1],False);stage="deactivation-and-owned-cleanup"
        value=json.loads(root_regular(AUTHORITY/"state/deployment.json",16384));require(value["active"]["id"]=="" and value["pending"]==[] and value["generation"]==current_generation+1 and value["highWaterVersion"]==VERSIONS[1] and len(known_slots)==current_generation,"Unexpected final owned core state")
        for old_version,old_app in known_slots.values():verify_deployment_bundle(old_app,core[old_version]["manifest"],core[old_version]["identity"],core[old_version]["manifestBytes"])
        verify_bundle(APP,desktop[VERSIONS[1]]["record"],core[VERSIONS[1]]["identity"])
        require({p.name for p in DESKTOP.iterdir()}=={record_name(d["record"]) for d in desktop.values()},"Unexpected registration retained during cleanup")
        for d in desktop.values():require(root_regular(DESKTOP/record_name(d["record"]),64<<10)==d["record"],"Retained registration changed")
        for path in (AUTHORITY,INPUT,DESKTOP,APP):
            no_alias(path);info=path.stat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755 and path in (AUTHORITY,INPUT,DESKTOP,APP),"Unsafe owned desktop cleanup target")
            aliases,_=run(["/usr/bin/sudo","-n","/usr/bin/find",path,"-type","l","-print"],env);require(not aliases.stdout.strip(),"Unexpected owned cleanup alias")
        preserved()
        for identifier in sorted(receipt_ids):run(["/usr/bin/sudo","-n","/usr/sbin/pkgutil","--forget",identifier],env,30)
        run(["/usr/bin/sudo","-n","/bin/rm","-rf","--",APP,DESKTOP,AUTHORITY,INPUT],env)
        require(all(not p.exists() and not p.is_symlink() for p in (APP,DESKTOP,AUTHORITY,INPUT,*receipt_paths)),"Owned public desktop fixture state remains")
        preserved();require(capsule.resolve().parent==temporary.resolve() and capsule.name.startswith("accessweaver-desktop-package-"),"Unsafe owned capsule cleanup");no_alias(capsule);shutil.rmtree(capsule);cleaned=True;complete=True
    except Exception as error:
        failure=type(error).__name__;trace=error.__traceback__
        while trace:
            if trace.tb_frame.f_code.co_filename==__file__:failure_line=trace.tb_lineno
            trace=trace.tb_next
    report={"schemaVersion":1,"sourceCommit":source,"runID":os.environ["GITHUB_RUN_ID"],"target":"darwin/"+arch,"stage":stage,"passed":complete,"failureType":failure,"failureSourceLine":failure_line,"operations":operations,"selections":selections,"launchServices":ls,"deactivation":deactivation,"corePackageSHA256":{v:core[v]["report"]["packageSHA256"] for v in VERSIONS},"desktopRecordSHA256":{v:digest(desktop[v]["record"]) for v in VERSIONS},"desktopPackageSHA256":{v:{role:c["sha256"] for role,c in desktop[v]["components"].items()} for v in VERSIONS},"actualOrderedComponentsExecuted":complete,"publicAppAndProtectedRegistrationsVerified":complete,"coreUpgradeWithPublicEntryVerified":complete,"actualUserDataAndContainerProtectionPreserved":complete,"ownedFixturesRemoved":cleaned,"installedProductCodeExecutedAsRoot":False,"publisherSignatureVerified":False,"notarized":False,"finderInteractiveQualificationComplete":False,"singleProductDistributionQualified":False,"productUninstallQualified":False,"managedEndpointQualified":False,"productionQualificationComplete":False}
    if product_mode:
        report.update({"lifecycleKind":"single-product","actualSingleProductLifecycleVerified":complete,"productPackageSHA256":{v:p["sha256"] for v,p in products.items()},"installerLogging":installer_logging})
        if not complete:
            report["lastInstaller"]=last_installer
            try:
                state=json.loads(root_regular(AUTHORITY/"state/deployment.json",16384));active_slot=state.get("active",{});pending=state.get("pending")
                report["failedProductState"]={"recordAvailable":True,"generation":state.get("generation") if type(state.get("generation")) is int else None,"activeSlotPresent":isinstance(active_slot,dict) and bool(active_slot.get("id")),"pendingCount":len(pending) if type(pending) is list and len(pending)<=8 else None,"highWaterVersion":state.get("highWaterVersion") if state.get("highWaterVersion") in VERSIONS else None}
            except Exception:report["failedProductState"]={"recordAvailable":False}

    (base/("product-lifecycle-artifact.json" if product_mode else "desktop-lifecycle-artifact.json")).write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    require(complete,"Native public desktop acceptance failed at "+stage+"; owned state retained")
    print(json.dumps({"target":report["target"],"actualInstallerOperations":len(operations),"launchServicesDefaultUI":True,"passed":True,"productionQualificationComplete":False}))

if __name__=="__main__":
    require(sys.argv[1:] in ([],["--product"]),"Expected no arguments or --product")
    main(product_mode=sys.argv[1:]==["--product"])
