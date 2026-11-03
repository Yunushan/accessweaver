"""Bounded public desktop component contracts; no extraction or target execution."""
import copy
import datetime
import json
from pathlib import Path,PurePosixPath
import plistlib
import re

from macos_installer import BUNDLE_NAME,BUNDLE_ID,MAX_BYTES,MAX_FILES,bundle_manifest,bundle_plist,digest,macho_identity,require,version_parts
from macos_launcher import BINARY
from macos_deployment import script_contract
from macos_package_archive import flat_members,cpio,inflate,xml
from sbom import component,properties,prop_map,validate

DESKTOP_ID=BUNDLE_ID+".desktop"
ROOT="/Library/Application Support/AccessWeaver Desktop"
NOTICE_ROOT=BUNDLE_NAME+"/Contents/Resources"
MAX_RECORD=64<<10
ROLE="active-copy-launcher"
HASH=re.compile(r"[a-f0-9]{64}")
PATH=re.compile(r"(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+")


def unique_json(data):
    require(isinstance(data,(str,bytes)),"Invalid desktop JSON input")
    if isinstance(data,bytes):data=data.decode("utf-8")
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,"Duplicate desktop JSON key");result[key]=value
        return result
    def no_constant(value):raise ValueError("Invalid desktop JSON number")
    try:
        result=json.loads(data,object_pairs_hook=pairs,parse_constant=no_constant)
    except RecursionError as error:raise ValueError("Desktop JSON nesting exceeds budget") from error
    pending=[(result,1)];count=0
    while pending:
        item,depth=pending.pop();count+=1;require(depth<=32 and count<=8192 and item is not None,"Desktop JSON structure exceeds budget")
        if isinstance(item,dict):pending.extend((v,depth+1) for v in item.values())
        elif isinstance(item,list):pending.extend((v,depth+1) for v in item)
    return result


def plist(identity):
    result=bundle_plist(identity["version"],"13.0.0");result["CFBundleIdentifier"]=DESKTOP_ID;result["CFBundleExecutable"]=BINARY
    return result


def inventory(app):
    for forbidden in ("INSTALL-MANIFEST.json","SBOM.cdx.json"):
        path=Path(app)/"Contents/Resources"/forbidden
        require(not path.exists() and not path.is_symlink(),"Binary-bound desktop metadata must stay outside the app")
    result=bundle_manifest(app);result["bundleIdentifier"]=DESKTOP_ID;return result


def record_name(encoded):return "desktop-"+digest(encoded)+".json"


def package_id(role,encoded):
    require(role in ("metadata","application"),"Unknown desktop component")
    return DESKTOP_ID+(".registration."+digest(encoded) if role=="metadata" else "")


def component_name(version,arch,role):
    version_parts(version);require(arch in ("amd64","arm64") and role in ("metadata","application"),"Invalid desktop component")
    return "accessweaver-"+version+"-darwin-"+arch+"-desktop-"+role+"-experimental.pkg"


def validate_record(encoded,identity):
    require(type(encoded) is bytes and 0<len(encoded)<=MAX_RECORD,"Desktop registration exceeds budget")
    r=unique_json(encoded)
    require(type(r) is dict and set(r)=={"schemaVersion","role","build","manifest","compiledSBOM","noticeRoot"} and type(r["schemaVersion"]) is int and r["schemaVersion"]==1 and r["role"]==ROLE and r["noticeRoot"]==NOTICE_ROOT and r["build"]==identity,"Desktop registration role/build differs")
    require(identity["platform"]=="darwin" and identity["arch"] in ("amd64","arm64") and identity["sourceState"]=="clean","Expected a clean native desktop build")
    require(set(identity)=={"version","commit","sourceState","builtAt","goVersion","platform","arch"} and type(identity["commit"]) is str and re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})",identity["commit"]) is not None and type(identity["goVersion"]) is str and identity["goVersion"].startswith("go1."),"Desktop build identity fields differ")
    require(datetime.datetime.strptime(identity["builtAt"],"%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ")==identity["builtAt"],"Noncanonical desktop build time")
    version_parts(identity["version"])
    m=r["manifest"];require(type(m) is dict and set(m)=={"schemaVersion","bundleIdentifier","files","directories"} and type(m["schemaVersion"]) is int and m["schemaVersion"]==1 and m["bundleIdentifier"]==DESKTOP_ID,"Invalid desktop inventory role")
    files=m["files"];dirs=m["directories"];require(type(files) is list and type(dirs) is list and 3<=len(files) and len(files)+len(dirs)<=MAX_FILES,"Invalid desktop inventory extent")
    names=set();directories=set();total=0
    for entry in dirs+files:
        require(type(entry) is dict and type(entry.get("path")) is str and PATH.fullmatch(entry["path"]) is not None,"Invalid desktop path")
        name=entry["path"];require(name not in names and str(PurePosixPath(name))==name and all(p not in (".","..") for p in PurePosixPath(name).parts) and len(name)<=4096 and len(PurePosixPath(name).parts)<=32,"Aliased/duplicated desktop path");names.add(name)
    for entry in dirs:
        require(set(entry)=={"path","mode"} and entry["mode"]=="0755","Invalid desktop directory");directories.add(entry["path"])
    binary="Contents/MacOS/"+BINARY;by_name={e["path"]:e for e in files}
    require({"Contents/Info.plist","Contents/Resources/BUILD-INFO.json",binary}<=set(by_name),"Missing desktop entry identity")
    for entry in files:
        require(set(entry)=={"path","mode","bytes","sha256"} and entry["mode"]==("0755" if entry["path"]==binary else "0644") and type(entry["bytes"]) is int and 0<=entry["bytes"]<=64<<20 and type(entry["sha256"]) is str and HASH.fullmatch(entry["sha256"]) is not None,"Invalid desktop file seal")
        require(entry["path"] not in ("Contents/Resources/INSTALL-MANIFEST.json","Contents/Resources/SBOM.cdx.json"),"Embedded binary-bound desktop metadata forbidden")
        total+=entry["bytes"]
    require(total<=MAX_BYTES,"Desktop inventory exceeds byte budget")
    for name in names:
        require(all(str(parent) in directories for parent in PurePosixPath(name).parents if str(parent)!="."),"Missing desktop parent")
    require(type(r["compiledSBOM"]) is str and 0<len(r["compiledSBOM"].encode("utf-8"))<=48<<10,"Desktop graph exceeds budget")
    graph=unique_json(r["compiledSBOM"]);application=graph["metadata"]["component"]
    require(graph.get("bomFormat")=="CycloneDX" and graph.get("specVersion")=="1.6" and application.get("type")=="application" and application["hashes"]==[{"alg":"SHA-256","content":by_name[binary]["sha256"]}] and application["version"]==identity["version"],"Desktop graph binary/version differs")
    for key,value in (("source-commit",identity["commit"]),("source-state","clean"),("target-os","darwin"),("target-arch",identity["arch"])):require(prop_map(application).get("accessweaver:"+key)==value,"Desktop graph source/target differs")
    return r


def verify_bundle(app,encoded,identity):
    r=validate_record(encoded,identity);require(inventory(app)==r["manifest"],"Desktop bundle differs from protected registration")
    app=Path(app);binary=(app/("Contents/MacOS/"+BINARY)).read_bytes();macho_identity(binary,identity["arch"])
    require(plistlib.loads((app/"Contents/Info.plist").read_bytes())==plist(identity) and unique_json((app/"Contents/Resources/BUILD-INFO.json").read_bytes())==identity,"Desktop plist/build differs")
    graph=unique_json(r["compiledSBOM"]);validate(graph,binary,identity)
    notices=set()
    for c in [graph["metadata"]["component"]]+graph["components"]:
        for evidence in json.loads(prop_map(c).get("accessweaver:license-evidence","[]")):
            name=evidence["path"];path=app/"Contents/Resources"/name
            require(digest(path.read_bytes())==evidence["sha256"],"Desktop notice differs");notices.add("Contents/Resources/"+name)
    require({f["path"] for f in r["manifest"]["files"]}==notices|{"Contents/Info.plist","Contents/Resources/BUILD-INFO.json","Contents/MacOS/"+BINARY},"Unexpected desktop resource")
    return r


def inspect_component(package,encoded,identity,role,scripts_manifest):
    r=validate_record(encoded,identity);expected_scripts=script_contract(scripts_manifest)
    members=flat_members(package);entries=cpio(inflate(members["Payload"],MAX_BYTES,31));scripts=cpio(inflate(members["Scripts"],32<<20,31))
    dirs={""};files={}
    if role=="metadata":files[record_name(encoded)]={"bytes":len(encoded),"sha256":digest(encoded),"mode":"0644"}
    else:
        require(role=="application","Unknown public desktop component")
        dirs|={BUNDLE_NAME}|{BUNDLE_NAME+"/"+d["path"] for d in r["manifest"]["directories"]};files={BUNDLE_NAME+"/"+f["path"]:f for f in r["manifest"]["files"]}
    require(set(entries)==dirs|set(files),"Unexpected public component payload")
    for name,entry in entries.items():
        require(entry["uid"]==0 and entry["gid"]==0,"Desktop payload is not root:wheel")
        if name in dirs:require(entry["directory"] and entry["mode"]==0o755,"Desktop directory differs")
        else:
            f=files[name];require(not entry["directory"] and entry["mode"]==int(f["mode"],8) and len(entry["data"])==f["bytes"] and digest(entry["data"])==f["sha256"],"Desktop payload file differs")
    if role=="metadata":require(entries[record_name(encoded)]["data"]==encoded,"Desktop registration raw bytes differ")
    else:
        prefix=BUNDLE_NAME+"/";binary=entries[prefix+"Contents/MacOS/"+BINARY]["data"];macho_identity(binary,identity["arch"])
        require(plistlib.loads(entries[prefix+"Contents/Info.plist"]["data"])==plist(identity) and unique_json(entries[prefix+"Contents/Resources/BUILD-INFO.json"]["data"])==identity,"Packaged desktop identity differs")
        graph=unique_json(r["compiledSBOM"]);validate(graph,binary,identity)
        for c in [graph["metadata"]["component"]]+graph["components"]:
            for e in json.loads(prop_map(c).get("accessweaver:license-evidence","[]")):require(digest(entries[prefix+"Contents/Resources/"+e["path"]]["data"])==e["sha256"],"Packaged desktop notice differs")
    script_dirs={""}|({"licenses"} if any(n.startswith("licenses/") for n in expected_scripts) else set())
    require(set(scripts)==set(expected_scripts)|script_dirs,"Unexpected desktop package scripts")
    for name,entry in scripts.items():
        require(entry["uid"]==0 and entry["gid"]==0,"Desktop script owner differs")
        if name in script_dirs:require(entry["directory"] and entry["mode"]==0o755,"Desktop script directory differs")
        else:
            f=expected_scripts[name];require(not entry["directory"] and entry["mode"]==int(f["mode"],8) and len(entry["data"])==f["bytes"] and digest(entry["data"])==f["sha256"],"Desktop script file differs")
    helper=macho_identity(scripts["preinstall"]["data"],identity["arch"])
    info=xml(members["PackageInfo"])
    require(info.tag=="pkg-info" and info.get("identifier")==package_id(role,encoded) and info.get("version")==identity["version"] and info.get("auth")=="root" and info.get("install-location")== (ROOT if role=="metadata" else "/Applications") and info.get("relocatable","false")=="false","Desktop package target/identity differs")
    require(info.find("relocate") is None or len(info.find("relocate"))==0,"Desktop relocation forbidden")
    require([n.get("file") for n in info.findall("./scripts/preinstall")]==["./preinstall"] and [n.get("file") for n in info.findall("./scripts/postinstall")]==["./postinstall"] and len(info.findall("./scripts/*"))==2,"Desktop package phases differ")
    bundles=[n.get("id") for n in info.findall("./strict-identifier/bundle")];require(bundles==([DESKTOP_ID] if role=="application" else []),"Desktop component bundle role differs")
    return {"packageSHA256":digest(package),"recordSHA256":digest(encoded),"component":role,"packageIdentifier":package_id(role,encoded),"payloadFiles":len(files),"payloadDirectories":len(dirs),"helperSHA256":digest(scripts["preinstall"]["data"]),"helperMachO":helper,"allPathsModesOwnersAndHashesVerified":True,"targetExecutionPerformed":False,"publisherSignatureVerified":False,"productionQualificationComplete":False}


def package_sbom(package,identity,helper,launcher,payload_records,scripts_manifest,tool):
    result=copy.deepcopy(helper);components=[];edges=[];roots=[]
    for label,doc in [("helper",helper)]+([("launcher",launcher)] if launcher is not None else []):
        prefix=label+":";root=doc["metadata"]["component"];roots.append(prefix+root["bom-ref"])
        for c in [root]+doc["components"]:
            c=copy.deepcopy(c);c["bom-ref"]=prefix+c["bom-ref"];components.append(c)
        for e in doc["dependencies"]:edges.append({"ref":prefix+e["ref"],"dependsOn":[prefix+n for n in e["dependsOn"]]})
    file_refs=[]
    for label,records in (("payload",payload_records),("script",scripts_manifest)):
        for f in records:
            ref=label+":"+f["path"];c=component(ref,f["path"],"file");c["hashes"]=[{"alg":"SHA-256","content":f["sha256"]}];components.append(c);edges.append({"ref":ref,"dependsOn":[]});file_refs.append(ref)
    root=copy.deepcopy(helper["metadata"]["component"]);root["bom-ref"]="application";root["name"]="AccessWeaver public desktop component";root["hashes"]=[{"alg":"SHA-256","content":digest(package)}]
    root.setdefault("properties",[]).extend(properties({"inventory-scope":"compiled subjects and actual payload/scripts; OS dependency closure excluded","desktop-registration-is-separate-from-core-authority":"true"}))
    result["metadata"]["component"]=root;result["metadata"]["tools"]={"components":[{"type":"application","name":"Apple pkgbuild","version":tool["osBuild"],"hashes":[{"alg":"SHA-256","content":tool["sha256"]}]}]}
    edges.append({"ref":"application","dependsOn":roots+file_refs});result["components"]=components;result["dependencies"]=edges;result["compositions"]=[{"aggregate":"incomplete","assemblies":["application"]}]
    validate(result,package,identity);return result
