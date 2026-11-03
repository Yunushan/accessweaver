"""Contracts for an experimental versioned macOS component package.

Incoming package files never share ownership with active deployment versions.
Inspection is bounded/in-memory; it neither extracts nor executes package code.
"""
import copy
import json
from pathlib import Path,PurePosixPath
import plistlib
import re
import stat
import uuid

from macos_installer import BUNDLE_ID,BUNDLE_NAME,MAX_BYTES,MAX_FILES,bundle_plist,digest,macho_identity,require,version_parts,verify_bundle
from macos_package_archive import flat_members,cpio,inflate,xml
from sbom import component,properties,prop_map,validate

PACKAGE_ID=BUNDLE_ID+".deployment"
INCOMING="/Library/Application Support/AccessWeaver Incoming"
MANIFEST="Contents/Resources/INSTALL-MANIFEST.json"
DETACHED_MANIFEST="INSTALL-MANIFEST.json"
PAYLOAD_SBOM="payload-SBOM.cdx.json"
EMBEDDED_SBOM="Contents/Resources/SBOM.cdx.json"
MAX_PAYLOAD_SBOM=8<<20
HASH=re.compile(r"[a-f0-9]{64}")
RELATIVE=re.compile(r"(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+")

def detached_payload_manifest(inventory,payload_sbom):
    require(type(inventory) is dict and set(inventory)=={"schemaVersion","bundleIdentifier","files","directories"} and type(inventory["schemaVersion"]) is int and inventory["schemaVersion"]==1,"Expected a complete app inventory")
    require(type(payload_sbom) is bytes and 0<len(payload_sbom)<=MAX_PAYLOAD_SBOM,"Invalid detached payload SBOM")
    manifest=copy.deepcopy(inventory);manifest["schemaVersion"]=2
    manifest["payloadSBOM"]={"path":PAYLOAD_SBOM,"bytes":len(payload_sbom),"sha256":digest(payload_sbom),"mode":"0644"}
    manifest_contract(manifest)
    return manifest


def verify_deployment_bundle(app,manifest,identity,manifest_bytes):
    sidecar=Path(app).parent/DETACHED_MANIFEST
    require(type(manifest_bytes) is bytes and 0<len(manifest_bytes)<=2<<20,"Invalid detached inventory bytes")
    verify_bundle(app,manifest,identity,manifest_path=sidecar)
    require(sidecar.read_bytes()==manifest_bytes,"Detached manifest byte seal differs")
    if manifest["schemaVersion"]==2:
        manifest_contract(manifest)
        path=Path(app).parent/PAYLOAD_SBOM;info=path.lstat();record=manifest["payloadSBOM"]
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o644 and info.st_size==record["bytes"],"Detached payload SBOM type/mode/extent differs")
        data=path.read_bytes();require(len(data)==record["bytes"] and digest(data)==record["sha256"],"Detached payload SBOM byte seal differs")
        require({p.name for p in Path(app).parent.iterdir()}=={BUNDLE_NAME,DETACHED_MANIFEST,PAYLOAD_SBOM},"Unexpected detached deployment container member")
    return True


def canonical_path(value):
    return type(value) is str and len(value)<=4096 and RELATIVE.fullmatch(value) is not None and len(value.split("/"))<=32 and all(p not in (".","..") for p in value.split("/"))

def manifest_contract(manifest):
    require(type(manifest) is dict and type(manifest.get("schemaVersion")) is int and manifest["schemaVersion"] in (1,2) and manifest.get("bundleIdentifier")==BUNDLE_ID,"Invalid deployment manifest identity")
    version=manifest["schemaVersion"];expected={"schemaVersion","bundleIdentifier","files","directories"}|({"payloadSBOM"} if version==2 else set())
    require(set(manifest)==expected,"Unexpected deployment manifest field")
    files=manifest["files"];dirs=manifest["directories"]
    require(type(files) is list and type(dirs) is list and 0<len(files)+len(dirs)<=MAX_FILES-(5 if version==2 else 4),"Invalid deployment manifest extent")
    seen=set();directories=set();total=0
    if version==2:
        record=manifest["payloadSBOM"]
        require(type(record) is dict and set(record)=={"path","mode","bytes","sha256"} and record["path"]==PAYLOAD_SBOM and record["mode"]=="0644" and type(record["bytes"]) is int and 0<record["bytes"]<=MAX_PAYLOAD_SBOM and type(record["sha256"]) is str and HASH.fullmatch(record["sha256"]) is not None,"Invalid detached payload SBOM seal")
        total=record["bytes"]
    for entry in dirs+files:
        require(type(entry) is dict and canonical_path(entry.get("path")),"Invalid deployment inventory path")
        name=entry["path"];require(name.casefold() not in seen,"Ambiguous deployment inventory path");seen.add(name.casefold())
    for entry in dirs:
        require(set(entry)=={"path","mode"} and entry["mode"]=="0755","Invalid deployment directory mode")
        directories.add(entry["path"])
    for entry in files:
        require(set(entry)=={"path","mode","bytes","sha256"} and type(entry["bytes"]) is int and 0<=entry["bytes"]<=64<<20 and type(entry["sha256"]) is str and HASH.fullmatch(entry["sha256"]) is not None and entry["path"]!=MANIFEST and (version==1 or entry["path"]!=EMBEDDED_SBOM),"Invalid deployment file subject")
        require(entry["mode"]==("0755" if entry["path"]=="Contents/MacOS/accessweaver" else "0644"),"Invalid deployment file mode")
        total+=entry["bytes"]
    required={"Contents/Info.plist","Contents/MacOS/accessweaver","Contents/Resources/BUILD-INFO.json"}|({EMBEDDED_SBOM} if version==1 else set())
    require(total<=MAX_BYTES and required<={f["path"] for f in files},"Missing or oversized deployment payload")
    for entry in dirs+files:
        require(all(str(p) in directories for p in PurePosixPath(entry["path"]).parents if str(p)!="."),"Missing deployment parent directory")
    return True

def install_location(manifest_hash):
    require(type(manifest_hash) is str and HASH.fullmatch(manifest_hash) is not None,"Invalid compiled manifest seal")
    return INCOMING+"/"+manifest_hash

def script_contract(records):
    require(type(records) is list and 2<=len(records)<=514,"Invalid package-script inventory extent")
    files={}
    for record in records:
        require(type(record) is dict and set(record)=={"path","mode","bytes","sha256"} and type(record["path"]) is str,"Invalid package-script subject")
        name=record["path"]
        require(name not in files and (name in ("preinstall","postinstall") or re.fullmatch(r"licenses/[A-Za-z0-9._-]+",name) is not None and not name.endswith(("/.","/.."))),"Unexpected package-script path")
        require(type(record["bytes"]) is int and 0<record["bytes"]<=(16<<20 if name in ("preinstall","postinstall") else 1<<20) and type(record["sha256"]) is str and HASH.fullmatch(record["sha256"]) is not None and record["mode"]==("0755" if name in ("preinstall","postinstall") else "0644"),"Invalid package-script extent/mode/seal")
        files[name]=record
    require({"preinstall","postinstall"}<=set(files) and files["preinstall"]["sha256"]==files["postinstall"]["sha256"] and files["preinstall"]["bytes"]==files["postinstall"]["bytes"],"Both package phases must execute the same sealed new helper")
    return files

def inspect_deployment(package,manifest_bytes,identity,scripts_manifest):
    require(type(manifest_bytes) is bytes and len(manifest_bytes)<=2<<20,"Deployment manifest exceeds budget")
    manifest=json.loads(manifest_bytes);manifest_contract(manifest);version_parts(identity["version"])
    require(manifest["schemaVersion"]==2,"New component packages require detached inventory and payload SBOM")
    require(identity.get("platform")=="darwin" and identity.get("arch") in ("amd64","arm64") and identity.get("sourceState")=="clean","Deployment package requires a clean native payload")
    members=flat_members(package);entries=cpio(inflate(members["Payload"],MAX_BYTES,31));scripts=cpio(inflate(members["Scripts"],32<<20,31))
    prefix=BUNDLE_NAME+"/"
    directories={"":0o755,BUNDLE_NAME:0o755};directories.update({prefix+d["path"]:0o755 for d in manifest["directories"]})
    files={prefix+f["path"]:f for f in manifest["files"]};files[DETACHED_MANIFEST]={"mode":"0644","bytes":len(manifest_bytes),"sha256":digest(manifest_bytes)};files[PAYLOAD_SBOM]=manifest["payloadSBOM"]
    require(set(entries)==set(directories)|set(files),"Unexpected or missing deployment package payload")
    for name,item in entries.items():
        require(item["uid"]==0 and item["gid"]==0,"Deployment payload is not root:wheel")
        if name in directories:require(item["directory"] and item["mode"]==directories[name],"Deployment directory differs")
        else:
            record=files[name];require(not item["directory"] and item["mode"]==int(record["mode"],8) and len(item["data"])==record["bytes"] and digest(item["data"])==record["sha256"],"Deployment payload file differs")
    core=entries[prefix+"Contents/MacOS/accessweaver"]["data"];native=macho_identity(core,identity["arch"])
    require(json.loads(entries[prefix+"Contents/Resources/BUILD-INFO.json"]["data"])==identity and plistlib.loads(entries[prefix+"Contents/Info.plist"]["data"])==bundle_plist(identity["version"],native["minimumOSVersion"]),"Deployment payload build/plist differs")
    expected_scripts=script_contract(scripts_manifest)
    script_dirs={""}|({"licenses"} if any(n.startswith("licenses/") for n in expected_scripts) else set())
    require(set(scripts)==set(expected_scripts)|script_dirs,"Unexpected or missing deployment package scripts")
    for name,item in scripts.items():
        if name in script_dirs:require(item["directory"] and item["mode"]==0o755,"Deployment script directory differs")
        else:
            record=expected_scripts[name];require(not item["directory"] and item["mode"]==int(record["mode"],8) and len(item["data"])==record["bytes"] and digest(item["data"])==record["sha256"],"Deployment script differs")
    helper=macho_identity(scripts["preinstall"]["data"],identity["arch"])
    require(helper["minimumOSVersion"]==native["minimumOSVersion"],"Payload/helper OS minimum differs")
    metadata=xml(members["PackageInfo"])
    location=install_location(digest(manifest_bytes))
    require(metadata.tag=="pkg-info" and metadata.get("identifier")==PACKAGE_ID and metadata.get("version")==identity["version"] and metadata.get("install-location")==location and metadata.get("auth")=="root" and metadata.get("relocatable")=="false","Deployment package metadata differs")
    relocate=metadata.find("relocate");require(relocate is not None and len(relocate)==0,"Deployment relocation must be disabled")
    require([n.get("id") for n in metadata.findall("./strict-identifier/bundle")]==[BUNDLE_ID],"Deployment strict bundle identity differs")
    phases=metadata.findall("./scripts/*")
    require(len(phases)==2 and {n.tag:n.get("file") for n in phases}=={"preinstall":"./preinstall","postinstall":"./postinstall"},"Deployment package phase entry points differ")
    return {"packageSHA256":digest(package),"payloadSHA256":digest(core),"manifestSHA256":digest(manifest_bytes),"helperSHA256":digest(scripts["preinstall"]["data"]),"installLocation":location,"packageIdentifier":PACKAGE_ID,"payloadFiles":len(files),"payloadDirectories":len(directories),"scriptFiles":len(expected_scripts),"macho":native,"helperMachO":helper,"detachedPayloadSBOMOutsideAppVerified":True,"payloadSBOMSHA256":manifest["payloadSBOM"]["sha256"],"detachedManifestOutsideAppVerified":True,"allPathsModesOwnershipAndHashesVerified":True,"xarAndCpioIntegrityVerified":True,"targetExecutionPerformed":False,"publisherSignatureVerified":False,"productionQualificationComplete":False}

def deployment_sbom(package,payload_bytes,helper,manifest_bytes,scripts_manifest,tool,core_bytes,helper_bytes):
    require(type(manifest_bytes) is bytes and 0<len(manifest_bytes)<=2<<20,"Invalid detached SBOM inventory")
    manifest=json.loads(manifest_bytes)
    manifest_contract(manifest);script_contract(scripts_manifest)
    require(manifest["schemaVersion"]==2 and type(payload_bytes) is bytes and 0<len(payload_bytes)<=MAX_PAYLOAD_SBOM,"Expected exact detached payload SBOM bytes")
    require(len(payload_bytes)==manifest["payloadSBOM"]["bytes"] and digest(payload_bytes)==manifest["payloadSBOM"]["sha256"],"Detached compiled graph byte seal differs")
    payload=json.loads(payload_bytes)
    require(type(package) is bytes and package[:4]==b"xar!" and len(package)<=64<<20,"Expected a bounded Apple component package")
    validate(payload,core_bytes);validate(helper,helper_bytes)
    core=next(f for f in manifest["files"] if f["path"]=="Contents/MacOS/accessweaver")
    script=next(f for f in scripts_manifest if f["path"]=="preinstall")
    for document,record in ((payload,core),(helper,script)):
        require(document["metadata"]["component"].get("hashes")==[{"alg":"SHA-256","content":record["sha256"]}],"Compiled SBOM subject differs from sealed package bytes")
    require(payload["metadata"]["component"]["version"]==helper["metadata"]["component"]["version"],"Payload/helper release differs")
    for name in ("accessweaver:source-commit","accessweaver:source-state","accessweaver:target-os","accessweaver:target-arch"):
        require(prop_map(payload["metadata"]["component"]).get(name)==prop_map(helper["metadata"]["component"]).get(name),"Payload/helper source or target differs")
    result=copy.deepcopy(payload);components=[];edges=[];roots=[]
    for label,document in (("payload",payload),("helper",helper)):
        application=document["metadata"]["component"]
        require(prop_map(application).get("accessweaver:target-os")=="darwin","Expected two native Go subjects")
        prefix=label+":";roots.append(prefix+application["bom-ref"])
        for entry in [application]+document["components"]:
            item=copy.deepcopy(entry);item["bom-ref"]=prefix+item["bom-ref"];components.append(item)
        for edge in document["dependencies"]:edges.append({"ref":prefix+edge["ref"],"dependsOn":[prefix+n for n in edge["dependsOn"]]})
    file_refs=[]
    for label,records in (("bundle",manifest["files"]),("script",scripts_manifest),("detached",[{"path":DETACHED_MANIFEST,"sha256":digest(manifest_bytes)}]+([manifest["payloadSBOM"]] if manifest["schemaVersion"]==2 else []))):
        for record in records:
            ref=label+"-file:"+record["path"];item=component(ref,record["path"],"file");item["hashes"]=[{"alg":"SHA-256","content":record["sha256"]}]
            components.append(item);edges.append({"ref":ref,"dependsOn":[]});file_refs.append(ref)
    root=component("application","AccessWeaver experimental versioned macOS installer","application",payload["metadata"]["component"]["version"])
    root["hashes"]=[{"alg":"SHA-256","content":digest(package)}]
    root["properties"]=[copy.deepcopy(p) for p in payload["metadata"]["component"]["properties"] if p["name"]!="accessweaver:inventory-scope"]
    root["properties"].extend(properties({"inventory-scope":"compiled core/helper graphs, detached inventory, sealed bundle and package-script files; OS Installer/system library closure excluded","package-format":"Apple flat component package","experimental-versioned-deployment":"true","bundle-identifier":BUNDLE_ID,"package-identifier":PACKAGE_ID}))
    result["metadata"]["component"]=root;result["metadata"]["tools"]={"components":[{"type":"application","name":"Apple pkgbuild","version":tool["osBuild"],"hashes":[{"alg":"SHA-256","content":tool["sha256"]}],"properties":properties({"host-os-version":tool["osVersion"],"scope":"measured build tool; not redistributed"})}]}
    result["components"]=components;result["dependencies"]=edges+[{"ref":"application","dependsOn":roots+file_refs}]
    result["compositions"]=[{"aggregate":"incomplete","assemblies":["application"],"dependencies":roots}]
    result["serialNumber"]="urn:uuid:"+str(uuid.uuid5(uuid.NAMESPACE_URL,"accessweaver-macos-deployment:"+digest(package)))
    validate(result,package)
    return result
