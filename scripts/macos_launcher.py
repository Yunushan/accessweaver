"""Bounded ordinary-user launcher candidate archive. Never executes a target."""
import io
import json
import re
import stat
import zipfile

from macos_installer import digest,macho_identity,require
from sbom import validate,prop_map

BINARY="accessweaver-launcher"
MAIN="github.com/Yunushan/accessweaver/cmd/accessweaver-launcher"

def archive_name(arch):
    require(arch in ("amd64","arm64"),"Invalid launcher architecture")
    return "accessweaver-launcher-darwin-"+arch+"-experimental.zip"

def inspect_launcher(encoded,identity):
    require(type(encoded) is bytes and 0<len(encoded)<=16<<20,"Invalid launcher archive extent")
    with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
        infos=archive.infolist();names={i.filename for i in infos}
        require(4<len(infos)<=520 and len(names)==len(infos) and sum(i.file_size for i in infos)<=32<<20,"Invalid launcher archive inventory")
        for item in infos:
            name=item.filename
            require(not item.is_dir() and not item.flag_bits&1 and (name in (BINARY,"BUILD-INFO.json","SBOM.cdx.json","compiler-artifact.json") or re.fullmatch(r"licenses/[A-Za-z0-9._-]+",name) is not None and name not in ("licenses/.","licenses/..")),"Unexpected launcher archive path")
            require(0<item.file_size<=(16<<20 if name==BINARY else 2<<20 if name.endswith(".json") else 1<<20),"Launcher archive member exceeds budget")
            require(stat.S_IFMT(item.external_attr>>16)==stat.S_IFREG and (item.external_attr>>16)&0o7777==(0o755 if name==BINARY else 0o644),"Launcher archive member mode/type differs")
        data={name:archive.read(name) for name in names}
    require({BINARY,"BUILD-INFO.json","SBOM.cdx.json","compiler-artifact.json"}<=names,"Launcher archive is incomplete")
    require(json.loads(data["BUILD-INFO.json"])==identity,"Launcher build identity differs")
    binary=data[BINARY];native=macho_identity(binary,identity["arch"]);report=json.loads(data["compiler-artifact.json"])
    require(report.get("schemaVersion")==1 and report.get("build")==identity and report.get("binarySHA256")==digest(binary) and report.get("binaryBytes")==len(binary) and report.get("macho")==native,"Launcher compiler report differs")
    metadata=report["goBuildMetadata"];settings={v["Key"]:v["Value"] for v in metadata["Settings"]}
    require(metadata.get("GoVersion")==identity["goVersion"] and metadata.get("Path")==MAIN and settings.get("GOOS")=="darwin" and settings.get("GOARCH")==identity["arch"] and settings.get("CGO_ENABLED")=="0" and settings.get("-trimpath")=="true" and "-ldflags" not in settings,"Launcher Go metadata differs")
    flags=" ".join("-X github.com/Yunushan/accessweaver/internal/buildinfo."+key+"="+value for key,value in {"Version":identity["version"],"Commit":identity["commit"],"SourceState":"clean","BuiltAt":identity["builtAt"]}.items())
    require(report.get("linkerFlags")==flags and report.get("unsigned") is True and all(report.get(k) is False for k in ("publisherSignatureVerified","publicApplicationIntegrated","productionQualificationComplete")),"Launcher construction scope differs")
    bom=json.loads(data["SBOM.cdx.json"]);validate(bom,binary,identity);notices={}
    for component in [bom["metadata"]["component"]]+bom["components"]:
        for evidence in json.loads(prop_map(component).get("accessweaver:license-evidence","[]")):
            name=evidence["path"];require(name in data and digest(data[name])==evidence["sha256"],"Launcher notice differs")
            notices[name]=evidence["sha256"]
    require(names=={BINARY,"BUILD-INFO.json","SBOM.cdx.json","compiler-artifact.json"}|set(notices),"Unexpected launcher notice/artifact")
    return {"archiveSHA256":digest(encoded),"binarySHA256":digest(binary),"binaryBytes":len(binary),"macho":native,"goBuildMetadata":metadata,"build":identity,"noticesVerified":len(notices),"publicApplicationIntegrated":False,"publisherSignatureVerified":False,"productionQualificationComplete":False}
