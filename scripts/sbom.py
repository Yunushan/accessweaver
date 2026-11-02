#!/usr/bin/env python3
"""Generate deterministic artifact-bound CycloneDX 1.6 inventories without executing target binaries."""
import argparse
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
from urllib.parse import quote

SCHEMA="http://cyclonedx.org/schema/bom-1.6.schema.json"
PRESET_COMMIT="766422ed8ca9cb5360e8d9d540e80722a0508efc"
PRESETS={"internal/workflow/presets/zapret.txt","internal/workflow/presets/zapret2.txt","internal/workflow/presets/goodbyedpi.txt","internal/workflow/presets/LICENSE.SplitWire-Turkey"}
LICENSE_NAMES=("LICENSE","LICENSE.txt","LICENSE.md","COPYING","COPYRIGHT","NOTICE","NOTICE.txt")
# Declarations are supported by copied notice evidence, not inferred text matching.
DECLARED={"github.com/Yunushan/accessweaver":"0BSD","accessweaver.test/wgpeer":"0BSD","github.com/ebitengine/purego":"Apache-2.0",
          "github.com/google/btree":"Apache-2.0","gvisor.dev/gvisor":"Apache-2.0",
          "golang.zx2c4.com/wireguard":"MIT","golang.zx2c4.com/wintun":"MIT"}


def require(condition,message):
    if not condition:raise ValueError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def read_file(path,limit=256<<20):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size<=limit,"Expected bounded regular file: "+path.name)
    data=path.read_bytes();require(len(data)<=limit,"File grew beyond limit")
    return data


def command(args,cwd=None,env=None):
    result=subprocess.run(args,cwd=cwd,env=env,check=True,capture_output=True,text=True,encoding="utf-8",timeout=120)
    require(len(result.stdout.encode("utf-8"))<=32<<20,"Go metadata exceeds limit")
    return result.stdout


def json_stream(data):
    result=[];decoder=json.JSONDecoder();offset=0
    while offset<len(data):
        while offset<len(data) and data[offset].isspace():offset+=1
        if offset==len(data):break
        value,end=decoder.raw_decode(data,offset);result.append(value);offset=end
        require(len(result)<=4096,"Go package metadata exceeds limit")
    return result


def properties(values):return [{"name":"accessweaver:"+k,"value":str(v)} for k,v in sorted(values.items())]


def prop_map(component):
    entries=component.get("properties",[])
    values={p["name"]:p["value"] for p in entries}
    require(len(entries)==len(values),"Duplicated SBOM property")
    return values


def notice(path,output,name):
    data=read_file(path,1<<20);output.mkdir(parents=True,exist_ok=True)
    target=output/name;target.write_bytes(data)
    return {"path":"licenses/"+name,"sha256":sha(data)}


def module_notices(module,package_dirs,destination,repo):
    path=module["Path"];root=Path(module["Dir"])
    candidates=set()
    for name in LICENSE_NAMES:
        if (root/name).is_file():candidates.add(root/name)
    for directory in package_dirs:
        parent=Path(directory)
        while parent==root or root in parent.parents:
            for name in LICENSE_NAMES:
                if (parent/name).is_file():candidates.add(parent/name)
            if parent==root:break
            parent=parent.parent
    if module.get("Main"):candidates.add(repo/"LICENSE")
    records=[]
    for source in sorted(candidates,key=lambda p:str(p)):
        # Preserve notice content without leaking module-cache/workstation paths.
        relative=source.relative_to(root).as_posix() if root in source.parents else "repository-LICENSE"
        name="module-"+sha((path+"/"+relative).encode())[:20]+"-"+source.name
        records.append(notice(source,destination,name))
    require(records,"No license notice evidence for module: "+path)
    return records


def component(ref,name,kind="library",version=None):
    result={"bom-ref":ref,"type":kind,"name":name}
    if version:result["version"]=version
    return result


def generate(binary,module_root,main,identity,notices,go="go"):
    binary=binary.resolve();module_root=module_root.resolve();notices=notices.resolve()
    data=read_file(binary)
    info=json.loads(command([go,"version","-m","-json",str(binary)]))
    settings={v["Key"]:v["Value"] for v in info["Settings"]}
    require(settings.get("CGO_ENABLED")=="0","SBOM requires the qualified CGO_ENABLED=0 build")
    for key,value in [("GOOS",identity["platform"]),("GOARCH",identity["arch"])]:require(settings.get(key)==value,"Binary target differs from build identity")
    require(info["GoVersion"]==identity["goVersion"],"Binary compiler differs from build identity")
    require(command([go,"env","GOVERSION"]).strip()==info["GoVersion"],"SBOM source analysis must use the binary's compiler version")
    env=dict(os.environ,GOOS=settings["GOOS"],GOARCH=settings["GOARCH"],CGO_ENABLED="0",GOFLAGS="")
    for key in ("GOEXPERIMENT","GOAMD64","GOARM64"):
        if key in settings:env[key]=settings[key]
    args=[go,"list","-mod=readonly","-deps","-json"]
    if settings.get("-tags"):args.append("-tags="+settings["-tags"])
    packages=json_stream(command(args+[main],cwd=module_root,env=env))
    require(packages and all(not p.get("Error") and not p.get("DepsErrors") and not p.get("Incomplete") for p in packages),"Incomplete Go package graph")
    modules={};dirs={}
    for package in packages:
        module=package.get("Module")
        if module:
            require(not module.get("Replace"),"Replacement modules require separate provenance qualification")
            modules[module["Path"]]=module
            dirs.setdefault(module["Path"],set()).add(package["Dir"])
    root_path=info["Main"]["Path"]
    require(root_path in modules and modules[root_path].get("Main"),"Binary does not match the source module")
    require(packages[-1]["ImportPath"]==info["Path"],"Binary does not match the selected main package")
    deps={m["Path"]:m for m in info.get("Deps",[])}
    require(set(deps)==set(modules)-{root_path},"Compiled binary modules differ from source import graph")
    for path,dep in deps.items():require(dep.get("Version")==modules[path].get("Version"),"Compiled module version differs from source graph")
    repo=Path(command(["git","rev-parse","--show-toplevel"],cwd=module_root).strip())
    root_ref="application";stdlib_ref="go-stdlib"
    root=component(root_ref,root_path,"application",identity["version"])
    root["hashes"]=[{"alg":"SHA-256","content":sha(data)}]
    root["properties"]=properties({"source-commit":identity["commit"],"source-state":identity["sourceState"],"target-os":settings["GOOS"],"target-arch":settings["GOARCH"],"main-package":main,"cgo-enabled":"0","inventory-scope":"compiled Go import graph and embedded non-standard-library assets; OS libraries and build tools excluded"})
    refs={path:(root_ref if path==root_path else "module:"+path) for path in modules}
    refs["std"]=stdlib_ref
    edges={ref:set() for ref in refs.values()}
    go_root=Path(command([go,"env","GOROOT"]).strip())
    stdlib_version=info["GoVersion"].removeprefix("go")
    stdlib=component(stdlib_ref,"stdlib","library",stdlib_version)
    stdlib["description"]="Go standard library and runtime"
    stdlib["purl"]="pkg:golang/stdlib@"+quote(stdlib_version,safe="")
    stdlib["licenses"]=[{"license":{"id":"BSD-3-Clause"}}]
    std_notice=notice(go_root/"LICENSE",notices,"Go-runtime-LICENSE")
    stdlib["properties"]=properties({"license-evidence":json.dumps([std_notice],sort_keys=True,separators=(",",":"))})
    components=[stdlib]
    license_records={}
    for path,module in sorted(modules.items()):
        c=root if path==root_path else component(refs[path],path,version=module["Version"])
        records=module_notices(module,dirs[path],notices,repo)
        license_records[path]=records
        declared=DECLARED.get(path,"BSD-3-Clause" if path.startswith("golang.org/x/") else None)
        if declared:c["licenses"]=[{"license":{"id":declared}}]
        c.setdefault("properties",[]).extend(properties({"license-evidence":json.dumps(records,sort_keys=True,separators=(",",":"))}))
        if path!=root_path:
            dep=deps[path]
            require(dep.get("Sum") and dep["Sum"]==module.get("Sum"),"Compiled module checksum differs from source graph")
            c["purl"]="pkg:golang/"+quote(path,safe="/")+"@"+quote(dep["Version"],safe="")
            c["properties"].extend(properties({"go-module-sum":dep["Sum"]}))
            components.append(c)
    pkg_refs={p["ImportPath"]:(stdlib_ref if p.get("Standard") else refs[p["Module"]["Path"]]) for p in packages}
    assets={}
    for package in packages:
        owner=pkg_refs[package["ImportPath"]]
        for imported in package.get("Imports",[]):
            imported=package.get("ImportMap",{}).get(imported,imported)
            require(imported in pkg_refs,"Unresolved Go import edge")
            if pkg_refs[imported]!=owner:edges[owner].add(pkg_refs[imported])
        if package.get("Standard"):continue
        module=package["Module"]
        for name in package.get("EmbedFiles",[]):
            path=Path(package["Dir"])/name
            relative=path.relative_to(Path(module["Dir"])).as_posix()
            ref="asset:"+module["Path"]+"/"+relative
            contents=read_file(path,16<<20)
            item=component(ref,relative,"file")
            item["hashes"]=[{"alg":"SHA-256","content":sha(contents)}]
            if module.get("Main"):
                license_id="MIT" if relative in PRESETS else "0BSD"
                item["licenses"]=[{"license":{"id":license_id}}]
                if relative in PRESETS:
                    preset_notice=notice(repo/"internal/workflow/presets/LICENSE.SplitWire-Turkey",notices,"SplitWire-Turkey-MIT.txt")
                    item["properties"]=properties({"upstream":"https://github.com/cagritaskn/SplitWire-Turkey","upstream-commit":PRESET_COMMIT,
                        "license-evidence":json.dumps([preset_notice],sort_keys=True,separators=(",",":"))})
                else:item["properties"]=properties({"license-evidence":json.dumps(license_records[module["Path"]],sort_keys=True,separators=(",",":"))})
            assets[ref]=item;edges[owner].add(ref);edges[ref]=set()
    components.extend(assets[ref] for ref in sorted(assets))
    edges[root_ref].add(stdlib_ref)
    document={"$schema":SCHEMA,"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
              "serialNumber":"urn:uuid:"+str(uuid.uuid5(uuid.NAMESPACE_URL,"accessweaver:"+sha(data)+":"+identity["commit"])),
              "metadata":{"timestamp":identity["builtAt"],"component":root},"components":components,
              "dependencies":[{"ref":ref,"dependsOn":sorted(values)} for ref,values in sorted(edges.items())],
              "compositions":[{"aggregate":"incomplete","assemblies":[root_ref],"dependencies":[root_ref]}]}
    validate(document,data,identity)
    return document


def validate(document,binary,identity=None):
    require(document.get("bomFormat")=="CycloneDX" and document.get("specVersion")=="1.6","Expected CycloneDX 1.6")
    root=document["metadata"]["component"]
    require(root.get("type")=="application","Expected an application SBOM root")
    require(root.get("hashes")==[{"alg":"SHA-256","content":sha(binary)}],"SBOM does not match artifact bytes")
    values=prop_map(root)
    if identity:
        require(root["version"]==identity["version"],"SBOM version mismatch")
        for key,expected in [("source-commit",identity["commit"]),("source-state",identity["sourceState"]),("target-os",identity["platform"]),("target-arch",identity["arch"])]:require(values.get("accessweaver:"+key)==expected,"SBOM build identity mismatch")
    all_components=[root]+document.get("components",[])
    refs=[c["bom-ref"] for c in all_components]
    require(len(refs)==len(set(refs)),"Duplicated SBOM component reference")
    for c in all_components:
        values=prop_map(c)
        if c.get("type")!="file" or c.get("licenses"):
            records=json.loads(values.get("accessweaver:license-evidence","[]"))
            require(isinstance(records,list) and records,"Missing component license evidence")
            for record in records:
                require(re.fullmatch(r"licenses/[A-Za-z0-9._-]+",record["path"]) and re.fullmatch(r"[a-f0-9]{64}",record["sha256"]),"Invalid license evidence")
    known=set(refs);graph={}
    for edge in document.get("dependencies",[]):
        require(edge["ref"] in known and edge["ref"] not in graph,"Invalid dependency node")
        require(set(edge.get("dependsOn",[]))<=known,"Dangling SBOM dependency")
        graph[edge["ref"]]=edge.get("dependsOn",[])
    require(set(graph)==known,"Missing dependency declarations")
    reached=set();pending=[root["bom-ref"]]
    while pending:
        ref=pending.pop()
        if ref in reached:continue
        reached.add(ref);pending.extend(graph[ref])
    require(reached==known,"Unreachable SBOM component")
    require(document.get("compositions") and all(c.get("aggregate")=="incomplete" for c in document["compositions"]),"Inventory completeness must retain qualification limits")
    return True


def fixture_identity(binary,module_root,go):
    info=json.loads(command([go,"version","-m","-json",str(binary.resolve())]))
    settings={v["Key"]:v["Value"] for v in info["Settings"]}
    commit=command(["git","rev-parse","HEAD"],cwd=module_root).strip()
    modified=bool(command(["git","status","--porcelain","--untracked-files=normal"],cwd=module_root).strip())
    epoch=int(command(["git","show","-s","--format=%ct","HEAD"],cwd=module_root).strip())
    return {"version":"test-"+commit[:12],"commit":commit,"sourceState":"modified" if modified else "clean",
            "goVersion":info["GoVersion"],"platform":settings["GOOS"],"arch":settings["GOARCH"],
            "builtAt":datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def installer(binary,payload,compiler,compiler_version,compiler_license,notices):
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",compiler_version),"Expected the measured Inno Setup compiler version")
    result=copy.deepcopy(payload)
    application=result["metadata"]["component"]
    old_ref=application["bom-ref"];application["bom-ref"]="payload-application"
    for entry in result["dependencies"]:
        if entry["ref"]==old_ref:entry["ref"]="payload-application"
        entry["dependsOn"]=["payload-application" if ref==old_ref else ref for ref in entry["dependsOn"]]
    result["components"].insert(0,application)
    native=component("inno-setup","Inno Setup generated installer runtime","framework",compiler_version)
    native["licenses"]=[{"license":{"name":"Inno Setup License"}}]
    evidence=notice(compiler_license,notices,"Inno-Setup-License.txt")
    native["properties"]=properties({"compiler-sha256":sha(read_file(compiler)),"license-evidence":json.dumps([evidence],sort_keys=True,separators=(",",":")),
                                     "identification":"compiler-engine compilation banner; bundled native dependency closure remains unqualified"})
    result["components"].append(native)
    root=component("application","AccessWeaver Windows installer","application",application["version"])
    contents=read_file(binary)
    root["hashes"]=[{"alg":"SHA-256","content":sha(contents)}]
    root["properties"]=[copy.deepcopy(p) for p in application["properties"] if p["name"]!="accessweaver:inventory-scope"]
    root["properties"].extend(properties({"inventory-scope":"staged Go application and Inno Setup compiler-identified runtime; native compression/helper closure remains incomplete"}))
    result["metadata"]["component"]=root
    result["serialNumber"]="urn:uuid:"+str(uuid.uuid5(uuid.NAMESPACE_URL,"accessweaver-installer:"+sha(contents)))
    result["dependencies"].extend([{"ref":"application","dependsOn":["payload-application","inno-setup"]},{"ref":"inno-setup","dependsOn":[]}])
    result["compositions"]=[{"aggregate":"incomplete","assemblies":["application","inno-setup"],"dependencies":["inno-setup"]}]
    validate(result,contents)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",type=Path,required=True)
    parser.add_argument("--module-root",type=Path)
    parser.add_argument("--main")
    parser.add_argument("--identity",type=Path)
    parser.add_argument("--fixture",action="store_true")
    parser.add_argument("--payload-sbom",type=Path)
    parser.add_argument("--compiler",type=Path)
    parser.add_argument("--compiler-version")
    parser.add_argument("--compiler-license",type=Path)
    parser.add_argument("--notices",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--go",default="go")
    args=parser.parse_args()
    if args.payload_sbom:
        require(args.compiler and args.compiler_version and args.compiler_license,"Installer SBOM requires compiler and notice evidence")
        document=installer(args.binary,json.loads(read_file(args.payload_sbom,16<<20)),args.compiler,args.compiler_version,args.compiler_license,args.notices)
    else:
        require(args.module_root and args.main,"Binary SBOM requires source module/main package")
        require(args.identity or args.fixture,"A build identity is required")
        identity=fixture_identity(args.binary,args.module_root,args.go) if args.fixture else json.loads(read_file(args.identity,1<<20))
        document=generate(args.binary,args.module_root,args.main,identity,args.notices,args.go)
    args.out.write_text(json.dumps(document,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")


if __name__=="__main__":main()
