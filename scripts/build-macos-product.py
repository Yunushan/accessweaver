#!/usr/bin/env python3
"""Build and inspect a native unsigned desktop product; never install it."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import tempfile

from macos_installer import digest,require
from macos_desktop import inspect_component
from macos_deployment import inspect_deployment
from macos_product import component_inputs,distribution,product_name,product_members,inspect_product,product_sbom
from sbom import validate

REPO=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location("accessweaver_product_dependency_builder",Path(__file__).with_name("build-macos-desktop.py"))
desktop=importlib.util.module_from_spec(spec);spec.loader.exec_module(desktop)
run=desktop.run;encode=desktop.encode


def build(version,arch,go="go"):
    product_name(version,arch)
    require(platform.system()=="Darwin" and os.geteuid()!=0,"Native ordinary-user product builder required")
    require(run(["/usr/sbin/sysctl","-n","sysctl.proc_translated"],codes=(0,1)).stdout.strip()!=b"1","Translated product builder refused")
    cpu=run(["/usr/sbin/sysctl","-n","hw.optional.arm64"],codes=(0,1)).stdout.strip()
    require(arch==("arm64" if cpu==b"1" else "amd64"),"Cross/emulated product builder refused")
    base=REPO/"build/macos-deployment-checks"/arch;core=base/version;public=base/"desktop"/version
    identity=json.loads((core/"BUILD-INFO.json").read_bytes())
    require(identity["version"]==version and identity["arch"]==arch and identity["platform"]=="darwin" and identity["sourceState"]=="clean" and identity["commit"]==run(["git","rev-parse","HEAD"]).stdout.decode().strip() and not run(["git","status","--porcelain","--untracked-files=normal"]).stdout.strip(),"Product requires exact clean component source")
    require(json.loads((public/"BUILD-INFO.json").read_bytes())==identity,"Product public/core build differs")
    sdk=json.loads(run([go,"env","-json","GOHOSTOS","GOHOSTARCH","GOVERSION"],env=dict(os.environ,GOTOOLCHAIN="local")).stdout)
    require(sdk=={"GOHOSTOS":"darwin","GOHOSTARCH":arch,"GOVERSION":identity["goVersion"]},"Product native SDK differs")
    record=(public/"DESKTOP-RECORD.json").read_bytes();desktop.validate_record(record,identity)
    inputs=component_inputs(version,arch,record);packages={};graphs={};reports={}
    core_report=json.loads((core/"compiler-artifact.json").read_bytes());public_report=json.loads((public/"compiler-artifact.json").read_bytes())
    require(public_report["sourceCommit"]==identity["commit"] and public_report["recordSHA256"]==digest(record),"Product registration/source differs")
    for role,identifier,name in inputs:
        directory=core if role=="core" else public;raw=(directory/name).read_bytes();require(0<len(raw)<=64<<20,"Product component budget exceeded")
        if role=="core":
            inspected=inspect_deployment(raw,(core/"INSTALL-MANIFEST.json").read_bytes(),identity,json.loads((core/"SCRIPT-MANIFEST.json").read_bytes()));report=core_report
        else:
            report=next(c for c in public_report["components"] if c["component"]==role)
            inspected=inspect_component(raw,record,identity,role,json.loads((public/(role+"-SCRIPT-MANIFEST.json")).read_bytes()),report["scriptArchiveOwner"])
        require(inspected==report["archiveInspection"],"Product component changed after native construction")
        graph=json.loads((directory/(name+".cdx.json")).read_bytes());validate(graph,raw,identity)
        packages[name]=raw;graphs[role]=graph;reports[role]=inspected
    output=base/"product"/version;require(not output.exists(),"Product output exists; preserve it");output.mkdir(parents=True)
    stage=Path(tempfile.mkdtemp(prefix="macos-product-stage-",dir=REPO/"build"))
    try:
        private=stage/"user";private.mkdir();env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":str(private),"TMPDIR":str(private),"LANG":"C","LC_ALL":"C","TZ":"UTC"}
        for name,raw in packages.items():path=stage/name;path.write_bytes(raw);path.chmod(0o644)
        source=stage/"distribution.dist";source.write_bytes(distribution(version,arch,inputs))
        target=output/product_name(version,arch)
        run(["/usr/bin/productbuild","--distribution",source,"--package-path",stage,target],env=env)
        raw=target.read_bytes();members=product_members(raw,list(packages));inspection=inspect_product(raw,version,arch,inputs,packages)
        (output/"DISTRIBUTION.xml").write_bytes(members["Distribution"])
        expanded=stage/"expanded";run(["/usr/sbin/pkgutil","--expand",target,expanded],env=env)
        expected_dirs={name.rsplit("/",1)[0] for name in members if "/" in name};actual_files={};actual_dirs=set()
        for path in expanded.rglob("*"):
            st=path.lstat();name=path.relative_to(expanded).as_posix()
            require(not path.is_symlink() and st.st_uid==os.getuid(),"Expanded product ownership/type differs")
            if stat.S_ISDIR(st.st_mode):actual_dirs.add(name)
            else:
                require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=64<<20,"Expanded product file differs")
                actual_files[name]=path.read_bytes()
        require(actual_files==members and actual_dirs in (expected_dirs,expected_dirs|{"Resources"}),"Expanded product member bytes differ")
        if "Resources" in actual_dirs:require(not list((expanded/"Resources").iterdir()),"Unexpected product resources")
        signature=run(["/usr/sbin/pkgutil","--check-signature",target],env=env,codes=(0,1))
        require(signature.returncode!=0 and b"no signature" in (signature.stdout+signature.stderr).lower(),"Experimental product unexpectedly publisher-signed")
        tool={"sha256":digest(Path("/usr/bin/productbuild").read_bytes()),"osVersion":run(["/usr/bin/sw_vers","-productVersion"],env=env).stdout.decode().strip(),"osBuild":run(["/usr/bin/sw_vers","-buildVersion"],env=env).stdout.decode().strip()}
        graph=product_sbom(raw,identity,inputs,packages,graphs,tool);encode(output/(target.name+".cdx.json"),graph)
        validator=stage/"sbom-schema";run([go,"-C",REPO/"scripts/sbom-tools","build","-mod=readonly","-trimpath","-o",validator,"."],env=dict(os.environ,GOTOOLCHAIN="local"));run([validator,"--schemas",REPO/"scripts/sbom/schema",output/(target.name+".cdx.json")],env=env)
        report={"schemaVersion":1,"sourceCommit":identity["commit"],"build":identity,"productFile":target.name,"productBytes":len(raw),"productSHA256":digest(raw),"productbuild":tool,"archiveInspection":inspection,"componentInspections":reports,"actualExpandedMemberBytesVerified":True,"productGraphSchemaValidated":True,"unsigned":True,"installationExecuted":False,"singleProductLifecycleQualified":False,"publisherSignatureVerified":False,"notarized":False,"productUninstallQualified":False,"managedEndpointQualified":False,"productionQualificationComplete":False}
        encode(output/"compiler-artifact.json",report);return report
    finally:
        require(stage.resolve().parent==(REPO/"build").resolve() and stage.name.startswith("macos-product-stage-"),"Unsafe product builder cleanup");shutil.rmtree(stage)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--version",required=True);parser.add_argument("--architecture",choices=("amd64","arm64"),required=True);parser.add_argument("--go",default="go");args=parser.parse_args()
    print(json.dumps(build(args.version,args.architecture,args.go)))


if __name__=="__main__":main()
