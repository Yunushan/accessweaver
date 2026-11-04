#!/usr/bin/env python3
"""Authenticate all public-desktop subjects before parsing; never execute targets."""
import argparse
import io
import json
from pathlib import Path,PurePosixPath
import re
import subprocess
import tempfile
import zipfile

from macos_installer import BUNDLE_NAME,MAX_BYTES,digest,require
from macos_desktop import BINARY,component_name,record_name,validate_record,inspect_component,package_sbom
from macos_launcher import archive_name,inspect_launcher
from macos_product import component_inputs,product_name,product_members,inspect_product,product_sbom,expanded_inventory
from macos_package_archive import flat_members,cpio,inflate
from sbom import validate,prop_map
from verify_macos_deployment_provenance import VERSIONS,subjects as core_subjects,validate_packages,copy_subject,check_rejections as shared_rejections
from verify_release_provenance import BUNDLE_NAME as PROVENANCE_BUNDLE,REPOSITORY,validate_identity,verification_command as portable_command
from verify_release_rebuild import snapshot

WORKFLOW=REPOSITORY+"/.github/workflows/macos-desktop.yml"


def subjects(arch):
    require(arch in ("amd64","arm64"),"Expected native desktop architecture")
    result={"desktop-lifecycle-artifact.json":Path("desktop-lifecycle-artifact.json"),"product-lifecycle-artifact.json":Path("product-lifecycle-artifact.json"),"product-recovery-artifact.json":Path("product-recovery-artifact.json")}
    for name,(version,original) in core_subjects(arch).items():
        if version is not None:result[name]=Path(version)/original
    for version in VERSIONS:
        name=archive_name(arch,None if version==VERSIONS[-1] else version);result[name]=Path(name)
        for role in ("metadata","application"):
            name=component_name(version,arch,role)
            result[name]=Path("desktop")/version/name;result[name+".cdx.json"]=Path("desktop")/version/(name+".cdx.json")
        for original in ("BUILD-INFO.json","DESKTOP-RECORD.json","compiler-artifact.json","metadata-SCRIPT-MANIFEST.json","application-SCRIPT-MANIFEST.json","metadata-helper-SBOM.cdx.json","application-helper-SBOM.cdx.json"):
            result["desktop-"+version+"-"+original]=Path("desktop")/version/original
        name=component_name(version,arch,"application",product=True)
        result[name]=Path("product-components")/version/name;result[name+".cdx.json"]=Path("product-components")/version/(name+".cdx.json")
        for original in ("compiler-artifact.json","application-SCRIPT-MANIFEST.json","application-helper-SBOM.cdx.json"):
            result["product-application-"+version+"-"+original]=Path("product-components")/version/original
        name=product_name(version,arch)
        result[name]=Path("product")/version/name;result[name+".cdx.json"]=Path("product")/version/(name+".cdx.json")
        for original in ("DISTRIBUTION.xml","compiler-artifact.json"):result["product-"+version+"-"+original]=Path("product")/version/original
    require(len(result)==61,"Desktop known subject extent changed")
    return result


def verification_command(path,bundle,commit,ref,gh="gh"):
    command=portable_command(path,bundle,commit,ref,gh);command[command.index("--signer-workflow")+1]=WORKFLOW;return command


def authenticate(path,bundle,commit,ref,gh):
    try:subprocess.run(verification_command(path,bundle,commit,ref,gh),check=True,capture_output=True,timeout=120)
    except subprocess.CalledProcessError as error:raise ValueError("Desktop cryptographic provenance verification failed") from error


def check_rejections(path,bundle,commit,ref,gh):
    return shared_rejections(path,bundle,commit,ref,gh,command_builder=verification_command)


def check_metadata(metadata,identity,main):
    settings={v["Key"]:v["Value"] for v in metadata["Settings"]}
    require(metadata.get("GoVersion")==identity["goVersion"] and metadata.get("Path")=="github.com/Yunushan/accessweaver/cmd/"+main and settings.get("GOOS")=="darwin" and settings.get("GOARCH")==identity["arch"] and settings.get("CGO_ENABLED")=="0" and settings.get("-trimpath")=="true" and "-ldflags" not in settings,"Desktop native compiled metadata differs")



def validate_coordinated_application(root,commit,arch,identity,encoded,record,core,launcher):
    read=lambda name:json.loads((root/name).read_text(encoding="utf-8"))
    prefix="product-application-"+identity["version"]+"-";report=read(prefix+"compiler-artifact.json")
    require(report.get("schemaVersion")==1 and report.get("sourceCommit")==commit and report.get("build")==identity and report.get("recordFile")==record_name(encoded) and report.get("recordSHA256")==digest(encoded) and report.get("productCoordination") is True,"Product application construction identity differs")
    binding={"version":identity["version"],"manifestSHA256":core["manifestSHA256"],"payloadSHA256":core["payloadSHA256"]}
    require(report.get("coreIdentity")==binding and report.get("pkgbuild")==core["pkgbuild"],"Product application core/tool binding differs")
    require(report.get("launcherBinarySHA256")==launcher["binarySHA256"] and report.get("launcherArchiveSHA256")==launcher["archiveSHA256"],"Product application launcher differs")
    require(all(report.get(k) is True for k in ("nativeBundleConstructionVerified","actualExpandedPayloadAndScriptsVerified","allCompiledAndPackageGraphsSchemaValidated","metadataOutsideAppVerified","packagePayloadWritesAreOSInstallerOnly","unsigned")),"Product application construction incomplete")
    require(all(report.get(k) is False for k in ("installationExecuted","launchServicesQualified","publisherSignatureVerified","notarized","productUninstallQualified","managedEndpointQualified","productionQualificationComplete")),"Unqualified product application scope changed")
    items=report.get("components");require(type(items) is list and len(items)==1 and items[0].get("component")=="application","Product application component inventory differs")
    item=items[0];name=component_name(identity["version"],arch,"application",product=True);raw=(root/name).read_bytes();scripts=read(prefix+"application-SCRIPT-MANIFEST.json")
    inspected=inspect_component(raw,encoded,identity,"application",scripts,item["scriptArchiveOwner"])
    require(item.get("file")==name and item.get("bytes")==len(raw) and item.get("sha256")==digest(raw) and item.get("archiveInspection")==inspected and item.get("helperSHA256")==inspected["helperSHA256"],"Actual product application differs")
    check_metadata(item["helperBuildMetadata"],identity,"accessweaver-product-installer")
    stamps={"Version":identity["version"],"Commit":commit,"SourceState":"clean","BuiltAt":identity["builtAt"]}
    flags=["-X github.com/Yunushan/accessweaver/internal/buildinfo."+k+"="+v for k,v in stamps.items()]
    seals={"sealedDesktopRecordSHA256":digest(encoded),"sealedDesktopComponent":"application","sealedVersion":binding["version"],"sealedManifestSHA256":binding["manifestSHA256"],"sealedPayloadSHA256":binding["payloadSHA256"]}
    flags.extend("-X github.com/Yunushan/accessweaver/internal/packageupgrade."+k+"="+v for k,v in seals.items())
    require(item.get("helperLinkerFlags")==" ".join(flags),"Product application dual compiled seals differ")
    members=flat_members(raw);payload=cpio(inflate(members["Payload"],MAX_BYTES,31));script_data=cpio(inflate(members["Scripts"],32<<20,31))
    helper=script_data["preinstall"]["data"];helper_graph=read(prefix+"application-helper-SBOM.cdx.json");validate(helper_graph,helper,identity)
    require(prop_map(helper_graph["metadata"]["component"]).get("accessweaver:main-package")=="./cmd/accessweaver-product-installer","Product helper graph main differs")
    payload_records=[dict(f,path=BUNDLE_NAME+"/"+f["path"]) for f in record["manifest"]["files"]]
    graph=read(name+".cdx.json");validate(graph,raw,identity)
    require(graph==package_sbom(raw,identity,helper_graph,json.loads(record["compiledSBOM"]),payload_records,scripts,report["pkgbuild"]),"Product application compiled/payload graphs differ")
    for c in [graph["metadata"]["component"]]+graph["components"]:
        for evidence in json.loads(prop_map(c).get("accessweaver:license-evidence","[]")):
            path=evidence["path"];require(path in script_data and digest(script_data[path]["data"])==evidence["sha256"],"Product helper notice differs")
    require(digest(payload[BUNDLE_NAME+"/Contents/MacOS/"+BINARY]["data"])==launcher["binarySHA256"],"Product launcher bytes differ")
    return inspected


def validate_contents(root,commit,arch):
    read=lambda name:json.loads((root/name).read_text(encoding="utf-8"))
    cores,core_bindings,_=validate_packages(root,commit,arch);records={};public_bindings={};outputs=[];identities={};product_bindings={};product_helpers={}
    for version in VERSIONS:
        identity=read(version+"-BUILD-INFO.json");identities[version]=identity
        prefix="desktop-"+version+"-";require(read(prefix+"BUILD-INFO.json")==identity,"Public/core build identities differ")
        encoded=(root/(prefix+"DESKTOP-RECORD.json")).read_bytes();record=validate_record(encoded,identity);records[version]=digest(encoded)
        report=read(prefix+"compiler-artifact.json")
        archive=archive_name(arch,None if version==VERSIONS[-1] else version);archive_bytes=(root/archive).read_bytes();launcher=inspect_launcher(archive_bytes,identity)
        require(report.get("schemaVersion")==1 and report.get("sourceCommit")==commit and report.get("build")==identity and report.get("recordFile")==record_name(encoded) and report.get("recordSHA256")==digest(encoded) and report.get("launcherArchiveSHA256")==digest(archive_bytes) and report.get("launcherBinarySHA256")==launcher["binarySHA256"],"Desktop construction/launcher subjects differ")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as source:
            require(source.read("SBOM.cdx.json")==record["compiledSBOM"].encode("utf-8"),"Desktop compiled graph raw bytes differ from launcher archive")
        require(all(report.get(k) is True for k in ("nativeBundleConstructionVerified","actualExpandedPayloadAndScriptsVerified","allCompiledAndPackageGraphsSchemaValidated","metadataOutsideAppVerified","packagePayloadWritesAreOSInstallerOnly","unsigned")),"Desktop construction incomplete")
        require(all(report.get(k) is False for k in ("installationExecuted","launchServicesQualified","publisherSignatureVerified","notarized","productUninstallQualified","managedEndpointQualified","productionQualificationComplete")),"Unqualified desktop construction scope changed")
        require(report.get("productCoordination") is False,"Standalone desktop construction may not select product coordination")
        items=report["components"];require(type(items) is list and [c.get("component") for c in items]==["metadata","application"],"Desktop component inventory differs")
        public_bindings[version]={};inspections=[]
        for role,item in zip(("metadata","application"),items):
            name=component_name(version,arch,role);raw=(root/name).read_bytes();scripts=read(prefix+role+"-SCRIPT-MANIFEST.json")
            inspected=inspect_component(raw,encoded,identity,role,scripts,item["scriptArchiveOwner"])
            require(item.get("file")==name and item.get("bytes")==len(raw) and item.get("sha256")==digest(raw) and item.get("archiveInspection")==inspected and item.get("helperSHA256")==inspected["helperSHA256"],"Actual desktop component differs from producer inspection")
            check_metadata(item["helperBuildMetadata"],identity,"accessweaver-desktop-installer")
            stamps={"Version":version,"Commit":commit,"SourceState":"clean","BuiltAt":identity["builtAt"]}
            flags=["-X github.com/Yunushan/accessweaver/internal/buildinfo."+k+"="+v for k,v in stamps.items()]
            flags.extend("-X github.com/Yunushan/accessweaver/internal/packageupgrade."+k+"="+v for k,v in {"sealedDesktopRecordSHA256":digest(encoded),"sealedDesktopComponent":role}.items())
            require(item.get("helperLinkerFlags")==" ".join(flags),"Desktop compiled component/seal invocation differs")
            members=flat_members(raw);payload=cpio(inflate(members["Payload"],MAX_BYTES,31));script_data=cpio(inflate(members["Scripts"],32<<20,31))
            helper=script_data["preinstall"]["data"];helper_graph=read(prefix+role+"-helper-SBOM.cdx.json");validate(helper_graph,helper,identity)
            graph=json.loads(record["compiledSBOM"]) if role=="application" else None
            payload_records=[dict(f,path=BUNDLE_NAME+"/"+f["path"]) for f in record["manifest"]["files"]] if role=="application" else [{"path":record_name(encoded),"bytes":len(encoded),"sha256":digest(encoded),"mode":"0644"}]
            bom=read(name+".cdx.json");validate(bom,raw,identity)
            require(bom==package_sbom(raw,identity,helper_graph,graph,payload_records,scripts,report["pkgbuild"]),"Desktop actual payload/script compiled graphs differ")
            for c in [bom["metadata"]["component"]]+bom["components"]:
                for evidence in json.loads(prop_map(c).get("accessweaver:license-evidence","[]")):
                    path=evidence["path"];require(path in script_data and digest(script_data[path]["data"])==evidence["sha256"],"Desktop compiled component notice differs")
            if role=="application":require(digest(payload[BUNDLE_NAME+"/Contents/MacOS/"+BINARY]["data"])==launcher["binarySHA256"],"Actual public launcher and standalone archive differ")
            public_bindings[version][role]=digest(raw);inspections.append(inspected)
        coordinated_inspection=validate_coordinated_application(root,commit,arch,identity,encoded,record,read(version+"-compiler-artifact.json"),launcher)
        product_helpers[version]=coordinated_inspection["helperSHA256"]
        product=product_name(version,arch);product_raw=(root/product).read_bytes();product_report=read("product-"+version+"-compiler-artifact.json")
        inputs=component_inputs(version,arch,encoded);input_packages={name:(root/name).read_bytes() for _,_,name in inputs}
        product_inspection=inspect_product(product_raw,version,arch,inputs,input_packages)
        require(product_report.get("schemaVersion")==1 and product_report.get("sourceCommit")==commit and product_report.get("build")==identity and product_report.get("productFile")==product and product_report.get("productBytes")==len(product_raw) and product_report.get("productSHA256")==digest(product_raw) and product_report.get("archiveInspection")==product_inspection,"Actual product construction differs")
        require(product_report.get("componentInspections")==dict(core=cores[VERSIONS.index(version)],metadata=inspections[0],application=coordinated_inspection),"Product component construction differs")
        require(all(product_report.get(k) is True for k in ("actualExpandedPayloadAndScriptsVerified","productGraphSchemaValidated","unsigned")),"Product construction incomplete")
        expected_files,_=expanded_inventory((root/("product-"+version+"-DISTRIBUTION.xml")).read_bytes(),input_packages)
        expanded=product_report.get("expandedInspection",{});require(type(expanded.get("files")) is int and expanded["files"]==len(expected_files) and all(expanded.get(k) is True for k in ("payloadAndScriptDirectoryModesVerified","payloadAndScriptFileModesVerified","allExpandedBytesVerified")) and expanded.get("targetExecutionPerformed") is False,"Native expanded product inspection incomplete")
        require(all(product_report.get(k) is False for k in ("installationExecuted","singleProductLifecycleQualified","publisherSignatureVerified","notarized","productUninstallQualified","managedEndpointQualified","productionQualificationComplete")),"Unqualified product construction scope changed")
        tool=product_report["productbuild"];core_tool=read(version+"-compiler-artifact.json")["pkgbuild"]
        require(set(tool)=={"sha256","osVersion","osBuild"} and re.fullmatch("[a-f0-9]{64}",tool["sha256"]) is not None and all(tool[k]==core_tool[k] for k in ("osVersion","osBuild")),"Product builder observation differs")
        require((root/("product-"+version+"-DISTRIBUTION.xml")).read_bytes()==product_members(product_raw,list(input_packages))["Distribution"],"Retained product distribution bytes differ")
        input_graphs={role:read(name+".cdx.json") for role,_,name in inputs};product_graph=read(product+".cdx.json");validate(product_graph,product_raw,identity)
        require(product_graph==product_sbom(product_raw,identity,inputs,input_packages,input_graphs,tool),"Product compiled/input/member graph differs")
        product_bindings[version]=digest(product_raw)
        outputs.append({"version":version,"launcher":launcher,"components":inspections,"recordSHA256":digest(encoded),"productArchiveConstruction":product_inspection})
    life=read("desktop-lifecycle-artifact.json")
    require(life.get("schemaVersion")==1 and life.get("sourceCommit")==commit and life.get("target")=="darwin/"+arch and life.get("stage")=="deactivation-and-owned-cleanup" and life.get("failureType") is None and life.get("failureSourceLine") is None and re.fullmatch("[1-9][0-9]{0,19}",str(life.get("runID",""))) is not None,"Desktop native lifecycle identity/completion differs")
    require(life.get("corePackageSHA256")=={v:b["packageSHA256"] for v,b in core_bindings.items()} and life.get("desktopRecordSHA256")==records and life.get("desktopPackageSHA256")==public_bindings,"Desktop native lifecycle is not bound to actual subjects")
    require(all(life.get(k) is True for k in ("passed","actualOrderedComponentsExecuted","publicAppAndProtectedRegistrationsVerified","coreUpgradeWithPublicEntryVerified","actualUserDataAndContainerProtectionPreserved","ownedFixturesRemoved")),"Actual public component lifecycle incomplete")
    require(all(life.get(k) is False for k in ("installedProductCodeExecutedAsRoot","publisherSignatureVerified","notarized","finderInteractiveQualificationComplete","singleProductDistributionQualified","productUninstallQualified","managedEndpointQualified","productionQualificationComplete")),"Unqualified public component lifecycle scope changed")
    old,new=VERSIONS
    expected=[("core-clean-install",old,"core",True),("app-without-metadata-refused",old,"application",False),("metadata-clean-install",old,"metadata",True),("public-app-clean-install",old,"application",True),("launchservices-live-core-upgrade-refused",new,"core",False),("core-upgrade-with-public-v1",new,"core",True),("metadata-upgrade",new,"metadata",True),("public-app-upgrade",new,"application",True),("metadata-equal-reinstall",new,"metadata",True),("public-app-equal-reinstall",new,"application",True),("older-metadata-refused",old,"metadata",False),("older-public-app-refused",old,"application",False),("changed-public-info-core-refused",new,"core",False),("changed-public-info-desktop-refused",new,"application",False),("changed-registration-core-refused",new,"core",False),("changed-registration-desktop-refused",new,"metadata",False),("public-alias-core-refused",new,"core",False),("public-alias-app-refused",new,"application",False),("registration-alias-core-refused",new,"core",False),("registration-alias-metadata-refused",new,"metadata",False),("restored-public-reinstall",new,"application",True)]
    ops=life.get("operations");require(type(ops) is list and len(ops)==len(expected),"Public component operation extent differs")
    for item,(name,version,role,success) in zip(ops,expected):
        require(item.get("name")==name and item.get("version")==version and item.get("component")==role and item.get("passed") is True and type(item.get("exitCode")) is int and (item["exitCode"]==0 if success else 1<=item["exitCode"]<=255),"Public component operation result differs")
        require(item.get("nativeReceiptVerified") is success and item.get("refusedStatePreserved") is (not success) and type(item.get("elapsedMilliseconds")) is int and 0<=item["elapsedMilliseconds"]<=180000,"Public component preservation/receipt/timing differs")
        require(item.get("packageSHA256")== (core_bindings[version]["packageSHA256"] if role=="core" else public_bindings[version][role]),"Native component operation subject differs")
    choices=life.get("selections");names=["initial-active","core-upgraded-public-v1","public-upgraded","restored-active","inactive-refused"]
    require(type(choices) is list and [v.get("name") for v in choices]==names,"Public app active selection coverage differs")
    for c in choices:
        expected_build=identities[old] if c["name"]=="initial-active" else None if c["name"]=="inactive-refused" else identities[new]
        require(c.get("expectedCoreBuild")==expected_build and c.get("installationAndUserDataPreserved") is True and c.get("passed") is True and type(c.get("exitCode")) is int and (c["exitCode"]==0 if expected_build is not None else 1<=c["exitCode"]<=255) and type(c.get("elapsedMilliseconds")) is int and 0<=c["elapsedMilliseconds"]<=30000,"Public app selection/refusal differs")
    launched=life.get("launchServices",{});require(all(launched.get(k) is True for k in ("defaultNoArgumentLaunch","kernelImageAndOrdinaryOwnerVerified","dashboardHTTPVerified","privateProfileLockVerified","authenticatedSavedProfileVerified","installerRefusalWhileServingVerified","controllerRemainedRunning","cleanShutdownVerified","passed")) and type(launched.get("elapsedMilliseconds")) is int and 0<=launched["elapsedMilliseconds"]<=300000,"Actual LaunchServices controller acceptance incomplete")
    deactivated=life.get("deactivation",{});require(deactivated.get("generation")==3 and deactivated.get("state")=="inactive" and deactivated.get("operationRecordPublished") is True and deactivated.get("exitCode")==0 and type(deactivated.get("elapsedMilliseconds")) is int and 0<=deactivated["elapsedMilliseconds"]<=60000,"Public/core deactivation fence differs")
    product_life=validate_product_lifecycle(read("product-lifecycle-artifact.json"),commit,arch,core_bindings,records,public_bindings,product_bindings,identities,str(life["runID"]))
    removal_life=validate_product_removal_inspections(read("product-lifecycle-artifact.json").get("removalInspections"),{v:read(v+"-compiler-artifact.json") for v in VERSIONS},records,product_helpers)
    newest=VERSIONS[-1];newest_record=(root/("desktop-"+newest+"-DESKTOP-RECORD.json")).read_bytes()
    core_input=component_inputs(newest,arch,newest_record)[0][2]
    recovery_payload=cpio(inflate(flat_members((root/core_input).read_bytes())["Payload"],MAX_BYTES,31))
    recovery_life=validate_product_recovery(read("product-recovery-artifact.json"),commit,arch,read(newest+"-compiler-artifact.json"),product_bindings[newest],recovery_payload,str(life["runID"]))
    return {"productRemovalInspection":removal_life,"productWriteFaultRecovery":recovery_life,"productLifecycle":product_life,"lifecycleRunID":str(life["runID"]),"corePackages":cores,"desktop":outputs,"actualInstallerOperations":21,"actualCoreDeactivationOperations":1,"publicAppSelectionCases":5,"launchServicesDefaultControllerVerified":True,"productArchiveConstructionVerified":True,"singleProductLifecycleQualified":False,"finderInteractiveQualificationComplete":False,"singleProductDistributionQualified":False,"publisherSignatureVerified":False,"productionQualificationComplete":False}



def validate_product_removal_inspections(items,cores,records,helpers):
    old,new=VERSIONS
    expected=[("initial-complete",old,True,1),("serving-controller-refused",old,False,0),("older-helper-refused",old,False,3),("changed-public-info-refused",new,False,3),("changed-registration-refused",new,False,3),("public-alias-refused",new,False,3),("registration-alias-refused",new,False,3),("restored-complete",new,True,4),("unrecorded-copy-refused",new,False,4)]
    for index,kind in enumerate(("metadata","controller")):
        expected.extend([(kind+"-pending-copy-refused",new,False,4+index),(kind+"-abandoned-copy-refused",new,False,4+index),(kind+"-retained-copy-refused",new,False,5+index)])
    expected.append(("inactive-core-refused",new,False,7))
    require(type(items) is list and len(items)==len(expected),"Removal inspection case extent differs")
    result_keys={"schemaVersion","operation","state","version","manifestSHA256","payloadSHA256","desktopRecordSHA256","generation","retainedCoreCopies","retainedStateRecords","desktopRegistrations","inventorySHA256","inventoryScope","mutationPerformed","incomingPayloadsInspected","installerReceiptsInspected","productUninstallQualified","productionQualificationComplete"}
    fingerprints=[]
    for item,(name,version,success,generation) in zip(items,expected):
        require(type(item) is dict and set(item)=={"name","helperSHA256","exitCode","elapsedMilliseconds","result","installationAndPrivateDataPreserved","passed"},"Removal inspection envelope differs")
        require(item.get("name")==name and item.get("helperSHA256")==helpers[version] and type(item.get("exitCode")) is int and item["exitCode"]==(0 if success else 1) and type(item.get("elapsedMilliseconds")) is int and 0<=item["elapsedMilliseconds"]<=60000 and item.get("installationAndPrivateDataPreserved") is True and item.get("passed") is True,"Removal inspection did not bind helper/outcome/preservation")
        value=item.get("result");require(type(value) is dict and set(value)==result_keys,"Removal inspection result shape differs")
        require(type(value.get("schemaVersion")) is int and value["schemaVersion"]==1 and value.get("operation")=="inspect-product-removal" and value.get("state")==("inspected" if success else "refused") and value.get("version")==version and value.get("manifestSHA256")==cores[version]["manifestSHA256"] and value.get("payloadSHA256")==cores[version]["payloadSHA256"] and value.get("desktopRecordSHA256")==records[version],"Removal inspection compiled identity differs")
        require(all(type(value.get(k)) is int for k in ("generation","retainedCoreCopies","retainedStateRecords","desktopRegistrations")) and value["generation"]==generation,"Removal inspection generation/count type differs")
        require(value.get("inventoryScope")=="core-history-public-app-registrations" and all(value.get(k) is False for k in ("mutationPerformed","incomingPayloadsInspected","installerReceiptsInspected","productUninstallQualified","productionQualificationComplete")),"Removal inspection scope changed")
        if success:
            require(value["retainedCoreCopies"]==generation and value["desktopRegistrations"]==(1 if version==old else 2) and 1<=value["retainedStateRecords"]<=129 and type(value.get("inventorySHA256")) is str and re.fullmatch("[a-f0-9]{64}",value["inventorySHA256"]) is not None,"Completed removal inventory differs")
            fingerprints.append(value["inventorySHA256"])
        else:require(value["retainedCoreCopies"]==value["retainedStateRecords"]==value["desktopRegistrations"]==0 and value["inventorySHA256"]=="","Refused removal inventory was presented as complete")
    require(len(set(fingerprints))==2,"Distinct removal inventories reused a fingerprint")
    return {"actualPackagedHelperInspectionCommands":len(expected),"completeInventories":2,"preservingRefusals":len(expected)-2,"fixedScope":"core-history-public-app-registrations","deletionPerformed":False,"productUninstallQualified":False,"productionQualificationComplete":False}

def validate_product_lifecycle(life,commit,arch,cores,records,public,products,identities,run_id):
    require(life.get("schemaVersion")==1 and life.get("sourceCommit")==commit and life.get("target")=="darwin/"+arch and str(life.get("runID"))==run_id and life.get("lifecycleKind")=="single-product" and life.get("stage")=="deactivation-and-owned-cleanup" and life.get("failureType") is None and life.get("failureSourceLine") is None,"Single product lifecycle identity differs")
    require(life.get("corePackageSHA256")=={v:c["packageSHA256"] for v,c in cores.items()} and life.get("desktopRecordSHA256")==records and life.get("desktopPackageSHA256")==public and life.get("productPackageSHA256")==products,"Single product lifecycle subjects differ")
    require(all(life.get(k) is True for k in ("passed","actualSingleProductLifecycleVerified","actualOrderedComponentsExecuted","publicAppAndProtectedRegistrationsVerified","coreUpgradeWithPublicEntryVerified","actualUserDataAndContainerProtectionPreserved","ownedFixturesRemoved")),"Single product lifecycle incomplete")
    require(all(life.get(k) is False for k in ("installedProductCodeExecutedAsRoot","publisherSignatureVerified","notarized","finderInteractiveQualificationComplete","singleProductDistributionQualified","productUninstallQualified","managedEndpointQualified","productionQualificationComplete")),"Unqualified single product scope changed")
    old,new=VERSIONS
    expected=[("app-without-metadata-refused",old,"application",False),("product-clean-install",old,"product",True),("launchservices-live-product-upgrade-refused",new,"product",False),("product-upgrade",new,"product",True),("product-equal-reinstall",new,"product",True),("older-product-refused",old,"product",False),("changed-public-info-product-refused",new,"product",False),("changed-registration-product-refused",new,"product",False),("public-alias-product-refused",new,"product",False),("registration-alias-product-refused",new,"product",False),("restored-product-reinstall",new,"product",True),("metadata-fault-product-retry",new,"product",True),("controller-fault-product-retry",new,"product",True)]
    operations=life.get("operations");require(type(operations) is list and len(operations)==len(expected),"Single product operation extent differs")
    for item,(name,version,role,success) in zip(operations,expected):
        require(item.get("name")==name and item.get("version")==version and item.get("component")==role and item.get("passed") is True and type(item.get("exitCode")) is int and (item["exitCode"]==0 if success else 1<=item["exitCode"]<=255),"Single product operation differs")
        require(item.get("nativeReceiptVerified") is success and item.get("refusedStatePreserved") is (not success) and type(item.get("elapsedMilliseconds")) is int and 0<=item["elapsedMilliseconds"]<=180000 and item.get("packageSHA256")== (products[version] if role=="product" else public[version][role]),"Single product operation evidence differs")
    choices=life.get("selections");names=["initial-active","product-upgraded","product-reinstalled","restored-active","metadata-fault-old-active","metadata-recovery-active","controller-fault-old-active","controller-recovery-active","inactive-refused"]
    require(type(choices) is list and [c.get("name") for c in choices]==names,"Single product selection coverage differs")
    for c in choices:
        build=identities[old] if c["name"]=="initial-active" else None if c["name"]=="inactive-refused" else identities[new]
        require(c.get("expectedCoreBuild")==build and c.get("installationAndUserDataPreserved") is True and c.get("passed") is True and type(c.get("exitCode")) is int and (c["exitCode"]==0 if build is not None else 1<=c["exitCode"]<=255) and type(c.get("elapsedMilliseconds")) is int and 0<=c["elapsedMilliseconds"]<=30000,"Single product active selection/refusal differs")
    launched=life.get("launchServices",{})
    require(all(launched.get(k) is True for k in ("defaultNoArgumentLaunch","kernelImageAndOrdinaryOwnerVerified","dashboardHTTPVerified","privateProfileLockVerified","authenticatedSavedProfileVerified","installerRefusalWhileServingVerified","controllerRemainedRunning","cleanShutdownVerified","passed")) and type(launched.get("elapsedMilliseconds")) is int and 0<=launched["elapsedMilliseconds"]<=300000,"Single product LaunchServices incomplete")
    deactivated=life.get("deactivation",{})
    require(deactivated.get("generation")==7 and deactivated.get("state")=="inactive" and deactivated.get("operationRecordPublished") is True and deactivated.get("exitCode")==0 and type(deactivated.get("elapsedMilliseconds")) is int and 0<=deactivated["elapsedMilliseconds"]<=60000,"Single product deactivation fence differs")
    return {"actualSingleProductInstallerOperations":12,"actualStandaloneAppRefusals":1,"actualCoreDeactivations":1,"publicAppSelectionCases":9,"privateLaunchServicesControllerVerified":True,"actualSingleProductLifecycleVerified":True,"singleProductDistributionQualified":False,"productionQualificationComplete":False}



def validate_partial_copy_inventory(value,payload,slot,limit,kind):
    require(type(value) is dict and set(value)=={"entries","partialFiles","allKnownSourcePrefixesVerified","bytes"} and value.get("allKnownSourcePrefixesVerified") is True,"Partial-copy prefix evidence missing")
    entries=value.get("entries");require(type(entries) is list and 1<=len(entries)<=4096,"Partial-copy entry extent differs")
    paths=[r.get("path") for r in entries];require(all(type(p) is str and p in payload for p in paths) and paths==sorted(set(paths)) and "" in paths,"Partial-copy paths differ")
    partial=[];total=0
    for row in entries:
        name=row["path"];expected=payload[name]
        common={"path","mode","uid","gid","device","inode","links","mtimeNs","ctimeNs","kind"}
        require(all(type(row.get(k)) is int for k in ("uid","gid","device","inode","links","mtimeNs","ctimeNs")) and row["uid"]==row["gid"]==0 and row["device"]==slot["device"] and row["inode"]>0 and row["links"]>0,"Partial-copy object identity/owner differs")
        if not name:require(row["inode"]==slot["inode"],"Partial-copy root inode differs")
        require(all(parent in paths for parent in (str(p) for p in PurePosixPath(name).parents) if parent!="."),"Missing partial-copy parent")
        if expected["directory"]:
            require(set(row)==common and row["kind"]=="directory" and row["mode"] in ("0700","0755"),"Partial-copy directory metadata differs")
        else:
            require(set(row)==common|{"bytes","expectedBytes","sha256","complete"} and row["kind"]=="file" and row["links"]==1 and row["mode"] in ("0600",format(expected["mode"],"04o")),"Partial-copy file metadata differs")
            count=row.get("bytes");require(type(count) is int and 0<=count<=len(expected["data"]) and type(row.get("expectedBytes")) is int and row["expectedBytes"]==len(expected["data"]),"Partial-copy file extent differs")
            require(row.get("sha256")==digest(expected["data"][:count]) and row.get("complete") is (count==len(expected["data"])),"Actual partial bytes differ from authenticated source prefix")
            total+=count
            if count<len(expected["data"]):partial.append(name);require(count==limit,"Actual partial file does not match kernel limit")
    require(total<=MAX_BYTES and type(value.get("bytes")) is int and value["bytes"]==total and value.get("partialFiles")==partial and len(partial)==1,"Partial-copy aggregate differs")
    require(partial[0] in ("INSTALL-MANIFEST.json","payload-SBOM.cdx.json") if kind=="metadata" else partial[0]=="AccessWeaver.app/Contents/MacOS/accessweaver","Write-fault copy stage differs")
    return digest(json.dumps(value,sort_keys=True,separators=(",",":")).encode())


def validate_product_recovery(value,commit,arch,core,product,payload,run_id):
    require(value.get("schemaVersion")==1 and value.get("sourceCommit")==commit and value.get("target")=="darwin/"+arch and str(value.get("runID"))==run_id and value.get("version")==VERSIONS[-1] and value.get("stage")=="deactivation-and-owned-cleanup" and value.get("failureType") is None and value.get("failureSourceLine") is None,"Product recovery identity differs")
    require(value.get("corePackageSHA256")==core["packageSHA256"] and value.get("productPackageSHA256")==product and value.get("helperSHA256")==core["helperSHA256"],"Product recovery subjects differ")
    require(all(value.get(k) is True for k in ("passed","actualPackageHelperWriteFaultsVerified","explicitAbandonmentAndWholeProductRetryVerified","retainedPartialCopiesPreservedUntilOwnedCleanup","ownedFixturesRemoved")),"Product recovery incomplete")
    require(all(value.get(k) is False for k in ("installedProductCodeExecutedAsRoot","hostFilesystemPressureApplied","actualInstallerProcessTerminated","actualPowerLossTested","productUninstallQualified","wholeProductInterruptionRecoveryQualified","productionQualificationComplete")),"Unearned product recovery scope")
    cases=value.get("cases");require(type(cases) is list and len(cases)==2,"Product recovery case extent differs")
    partial_ids=[];recovered_ids=[]
    for index,(case,kind,limit) in enumerate(zip(cases,("metadata","controller"),(4096,1<<20))):
        generation=4+index
        require(case.get("name")==kind and type(case.get("limitBytes")) is int and case["limitBytes"]==limit and case.get("baseGeneration")==generation and case.get("recoveredGeneration")==generation+1 and case.get("helperSHA256")==core["helperSHA256"],"Product recovery case/generation differs")
        require(all(case.get(k) is True for k in ("oldActiveCorePreservedDuringFault","publicAppRegistrationsAndReceiptsPreservedDuringFault","privateProfileAndContainerPreserved","wholeProductRetryVerified","passed")),"Product recovery preservation missing")
        slot=case.get("partialSlot",{});require(set(slot)=={"id","device","inode","identity"} and type(slot.get("id")) is str and re.fullmatch("[a-f0-9]{32}",slot["id"]) is not None and type(slot.get("device")) is int and type(slot.get("inode")) is int and slot["inode"]>0,"Product recovery partial slot differs")
        require(slot["identity"]=={"version":VERSIONS[-1],"manifestSHA256":core["manifestSHA256"],"payloadSHA256":core["payloadSHA256"]},"Product recovery partial seal differs")
        recovered=case.get("recoveredSlotID");old=case.get("oldActiveSlotID")
        require(type(recovered) is str and re.fullmatch("[a-f0-9]{32}",recovered) is not None and type(old) is str and re.fullmatch("[a-f0-9]{32}",old) is not None and recovered not in (slot["id"],old),"Product recovery reused a retained/old slot")
        if index:require(old==recovered_ids[-1],"Product recovery active-slot sequence differs")
        partial_ids.append(slot["id"]);recovered_ids.append(recovered)
        fingerprint=validate_partial_copy_inventory(case.get("partialInventory"),payload,slot,limit,kind)
        require(all(case.get(k)==fingerprint for k in ("partialFingerprintSHA256","refusedRetryPreservedFingerprintSHA256","abandonmentPreservedFingerprintSHA256","recoveryPreservedFingerprintSHA256")),"Partial copy was changed/lost during recovery")
        operations=case.get("operations");require(type(operations) is list and [op.get("name") for op in operations]==["prepare","limited-activate","partial-retry-refused","explicit-abandon"],"Recovery helper operation order differs")
        for operation in operations:require(type(operation.get("elapsedMilliseconds")) is int and 0<=operation["elapsedMilliseconds"]<=60000,"Recovery helper timing differs")
        for operation,command,state,exit_code,published in ((operations[0],"prepare-deployment","prepared",0,True),(operations[2],"activate-deployment","refused",1,False),(operations[3],"abandon-deployment","abandoned",0,True)):
            result=operation.get("result",{})
            require(operation.get("exitCode")==exit_code and result.get("schemaVersion")==1 and result.get("operation")==command and result.get("state")==state and result.get("generation")==generation and result.get("slotID")==slot["id"] and result.get("operationRecordPublished") is published and result.get("version")==VERSIONS[-1] and result.get("manifestSHA256")==core["manifestSHA256"] and result.get("payloadSHA256")==core["payloadSHA256"],"Recovery helper result/seal differs")
            require(result.get("publisherSignatureVerified") is False and result.get("productionQualificationComplete") is False,"Recovery helper scope differs")
        fault=operations[1];code=fault.get("exitCode")
        require(type(code) is int and code in (1,-25,153) and fault.get("fileSizeSignalObserved") is (code in (-25,153)) and fault.get("appliedLimit")=={"schemaVersion":1,"euid":0,"softFileSizeBytes":limit,"hardFileSizeBytes":limit,"coreDumpLimitBytes":0,"scope":"owned-helper-process"},"Actual kernel write limit/exit differs")
        require(all(type(fault.get(k)) is str and re.fullmatch("[a-f0-9]{64}",fault[k]) is not None for k in ("stdoutSHA256","stderrSHA256")),"Fault output digest missing")
    require(len(set(partial_ids))==len(set(recovered_ids))==2 and not set(partial_ids)&set(recovered_ids) and value.get("lastHelper")==cases[-1]["operations"][-1],"Recovery slot retention/final helper differs")
    return {"actualPackageHelperWriteFaultCases":2,"actualRootHelperCommands":8,"explicitAbandonments":2,"actualWholeProductRecoveryReinstalls":2,"retainedPartialCopiesVerified":2,"wholeProductInterruptionRecoveryQualified":False,"productionQualificationComplete":False}


def limit(name):return 64<<20 if name.endswith(".pkg") else 16<<20 if name.endswith(".zip") or name==PROVENANCE_BUNDLE else 8<<20


def stage(build_root,destination,commit,ref,arch,run_id=None):
    validate_identity(commit,ref);mapping=subjects(arch);destination.mkdir(mode=0o700)
    for name,relative in mapping.items():copy_subject(build_root/relative,destination/name,limit(name))
    result=validate_contents(destination,commit,arch)
    if run_id is not None:require(result["lifecycleRunID"]==run_id,"Native desktop producer run differs")
    return {"producerValidation":result,"sourceCommit":commit,"cryptographicAuthenticationPerformed":False}


def verify(directory,commit,ref,arch,gh="gh",rejections=False,run_id=None):
    validate_identity(commit,ref);names=set(subjects(arch))
    with tempfile.TemporaryDirectory(prefix="accessweaver-desktop-verify-") as temporary:
        root=Path(temporary);present=snapshot(directory,root,len(names)+1)
        require(present==names|{PROVENANCE_BUNDLE},"Desktop input inventory differs")
        for name in present:require((root/name).stat().st_size<=limit(name),"Desktop input exceeds budget")
        for name in sorted(names):authenticate(root/name,root/PROVENANCE_BUNDLE,commit,ref,gh)
        result=validate_contents(root,commit,arch)
        if run_id is not None:require(result["lifecycleRunID"]==run_id,"Authenticated desktop native run differs")
        negative=check_rejections(root/next(n for n in sorted(names) if n.endswith(".pkg")),root/PROVENANCE_BUNDLE,commit,ref,gh) if rejections else None
        return {"schemaVersion":1,"repository":REPOSITORY,"workflow":WORKFLOW,"sourceCommit":commit,"sourceRef":ref,"target":"darwin/"+arch,"subjectsVerified":len(names),"subjects":[{"file":n,"sha256":digest((root/n).read_bytes())} for n in sorted(names)],"authenticatedBeforeParsing":True,"hostedRunnerRequired":True,"desktop":result,"rejectionChecks":negative,"localTargetExecution":False,"publisherSignatureVerified":False,"notarized":False,"productionQualificationComplete":False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("directory",type=Path);p.add_argument("--source-commit",required=True);p.add_argument("--source-ref",required=True);p.add_argument("--architecture",choices=("amd64","arm64"),required=True);p.add_argument("--run-id");p.add_argument("--gh",default="gh");p.add_argument("--check-rejections",action="store_true");p.add_argument("--stage-build-root",type=Path);a=p.parse_args()
    try:result=stage(a.stage_build_root,a.directory,a.source_commit,a.source_ref,a.architecture,a.run_id) if a.stage_build_root else verify(a.directory,a.source_commit,a.source_ref,a.architecture,a.gh,a.check_rejections,a.run_id)
    except Exception as e:raise SystemExit("Desktop provenance refused: "+type(e).__name__)
    print(json.dumps(result,indent=2))

if __name__=="__main__":main()
