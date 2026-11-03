"""Bounded unsigned single-product contracts; never install or execute packages."""
import copy
import hashlib
import re
import struct
import uuid
import xml.etree.ElementTree as ET

from macos_installer import BUNDLE_ID,BUNDLE_NAME,MAX_BYTES,digest,require,version_parts
from macos_deployment import PACKAGE_ID
from macos_desktop import component_name,package_id
from macos_package_archive import flat_members,inflate,number,xml
from sbom import component,properties,validate

ROLES=("core","metadata","application")
PRODUCT_ID=BUNDLE_ID+".desktop.product"
PARTS={"Bom","PackageInfo","Payload","Scripts"}


def product_name(version,arch):
    version_parts(version);require(arch in ("amd64","arm64"),"Expected product architecture")
    name="accessweaver-"+version+"-darwin-"+arch+"-desktop-product-experimental.pkg";require(len(name.encode("utf-8"))<=255,"Product name exceeds filesystem limit");return name


def component_inputs(version,arch,record):
    product_name(version,arch)
    return [("core",PACKAGE_ID,"accessweaver-"+version+"-darwin-"+arch+"-deployment-experimental.pkg")]+[(role,package_id(role,record),component_name(version,arch,role)) for role in ROLES[1:]]


def distribution(version,arch,inputs):
    product_name(version,arch);require([p[0] for p in inputs]==list(ROLES),"Product component order differs")
    root=ET.Element("installer-gui-script",minSpecVersion="2")
    ET.SubElement(root,"title").text="AccessWeaver"
    ET.SubElement(root,"product",id=PRODUCT_ID,version=version)
    ET.SubElement(root,"options",customize="never",hostArchitectures="x86_64" if arch=="amd64" else "arm64",attrib={"require-scripts":"false","allow-external-scripts":"false"})
    ET.SubElement(root,"domains",enable_localSystem="true",enable_currentUserHome="false",enable_anywhere="false")
    check=ET.SubElement(root,"volume-check");allowed=ET.SubElement(check,"allowed-os-versions");ET.SubElement(allowed,"os-version",min="13.0.0")
    outline=ET.SubElement(root,"choices-outline")
    for role,identifier,name in inputs:
        ET.SubElement(outline,"line",choice=role)
        choice=ET.SubElement(root,"choice",id=role,visible="false",enabled="false",selected="true")
        ET.SubElement(choice,"pkg-ref",id=identifier)
        ET.SubElement(root,"pkg-ref",id=identifier,version=version).text=name
    return ET.tostring(root,encoding="utf-8",xml_declaration=True)


def tree(node):
    return (node.tag,tuple(sorted(node.attrib.items())),(node.text or "").strip(),tuple(tree(c) for c in node))


def bundle_versions(original,role):
    markers=original.findall("bundle-version");bundles=original.findall("bundle")
    require(len(markers)<=1 and all(not m.attrib and len(m)==0 and not (m.text or "").strip() for m in markers),"Source bundle-version marker differs")
    require(len(bundles)<=1 and (role!="metadata" or not bundles),"Source component bundle role differs")
    if not markers and not bundles:return []
    result=ET.Element("bundle-version")
    for bundle in bundles:
        require(set(bundle.attrib)=={"path","id","CFBundleShortVersionString","CFBundleVersion"} and len(bundle)==0 and not (bundle.text or "").strip(),"Source component bundle metadata differs")
        values=dict(bundle.attrib);require(values["path"] in (BUNDLE_NAME,"./"+BUNDLE_NAME) and values["id"]==BUNDLE_ID+(".desktop" if role=="application" else ""),"Source bundle identity/path differs")
        values["path"]=BUNDLE_NAME;ET.SubElement(result,"bundle",**values)
    return [result]


def validate_distribution(encoded,version,arch,inputs,members):
    root=xml(encoded);expected=xml(distribution(version,arch,inputs))
    require(root.tag==expected.tag and root.attrib==expected.attrib,"Product distribution root differs")
    require(sorted(n.tag for n in root if n.tag!="pkg-ref")==sorted(n.tag for n in expected if n.tag!="pkg-ref"),"Product distribution elements differ")
    for tag in ("title","product","options","domains","volume-check","choices-outline"):
        found=root.findall(tag);want=expected.findall(tag)
        require(len(found)==len(want)==1 and tree(found[0])==tree(want[0]),"Product distribution policy differs: "+tag)
    choices=root.findall("choice")
    require(len(choices)==3 and {c.get("id") for c in choices}==set(ROLES),"Product choices differ")
    for choice in choices:
        want=next(c for c in expected.findall("choice") if c.get("id")==choice.get("id"))
        require(tree(choice)==tree(want),"Product choice may be changed or redirected")
    refs=root.findall("pkg-ref");require(3<=len(refs)<=6 and {n.get("id") for n in refs}=={p[1] for p in inputs},"Product references differ")
    for role,identifier,name in inputs:
        group=[n for n in refs if n.get("id")==identifier];primary=[n for n in group if (n.text or "").strip()]
        require(1<=len(group)<=2 and len(primary)==1,"Product reference has ambiguous package URL")
        ref=primary[0];require(ref.get("version")==version and (ref.text or "").strip() in (name,"#"+name),"Product component URL/version differs")
        require(set(ref.attrib)<={"id","version","installKBytes","updateKBytes","auth","onConclusion"} and ref.get("auth","root")=="root" and ref.get("onConclusion","None")=="None" and ref.get("updateKBytes","0")=="0","Product component execution policy differs")
        original=xml(members[name]["PackageInfo"])
        if "installKBytes" in ref.attrib:
            number(ref.get("installKBytes"));payloads=original.findall("payload")
            require(len(payloads)==1 and ref.get("installKBytes")==payloads[0].get("installKBytes"),"Product component install size differs")
        metadata=ref
        if len(group)==2:
            metadata=next(n for n in group if n is not ref)
            require(len(ref)==0 and metadata.attrib=={"id":identifier} and not (metadata.text or "").strip(),"Product supplemental reference differs")
        require([tree(c) for c in metadata]==[tree(c) for c in bundle_versions(original,role)],"Product component bundle metadata differs")
    return True


def product_members(package,names):
    require(28<=len(package)<=64<<20 and len(names)==3 and len(set(names))==3,"Product archive budget differs")
    magic,header,version,compressed,size,algorithm=struct.unpack_from(">4sHHQQI",package)
    require((magic,header,version,algorithm)==(b"xar!",28,1,1),"Unsupported unsigned product XAR")
    require(0<compressed<=1<<20 and 0<size<=4<<20 and header+compressed+20<=len(package),"Product XAR table exceeds bounds")
    encoded=package[header:header+compressed];decoded=inflate(encoded,4<<20);require(len(decoded)==size,"Product XAR table size differs")
    root=xml(decoded);require(root.tag=="xar" and [n.tag for n in root]==["toc"],"Product XAR root/signature differs")
    toc=root[0];require(all(n.tag in ("creation-time","checksum","file") for n in toc),"Unknown product XAR metadata")
    checks=toc.findall("checksum");require(len(checks)==1,"Product table checksum missing")
    check=checks[0];require(check.get("style")=="sha1" and check.findtext("offset")=="0" and check.findtext("size")=="20","Product table checksum differs")
    heap=header+compressed;require(hashlib.sha1(encoded).digest()==package[heap:heap+20],"Product table integrity differs")
    output={};ranges=[(0,20)];total=0;seen=set()
    def read(entry,parent=""):
        nonlocal total
        name_nodes=entry.findall("name");type_nodes=entry.findall("type")
        require(len(type_nodes)==1 and (len(name_nodes)==1 or parent and type_nodes[0].text=="file" and len(name_nodes)==2 and name_nodes[0].text==name_nodes[1].text),"Ambiguous product entry")
        require(not entry.findall("link") and all(not n.attrib and len(n)==0 for n in name_nodes+type_nodes),"Product archive link metadata forbidden")
        name=name_nodes[0].text;kind=type_nodes[0].text
        require(isinstance(name,str) and re.fullmatch(r"[A-Za-z0-9._-]{1,255}",name) is not None and name not in (".",".."),"Unsafe product archive name")
        path=parent+name;require(path not in seen,"Duplicate product entry");seen.add(path)
        if kind=="directory":
            require(not parent and (name in names or name=="Resources") and not entry.findall("data"),"Unknown product directory")
            children=entry.findall("file")
            require(not children if name=="Resources" else len(children)==4,"Product component directory extent differs")
            for child in children:read(child,name+"/")
            return
        require(kind=="file" and not entry.findall("file") and (path=="Distribution" or not parent and name in names or parent[:-1] in names and name in PARTS),"Unknown product file/type")
        blocks=entry.findall("data");require(len(blocks)==1,"Product data extent differs")
        data=blocks[0];fields={"offset","length","size","encoding","archived-checksum","extracted-checksum"}
        require(set(n.tag for n in data)==fields and all(len(data.findall(n))==1 for n in fields),"Ambiguous product data metadata")
        offset=number(data.findtext("offset"));length=number(data.findtext("length"));unpacked=number(data.findtext("size"));total+=unpacked
        require(length>0 and 0<unpacked<=64<<20 and total<=MAX_BYTES and offset+length<=len(package)-heap,"Product member exceeds budget")
        require(all(offset>=end or offset+length<=start for start,end in ranges),"Overlapping product members");ranges.append((offset,offset+length))
        raw=package[heap+offset:heap+offset+length];stored=data.find("archived-checksum");extracted=data.find("extracted-checksum");encoding=data.find("encoding")
        require(stored is not None and extracted is not None and encoding is not None and stored.get("style")==extracted.get("style")=="sha1","Product member checksum style differs")
        require(hashlib.sha1(raw).hexdigest()==stored.text,"Product stored integrity differs")
        style=encoding.get("style");require(style in ("application/octet-stream","application/x-gzip"),"Product member encoding differs")
        value=raw if style=="application/octet-stream" else inflate(raw,unpacked)
        require(len(value)==unpacked and hashlib.sha1(value).hexdigest()==extracted.text,"Product extracted integrity differs");output[path]=value
    for entry in toc.findall("file"):read(entry)
    cursor=0
    for start,end in sorted(ranges):require(start==cursor,"Unaccounted product heap bytes");cursor=end
    require(heap+cursor==len(package),"Trailing product archive bytes")
    expected={"Distribution"}
    for name in names:
        expected.update({name} if name in output else {name+"/"+p for p in PARTS})
    require(set(output)==expected and set(names)<=seen,"Product component/file inventory differs")
    return output


def inspect_product(package,version,arch,inputs,packages):
    require(set(packages)=={p[2] for p in inputs},"Product source component inventory differs")
    originals={name:flat_members(raw) for name,raw in packages.items()};members=product_members(package,list(packages));actual={}
    for name,raw in packages.items():
        actual[name]=flat_members(members[name]) if name in members else {part:members[name+"/"+part] for part in PARTS}
        require(actual[name]==originals[name],"Embedded product component bytes differ: "+name)
    validate_distribution(members["Distribution"],version,arch,inputs,actual)
    return {"productSHA256":digest(package),"distributionSHA256":digest(members["Distribution"]),"componentOrder":list(ROLES),"componentInputs":[{"role":role,"identifier":identifier,"file":name,"sha256":digest(packages[name]),"members":{p:digest(v) for p,v in sorted(actual[name].items())}} for role,identifier,name in inputs],"allEmbeddedComponentMemberBytesVerified":True,"systemDomainOnly":True,"targetExecutionPerformed":False,"installationExecuted":False,"publisherSignatureVerified":False,"productionQualificationComplete":False}


def product_sbom(package,identity,inputs,packages,graphs,tool):
    require([p[0] for p in inputs]==list(ROLES) and set(graphs)==set(ROLES),"Product graph component roles differ")
    result=copy.deepcopy(graphs["core"]);result["serialNumber"]="urn:uuid:"+str(uuid.uuid5(uuid.NAMESPACE_URL,"accessweaver-product:"+digest(package)));nodes=[];edges=[];roots=[]
    for role,identifier,name in inputs:
        doc=graphs[role];validate(doc,packages[name],identity);prefix=role+":";root=doc["metadata"]["component"];roots.append(prefix+root["bom-ref"])
        for c in [root]+doc["components"]:
            c=copy.deepcopy(c);c["bom-ref"]=prefix+c["bom-ref"];nodes.append(c)
        for edge in doc["dependencies"]:edges.append({"ref":prefix+edge["ref"],"dependsOn":[prefix+r for r in edge["dependsOn"]]})
    members=product_members(package,list(packages))
    for name,value in sorted(members.items()):
        ref="product-file:"+name;c=component(ref,name,"file");c["hashes"]=[{"alg":"SHA-256","content":digest(value)}];nodes.append(c);edges.append({"ref":ref,"dependsOn":[]});roots.append(ref)
    root=copy.deepcopy(result["metadata"]["component"]);root.update({"bom-ref":"application","name":"AccessWeaver desktop product archive","hashes":[{"alg":"SHA-256","content":digest(package)}]})
    overrides=properties({"inventory-scope":"input component archives, their compiled graphs and actual product members; OS dependency closure excluded","input-components-may-be-repacked":"true"});names={p["name"] for p in overrides};root["properties"]=[p for p in root.get("properties",[]) if p["name"] not in names]+overrides
    result["metadata"]["component"]=root;result["metadata"]["tools"]={"components":[{"type":"application","name":"Apple productbuild","version":tool["osBuild"],"hashes":[{"alg":"SHA-256","content":tool["sha256"]}]}]}
    result["components"]=nodes;result["dependencies"]=edges+[{"ref":"application","dependsOn":roots}];result["compositions"]=[{"aggregate":"incomplete","assemblies":["application"]}]
    validate(result,package,identity);return result
