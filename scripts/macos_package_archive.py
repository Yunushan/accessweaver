"""Bounded, in-memory inspection of the experimental unsigned flat-package format.

No archive paths are written and no package scripts/target executables are run.
Outer artifact authentication is separate from legacy XAR integrity checks.
"""
import hashlib
import json
from pathlib import PurePosixPath
import plistlib
import re
import stat
import struct
import xml.etree.ElementTree as ET
import zlib
from macos_installer import BUNDLE_ID,BUNDLE_NAME,MAX_BYTES,MAX_FILES,bundle_plist,digest,macho_identity,require

def inflate(data,limit,wbits=15):
    require(0<limit<=MAX_BYTES,"Invalid decompression budget")
    decoder=zlib.decompressobj(wbits);result=decoder.decompress(data,limit+1)
    require(len(result)<=limit and not decoder.unconsumed_tail and decoder.eof and not decoder.unused_data,"Truncated, concatenated or oversized compressed data")
    return result

def xml(data):
    require(len(data)<=4<<20 and b"\0" not in data and b"<!DOCTYPE" not in data.upper() and b"<!ENTITY" not in data.upper(),"Unsupported XML declaration/budget")
    root=ET.fromstring(data.decode("utf-8"));pending=[(root,1)];count=0
    while pending:
        node,depth=pending.pop();count+=1
        require(depth<=32 and count<=4096,"XML structure exceeds limits")
        pending.extend((child,depth+1) for child in node)
    return root

def number(value):
    require(isinstance(value,str) and re.fullmatch(r"[0-9]{1,18}",value) is not None,"Invalid archive integer")
    return int(value)

def flat_members(package):
    require(28<=len(package)<=64<<20,"Package size exceeds inspection budget")
    magic,header,version,compressed,size,algorithm=struct.unpack_from(">4sHHQQI",package)
    require(magic==b"xar!" and header==28 and version==1 and algorithm==1,"Unsupported unsigned XAR header")
    require(0<compressed<=1<<20 and 0<size<=4<<20 and header+compressed+20<=len(package),"Invalid XAR table bounds")
    encoded=package[header:header+compressed];toc_bytes=inflate(encoded,4<<20);require(len(toc_bytes)==size,"XAR table size differs")
    root=xml(toc_bytes);require(root.tag=="xar" and [n.tag for n in root]==["toc"],"Unexpected XAR layout/signature")
    toc=root[0];require(all(n.tag in ("creation-time","checksum","file") for n in toc),"Unexpected XAR member")
    checksum=toc.findall("checksum");require(len(checksum)==1,"Missing XAR table checksum")
    checksum=checksum[0];require(checksum.get("style")=="sha1" and checksum.findtext("offset")=="0" and checksum.findtext("size")=="20","Unsupported XAR integrity checksum")
    heap=header+compressed;require(hashlib.sha1(encoded).digest()==package[heap:heap+20],"XAR table integrity differs")
    files=toc.findall("file");require(len(files)==4,"Expected one flat component package")
    output={};ranges=[(0,20)];total=0
    for entry in files:
        name=entry.findtext("name");require(name in ("Bom","PackageInfo","Scripts","Payload") and name not in output and entry.findtext("type")=="file" and not entry.findall("file"),"Unexpected XAR member type/name")
        blocks=entry.findall("data");require(len(blocks)==1,"Unexpected XAR data layout")
        data=blocks[0];offset=number(data.findtext("offset"));length=number(data.findtext("length"));unpacked=number(data.findtext("size"))
        total+=unpacked;require(total<=MAX_BYTES,"XAR aggregate expansion exceeds budget")
        require(length>0 and unpacked>0 and unpacked<=MAX_BYTES and offset+length<=len(package)-heap,"XAR member exceeds bounds")
        require(all(offset>=end or offset+length<=start for start,end in ranges),"Overlapping XAR members")
        ranges.append((offset,offset+length));raw=package[heap+offset:heap+offset+length]
        stored=data.find("archived-checksum");extracted=data.find("extracted-checksum");encoding=data.find("encoding")
        require(stored is not None and extracted is not None and encoding is not None and stored.get("style")==extracted.get("style")=="sha1","Unsupported member integrity checks")
        require(hashlib.sha1(raw).hexdigest()==stored.text,"Stored XAR member integrity differs")
        style=encoding.get("style")
        require(style in ("application/octet-stream","application/x-gzip"),"Unsupported XAR member encoding")
        contents=raw if style=="application/octet-stream" else inflate(raw,unpacked)
        require(len(contents)==unpacked and hashlib.sha1(contents).hexdigest()==extracted.text,"Extracted XAR member integrity differs")
        output[name]=contents
    cursor=0
    for start,end in sorted(ranges):require(start==cursor,"Unaccounted XAR heap data");cursor=end
    require(heap+cursor==len(package),"Trailing XAR data")
    return output

def cpio(data):
    require(len(data)<=MAX_BYTES,"CPIO exceeds byte limit")
    result={};offset=0
    while True:
        require(offset+76<=len(data) and len(result)<=MAX_FILES,"Truncated or oversized CPIO inventory")
        header=data[offset:offset+76];require(header[:6]==b"070707","Unsupported CPIO format")
        fields=[header[a:b] for a,b in [(6,12),(12,18),(18,24),(24,30),(30,36),(36,42),(42,48),(48,59),(59,65),(65,76)]]
        require(all(re.fullmatch(b"[0-7]+",value) for value in fields),"Invalid CPIO integer")
        dev,ino,mode,uid,gid,links,rdev,mtime,namesize,size=(int(value,8) for value in fields)
        require(1<=namesize<=4096 and size<=64<<20 and offset+76+namesize+size<=len(data),"CPIO entry exceeds bounds")
        encoded=data[offset+76:offset+76+namesize];require(encoded[-1:]==b"\0" and b"\0" not in encoded[:-1],"Invalid CPIO name terminator")
        name=encoded[:-1].decode("utf-8");contents=data[offset+76+namesize:offset+76+namesize+size];offset+=76+namesize+size
        if name=="TRAILER!!!":
            require(size==0 and not any(data[offset:]),"Unexpected data after CPIO trailer")
            return result
        if name==".":name=""
        elif name.startswith("./"):name=name[2:]
        require(not name.startswith("/") and "\\" not in name and ":" not in name and all(ord(c)>=32 and ord(c)!=127 for c in name),"Unsafe CPIO path")
        require(name=="" or str(PurePosixPath(name))==name and all(part not in (".","..") for part in PurePosixPath(name).parts) and len(PurePosixPath(name).parts)<=32,"Noncanonical CPIO path")
        require(name not in result and (stat.S_ISREG(mode) and links==1 or stat.S_ISDIR(mode) and size==0),"Unsupported CPIO object/link or duplicate")
        require(not mode&0o6022,"Unsafe CPIO mutation/set-ID mode")
        result[name]={"mode":stat.S_IMODE(mode),"uid":uid,"gid":gid,"directory":stat.S_ISDIR(mode),"data":contents}

def inspect(package,manifest,identity):
    members=flat_members(package);entries=cpio(inflate(members["Payload"],MAX_BYTES,31));scripts=cpio(inflate(members["Scripts"],1<<20,31))
    prefix="Applications/"+BUNDLE_NAME
    directories={"":0o755,"Applications":0o755,prefix:0o755}
    directories.update({prefix+"/"+v["path"]:int(v["mode"],8) for v in manifest["directories"]})
    files={prefix+"/"+v["path"]:v for v in manifest["files"]}
    embedded=prefix+"/Contents/Resources/INSTALL-MANIFEST.json"
    require(set(entries)==set(directories)|set(files)|{embedded},"Package contains missing or unexpected paths")
    for name,entry in entries.items():
        require(entry["uid"]==0 and entry["gid"]==0,"Payload is not root:wheel owned")
        if name in directories:require(entry["directory"] and entry["mode"]==directories[name],"Package directory mode/type differs")
        else:
            require(not entry["directory"],"Expected a package file")
            if name==embedded:
                require(entry["mode"]==0o644 and len(entry["data"])<=2<<20 and json.loads(entry["data"])==manifest,"Embedded package manifest differs")
            else:
                record=files[name]
                require(len(entry["data"])==record["bytes"] and digest(entry["data"])==record["sha256"] and entry["mode"]==int(record["mode"],8),"Package file content/mode differs")
    core=entries[prefix+"/Contents/MacOS/accessweaver"]["data"]
    native=macho_identity(core,identity["arch"])
    plist=entries[prefix+"/Contents/Info.plist"]["data"]
    require(plistlib.loads(plist)==bundle_plist(identity["version"],native["minimumOSVersion"]),"Package plist differs from native identity")
    require(json.loads(entries[prefix+"/Contents/Resources/BUILD-INFO.json"]["data"])==identity,"Package build identity differs")
    require(set(scripts)=={"","preinstall"} and scripts[""]["directory"] and not scripts["preinstall"]["directory"] and scripts["preinstall"]["mode"]==0o755,"Unexpected package scripts")
    info=xml(members["PackageInfo"])
    require(info.tag=="pkg-info" and info.get("identifier")==BUNDLE_ID and info.get("version")==identity["version"] and info.get("install-location")=="/" and info.get("auth")=="root" and info.get("relocatable")=="false","Package installation metadata differs")
    require(info.find("relocate") is not None and len(info.find("relocate"))==0,"Package relocation must be disabled")
    require([v.get("id") for v in info.findall("./strict-identifier/bundle")]==[BUNDLE_ID],"Strict package identifier missing")
    require([v.get("file") for v in info.findall("./scripts/preinstall")]==["./preinstall"] and len(info.findall("./scripts/*"))==1,"Unexpected installation scripts")
    return {"packageSHA256":digest(package),"payloadSHA256":digest(core),"bundleInfoSHA256":digest(plist),"bundleManifestSHA256":digest(entries[embedded]["data"]),"preinstallSHA256":digest(scripts["preinstall"]["data"]),"macho":native,"payloadFiles":sum(not v["directory"] for v in entries.values()),"payloadDirectories":sum(v["directory"] for v in entries.values()),"allPayloadPathsModesOwnershipAndHashesVerified":True,"xarAndCpioIntegrityVerified":True,"localTargetExecution":False,"publisherSignatureVerified":False,"productionQualificationComplete":False}
