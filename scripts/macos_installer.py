"""Native macOS package construction contracts; publisher/endpoint qualification is separate."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct

BUNDLE_ID="io.github.yunushan.accessweaver"
BUNDLE_NAME="AccessWeaver.app"
MAX_FILES=4096
MAX_BYTES=128<<20

def require(ok,message):
    if not ok: raise ValueError(message)

def digest(data): return hashlib.sha256(data).hexdigest()

def version_parts(value):
    require(isinstance(value,str) and len(value)<=256,"Invalid package release version")
    match=re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?",value)
    require(match is not None,"Expected canonical SemVer")
    prerelease=match[4]
    require(not prerelease or all(not part.isdigit() or part=="0" or not part.startswith("0") for part in prerelease.split(".")),"Invalid numeric prerelease")
    numbers=tuple(int(match[i]) for i in (1,2,3))
    require(numbers[0]<=9999 and numbers[1]<=99 and numbers[2]<=99,"Version exceeds Apple's bundle version fields")
    return ".".join(str(v) for v in numbers)

def macho_identity(data,arch):
    require(arch in ("amd64","arm64") and 32<=len(data)<=64<<20,"Invalid native Mach-O target/size")
    magic,cpu,subtype,kind,count,commands,flags,reserved=struct.unpack_from("<8I",data)
    require(magic==0xfeedfacf and cpu=={"amd64":0x01000007,"arm64":0x0100000c}[arch] and kind==2,"Expected the matching thin native 64-bit executable")
    require(0<count<=256 and commands<=1<<20 and 32+commands<=len(data),"Mach-O command bounds are invalid")
    offset=32;minimum=[]
    for _ in range(count):
        require(offset+8<=32+commands,"Truncated Mach-O command")
        command,size=struct.unpack_from("<II",data,offset)
        require(size>=8 and size%4==0 and offset+size<=32+commands,"Invalid Mach-O command extent")
        if command==0x24:
            require(size>=16,"Invalid minimum macOS command")
            minimum.append(struct.unpack_from("<I",data,offset+8)[0])
        elif command==0x32:
            require(size>=24,"Invalid build-version command")
            platform,version=struct.unpack_from("<II",data,offset+8)
            require(platform==1,"Expected the macOS platform")
            minimum.append(version)
        offset+=size
    require(offset==32+commands and len(minimum)==1,"Expected one minimum macOS version")
    encoded=minimum[0]
    require(encoded>>16>=10,"Unexpected minimum macOS version")
    return {"cpuType":f"0x{cpu:08x}","minimumOSVersion":f"{encoded>>16}.{(encoded>>8)&255}.{encoded&255}"}

def bundle_plist(version,minimum):
    numeric=version_parts(version)
    return {"CFBundleDevelopmentRegion":"en","CFBundleDisplayName":"AccessWeaver","CFBundleExecutable":"accessweaver",
        "CFBundleIdentifier":BUNDLE_ID,"CFBundleInfoDictionaryVersion":"6.0","CFBundleName":"AccessWeaver","CFBundlePackageType":"APPL",
        "CFBundleShortVersionString":numeric,"CFBundleVersion":numeric,"AccessWeaverReleaseVersion":version,
        "LSMinimumSystemVersion":minimum,"LSUIElement":True,"NSHighResolutionCapable":True}

def bundle_manifest(bundle):
    bundle=Path(bundle);require(bundle.is_dir() and not bundle.is_symlink(),"Expected a new real app bundle")
    entries=[];directories=[];total=0;count=0
    for root,dirs,files in os.walk(bundle,followlinks=False):
        require(len(entries)+len(dirs)+len(files)<=MAX_FILES,"App bundle exceeds entry limit")
        for name in sorted(dirs+files):
            count+=1;require(count<=MAX_FILES,"App bundle exceeds entry limit")
            path=Path(root)/name;info=path.lstat();relative=path.relative_to(bundle).as_posix()
            require(not stat.S_ISLNK(info.st_mode) and not info.st_mode & 0o6022,"Unsafe bundle type/mode")
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),"Special bundle objects are not supported")
            if stat.S_ISDIR(info.st_mode):directories.append({"path":relative,"mode":f"{stat.S_IMODE(info.st_mode):04o}"})
            if relative=="Contents/Resources/INSTALL-MANIFEST.json":
                require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=2<<20,"Invalid embedded manifest")
                continue
            if stat.S_ISREG(info.st_mode):
                require(info.st_nlink==1 and info.st_size<=64<<20,"Unexpected bundle hardlink/size")
                total+=info.st_size;require(total<=MAX_BYTES,"App bundle exceeds byte limit")
                data=path.read_bytes();require(len(data)==info.st_size,"Bundle changed during inventory")
                entries.append({"path":relative,"bytes":len(data),"sha256":digest(data),"mode":f"{stat.S_IMODE(info.st_mode):04o}"})
    require(entries and len(entries)<=MAX_FILES,"Empty or oversized app bundle")
    return {"schemaVersion":1,"bundleIdentifier":BUNDLE_ID,"files":sorted(entries,key=lambda v:v["path"]),"directories":sorted(directories,key=lambda v:v["path"])}

def verify_bundle(bundle,manifest,identity):
    require(bundle_manifest(bundle)==manifest,"App bundle differs from its sealed manifest")
    bundle=Path(bundle)
    require(stat.S_IMODE((bundle/"Contents/MacOS/accessweaver").stat().st_mode)==0o755,"App executable mode differs")
    embedded=bundle/"Contents/Resources/INSTALL-MANIFEST.json"
    require(embedded.stat().st_size<=2<<20 and json.loads(embedded.read_text(encoding="utf-8"))==manifest,"Embedded manifest differs")
    info=plistlib.loads((bundle/"Contents/Info.plist").read_bytes())
    require(info==bundle_plist(identity["version"],macho_identity((bundle/"Contents/MacOS/accessweaver").read_bytes(),identity["arch"])["minimumOSVersion"]),"Bundle metadata differs from native identity")
    require(json.loads((bundle/"Contents/Resources/BUILD-INFO.json").read_text(encoding="utf-8"))==identity,"Bundle build identity differs from payload")
    return True
