import hashlib
import stat
import struct
import unittest
import xml.etree.ElementTree as ET
import zlib
from macos_package_archive import cpio,flat_members,inflate,xml

class PackageArchiveContracts(unittest.TestCase):
    def entry(self,name,mode=stat.S_IFREG|0o644,data=b"value",links=1):
        encoded=name.encode()+b"\0"
        values=[(0,6),(1,6),(mode,6),(0,6),(0,6),(links,6),(0,6),(0,11),(len(encoded),6),(len(data),11)]
        return b"070707"+b"".join(format(value,"0"+str(width)+"o").encode() for value,width in values)+encoded+data
    def archive(self,contents):
        return contents+self.entry("TRAILER!!!",0,b"")+b"\0"*32
    def package(self,overlap=False):
        members={"Bom":b"bom","PackageInfo":b"<pkg-info/>","Payload":b"payload","Scripts":b"scripts"}
        root=ET.Element("xar");toc=ET.SubElement(root,"toc");checksum=ET.SubElement(toc,"checksum",style="sha1")
        ET.SubElement(checksum,"offset").text="0";ET.SubElement(checksum,"size").text="20"
        heap=b"";offset=20
        for name,contents in members.items():
            file=ET.SubElement(toc,"file");ET.SubElement(file,"name").text=name;ET.SubElement(file,"type").text="file";data=ET.SubElement(file,"data")
            raw=zlib.compress(contents)
            for key,value in [("offset",20 if overlap else offset),("length",len(raw)),("size",len(contents))]:ET.SubElement(data,key).text=str(value)
            ET.SubElement(data,"encoding",style="application/x-gzip")
            ET.SubElement(data,"archived-checksum",style="sha1").text=hashlib.sha1(raw).hexdigest()
            ET.SubElement(data,"extracted-checksum",style="sha1").text=hashlib.sha1(contents).hexdigest()
            heap+=raw;offset+=len(raw)
        decoded=ET.tostring(root);encoded=zlib.compress(decoded)
        return struct.pack(">4sHHQQI",b"xar!",28,1,len(encoded),len(decoded),1)+encoded+hashlib.sha1(encoded).digest()+heap,members
    def test_flat_package_checks_integrity_member_layout_and_bounds(self):
        package,members=self.package();self.assertEqual(flat_members(package),members)
        for invalid in [package[:20],package+b"trailing",package[:-1],self.package(True)[0],package[:-1]+bytes([package[-1]^1])]:
            with self.assertRaises((ValueError,zlib.error)):flat_members(invalid)
    def test_compression_truncation_concatenation_and_expansion_are_rejected(self):
        encoded=zlib.compress(b"x"*100)
        self.assertEqual(inflate(encoded,100),b"x"*100)
        for data,budget in [(encoded,99),(encoded[:-1],100),(encoded+encoded,200)]:
            with self.assertRaises(ValueError):inflate(data,budget)
    def test_cpio_paths_links_duplicates_types_and_trailing_data_are_rejected(self):
        valid=self.archive(self.entry(".",stat.S_IFDIR|0o755,b"")+self.entry("./Contents/file"))
        result=cpio(valid);self.assertEqual(result["Contents/file"]["data"],b"value")
        for name in ["../outside","/absolute","a/../b","a\\b","a:b","a//b"]:
            with self.assertRaises(ValueError):cpio(self.archive(self.entry(name)))
        for contents in [self.entry("link",stat.S_IFLNK|0o755),self.entry("hard",links=2),self.entry("exec",stat.S_IFREG|0o4755),self.entry("same")+self.entry("same")]:
            with self.assertRaises(ValueError):cpio(self.archive(contents))
        with self.assertRaises(ValueError):cpio(valid+b"nonzero")
        with self.assertRaises(ValueError):cpio(self.entry("no-trailer"))
    def test_xml_external_entities_utf16_and_depth_are_not_supported(self):
        for data in [b'<!DOCTYPE x [<!ENTITY entity "value">]><x>&entity;</x>',"<x/>".encode("utf-16"),b"<x>"*33+b"</x>"*33]:
            with self.assertRaises(ValueError):xml(data)

if __name__=="__main__":unittest.main()
