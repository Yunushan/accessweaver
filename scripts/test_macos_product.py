import copy
import hashlib
import json
import struct
import unittest
import xml.etree.ElementTree as ET
import zlib

from macos_product import component_inputs,distribution,inspect_product,product_members,product_sbom,tree
from macos_installer import digest
from macos_package_archive import flat_members
from test_macos_deployment import flat_package
import test_macos_launcher as launcher_fixture


def product_archive(members,nested=False,change=None):
    raw=flat_package(members)
    header=struct.unpack_from(">4sHHQQI",raw);start=header[1];end=start+header[3]
    root=ET.fromstring(zlib.decompress(raw[start:end]));toc=root[0]
    if nested:
        dirs={}
        for entry in list(toc.findall("file")):
            name=entry.findtext("name")
            if "/" in name:
                parent,leaf=name.split("/",1);toc.remove(entry)
                if parent not in dirs:
                    directory=ET.SubElement(toc,"file");ET.SubElement(directory,"name").text=parent;ET.SubElement(directory,"type").text="directory";dirs[parent]=directory
                entry.find("name").text=leaf;dirs[parent].append(entry)
    if change:change(toc)
    decoded=ET.tostring(root);encoded=zlib.compress(decoded)
    return struct.pack(">4sHHQQI",b"xar!",28,1,len(encoded),len(decoded),1)+encoded+hashlib.sha1(encoded).digest()+raw[end+20:]


class ProductContracts(unittest.TestCase):
    def fixture(self,arch="amd64",nested=False):
        version="0.1.0-alpha";inputs=component_inputs(version,arch,b"protected fixture registration")
        def info(identifier):
            root=ET.Element("pkg-info",identifier=identifier,version=version);ET.SubElement(root,"payload",installKBytes="123");return ET.tostring(root)
        packages={name:flat_package({"Bom":b"bom-"+role.encode(),"PackageInfo":info(identifier),"Payload":b"payload-"+role.encode(),"Scripts":b"phases-"+role.encode()}) for role,identifier,name in inputs}
        members={"Distribution":distribution(version,arch,inputs)}
        for name,value in packages.items():
            if nested:members.update({name+"/"+p:b for p,b in flat_members(value).items()})
            else:members[name]=value
        return version,arch,inputs,packages,members,product_archive(members,nested)
    def test_actual_members_bind_all_three_inputs_for_both_native_architectures(self):
        for arch in ("amd64","arm64"):
            for nested in (False,True):
                version,arch,inputs,packages,members,raw=self.fixture(arch,nested)
                result=inspect_product(raw,version,arch,inputs,packages)
                self.assertEqual(result["componentOrder"],["core","metadata","application"])
                self.assertTrue(result["allEmbeddedComponentMemberBytesVerified"])
                self.assertEqual(product_members(raw,list(packages)),members)
                self.assertFalse(result["installationExecuted"])
    def test_distribution_rejects_redirects_mutable_choices_and_extra_execution(self):
        version,arch,inputs,packages,members,_=self.fixture()
        for kind in ("remote","order","home","anywhere","architecture","selected","enabled","visible","identifier","version","duplicate-ref","script","external","extra-option","minimum-os","custom-location"):
            with self.subTest(kind=kind):
                doc=ET.fromstring(members["Distribution"])
                if kind=="remote":doc.findall("pkg-ref")[0].text="https://example.invalid/core.pkg"
                elif kind=="order":doc.find("choices-outline")[0].set("choice","application")
                elif kind=="home":doc.find("domains").set("enable_currentUserHome","true")
                elif kind=="anywhere":doc.find("domains").set("enable_anywhere","true")
                elif kind=="architecture":doc.find("options").set("hostArchitectures","arm64")
                elif kind in ("selected","enabled","visible"):doc.find("choice").set(kind,"false" if kind=="selected" else "true")
                elif kind=="identifier":doc.findall("pkg-ref")[0].set("id","other")
                elif kind=="version":doc.findall("pkg-ref")[0].set("version","0.0.9")
                elif kind=="duplicate-ref":doc.append(copy.deepcopy(doc.findall("pkg-ref")[0]))
                elif kind=="script":ET.SubElement(doc,"script").text="system.run('unexpected')"
                elif kind=="external":doc.find("options").set("allow-external-scripts","true")
                elif kind=="extra-option":doc.find("options").set("unexpected","true")
                elif kind=="minimum-os":doc.find("./volume-check/allowed-os-versions/os-version").set("min","1.0")
                elif kind=="custom-location":doc.find("choice").set("customLocation","/tmp")
                changed=dict(members,Distribution=ET.tostring(doc))
                with self.assertRaises(ValueError):inspect_product(product_archive(changed),version,arch,inputs,packages)
    def test_native_repeated_nested_names_must_be_identical_and_bounded(self):
        version,arch,inputs,packages,members,_=self.fixture(nested=True)
        def repeat(toc):
            for directory in toc.findall("file"):
                for child in directory.findall("file"):child.append(copy.deepcopy(child.find("name")))
        native=product_archive(members,True,repeat)
        self.assertTrue(inspect_product(native,version,arch,inputs,packages)["allEmbeddedComponentMemberBytesVerified"])
        for kind in ("conflicting","third","attribute","root","type"):
            def invalid(toc):
                repeat(toc);directory=next(d for d in toc.findall("file") if d.findall("file"));child=directory.findall("file")[0]
                if kind=="conflicting":child.findall("name")[-1].text="Payload" if child.findtext("name")!="Payload" else "Bom"
                elif kind=="third":child.append(copy.deepcopy(child.find("name")))
                elif kind=="attribute":child.findall("name")[-1].set("unexpected","true")
                elif kind=="root":directory.append(copy.deepcopy(directory.find("name")))
                elif kind=="type":child.append(copy.deepcopy(child.find("type")))
            with self.subTest(kind=kind),self.assertRaises(ValueError):inspect_product(product_archive(members,True,invalid),version,arch,inputs,packages)
    def test_native_supplemental_references_bind_source_bundle_and_size_metadata(self):
        version,arch,inputs,packages,_,_=self.fixture();doc=ET.fromstring(distribution(version,arch,inputs))
        for role,identifier,name in inputs:
            parts=flat_members(packages[name]);info=ET.Element("pkg-info",identifier=identifier,version=version)
            ET.SubElement(info,"payload",installKBytes="123")
            supplemental=ET.SubElement(doc,"pkg-ref",id=identifier);bundles=ET.SubElement(supplemental,"bundle-version")
            if role!="metadata":
                values={"path":"./AccessWeaver.app","id":"io.github.yunushan.accessweaver"+(".desktop" if role=="application" else ""),"CFBundleShortVersionString":"0.1.0","CFBundleVersion":"0.1.0"}
                ET.SubElement(info,"bundle",**values);ET.SubElement(bundles,"bundle",**dict(values,path="AccessWeaver.app"))
            ET.SubElement(info,"bundle-version");parts["PackageInfo"]=ET.tostring(info);packages[name]=flat_package(parts)
            ref=next(n for n in doc.findall("pkg-ref") if n.get("id")==identifier and n.get("version"));ref.text="#"+name;ref.set("installKBytes","123");ref.set("updateKBytes","0")
        def package(dist):
            members={"Distribution":ET.tostring(dist)}
            for name,raw in packages.items():members.update({name+"/"+p:v for p,v in flat_members(raw).items()})
            return product_archive(members,True)
        self.assertTrue(inspect_product(package(doc),version,arch,inputs,packages)["systemDomainOnly"])
        for kind in ("second-url","duplicate-metadata","bundle-path","bundle-version","extra-attribute","install-size","update-size"):
            changed=copy.deepcopy(doc);supplement=next(n for n in changed.findall("pkg-ref") if n.find("bundle-version/bundle") is not None);primary=next(n for n in changed.findall("pkg-ref") if n.get("version"))
            if kind=="second-url":supplement.text="other.pkg"
            elif kind=="duplicate-metadata":changed.append(copy.deepcopy(supplement))
            elif kind=="bundle-path":supplement.find("bundle-version/bundle").set("path","Other.app")
            elif kind=="bundle-version":supplement.find("bundle-version/bundle").set("CFBundleVersion","9.9.9")
            elif kind=="extra-attribute":supplement.set("active","true")
            elif kind=="install-size":primary.set("installKBytes","124")
            elif kind=="update-size":primary.set("updateKBytes","1")
            with self.subTest(kind=kind),self.assertRaises(ValueError):inspect_product(package(changed),version,arch,inputs,packages)
    def test_changed_component_bytes_fail_even_with_valid_rebuilt_xar_checksums(self):
        for nested in (False,True):
            version,arch,inputs,packages,members,_=self.fixture(nested=nested);name=inputs[1][2]
            changed=dict(members)
            if nested:changed[name+"/Payload"]+=b"changed"
            else:
                parts=flat_members(changed[name]);parts["Payload"]+=b"changed";changed[name]=flat_package(parts)
            with self.assertRaisesRegex(ValueError,"component bytes differ"):inspect_product(product_archive(changed,nested),version,arch,inputs,packages)
    def test_unknown_duplicate_linked_trailing_or_corrupt_entries_fail(self):
        version,arch,inputs,packages,members,raw=self.fixture()
        bad=dict(members);bad["extra"]=b"unaccounted"
        with self.assertRaises(ValueError):inspect_product(product_archive(bad),version,arch,inputs,packages)
        for change in (lambda toc:ET.SubElement(toc.findall("file")[0],"link"),lambda toc:toc.append(copy.deepcopy(toc.findall("file")[0])),lambda toc:toc.findall("file")[0].find("type").__setattr__("text","symlink"),lambda toc:toc.findall("file")[0].find("name").__setattr__("text","../Distribution")):
            with self.assertRaises(ValueError):inspect_product(product_archive(members,change=change),version,arch,inputs,packages)
        for value in (raw+b"extra",raw[:-1],b"bad"+raw[3:]):
            with self.assertRaises(ValueError):inspect_product(value,version,arch,inputs,packages)
    def test_bundle_metadata_and_local_component_urls_remain_bound(self):
        version,arch,inputs,packages,members,_=self.fixture()
        doc=ET.fromstring(members["Distribution"])
        for ref in doc.findall("pkg-ref"):ref.text="#"+ref.text;ref.set("installKBytes","123")
        members["Distribution"]=ET.tostring(doc)
        self.assertTrue(inspect_product(product_archive(members),version,arch,inputs,packages)["systemDomainOnly"])
        ET.SubElement(doc.findall("pkg-ref")[0],"bundle-version")
        members["Distribution"]=ET.tostring(doc)
        with self.assertRaisesRegex(ValueError,"bundle metadata"):inspect_product(product_archive(members),version,arch,inputs,packages)
    def test_product_graph_preserves_compiled_inputs_and_actual_member_hashes(self):
        version,arch,inputs,packages,members,raw=self.fixture(nested=True)
        identity,files=launcher_fixture.LauncherArchiveContracts().fixture(arch);graph=json.loads(files["SBOM.cdx.json"])
        graph["metadata"]["component"]["properties"].append({"name":"accessweaver:inventory-scope","value":"compiled source graph"})
        graphs={role:copy.deepcopy(graph) for role,_,_ in inputs}
        for role,_,name in inputs:graphs[role]["metadata"]["component"]["hashes"]=[{"alg":"SHA-256","content":digest(packages[name])}]
        before=copy.deepcopy(graphs)
        result=product_sbom(raw,identity,inputs,packages,graphs,{"sha256":"a"*64,"osBuild":"fixture"})
        self.assertEqual(graphs,before)
        self.assertTrue(result["serialNumber"].startswith("urn:uuid:"))
        self.assertNotEqual(result["serialNumber"],graph.get("serialNumber"))
        self.assertEqual({c["name"] for c in result["components"] if c["bom-ref"].startswith("product-file:")},set(members))
        self.assertEqual(sum(p["name"]=="accessweaver:inventory-scope" for p in result["metadata"]["component"]["properties"]),1)
        for role in graphs:
            root=next(c for c in result["components"] if c["bom-ref"]==role+":application")
            self.assertIn({"name":"accessweaver:inventory-scope","value":"compiled source graph"},root["properties"])
        self.assertTrue(all(c["aggregate"]=="incomplete" for c in result["compositions"]))


if __name__=="__main__":unittest.main()
