import copy
import json
import unittest

from verify_macos_desktop_provenance import validate_product_lifecycle,VERSIONS
from macos_product import product_installer_observation


class ProductInstallerDiagnostics(unittest.TestCase):
    def test_observed_phases_and_fixed_refusal_are_ordered_without_private_log_text(self):
        raw=(b"PackageKit: Executing script \"./preinstall\" in /private/tmp/secret/path\n"
             b"package_script_service: ./preinstall: desktop package refused: install matching protected desktop metadata before the application component\n"
             b"PackageKit: Executing script './postinstall' in /private/tmp/secret/path\n")
        result=product_installer_observation(b"",raw)
        events=result["streams"][1]["events"]
        self.assertEqual([e["kind"] for e in events],["script-phase","helper-refusal","script-phase"])
        self.assertEqual([e["phase"] for e in events if e["kind"]=="script-phase"],["preinstall","postinstall"])
        self.assertEqual(events[1]["reason"],"install matching protected desktop metadata before the application component")
        self.assertNotIn("secret",json.dumps(result));self.assertFalse(result["rawLogRetained"])
    def test_unrecognized_errors_and_unrelated_output_are_only_hashed(self):
        raw=b"desktop package refused: open /Users/private/profile: denied\nsecret-token\n"
        result=product_installer_observation(raw,b"")
        event=result["streams"][0]["events"][0]
        self.assertEqual(event["helper"],"desktop");self.assertNotIn("reason",event)
        for private in ("profile","secret-token","/Users/"):self.assertNotIn(private,json.dumps(result))
        self.assertEqual(result["streams"][0]["bytes"],len(raw))
    def test_large_output_and_excessive_events_refuse(self):
        for stdout,stderr in ((b"x"*((4<<20)+1),b""),(b"",b"desktop package refused: no such file or directory\n"*65)):
            with self.assertRaises(ValueError):product_installer_observation(stdout,stderr)


class SingleProductLifecycleContracts(unittest.TestCase):
    def fixture(self):
        old,new=VERSIONS;commit="a"*40;arch="amd64";run="7"
        cores={old:{"packageSHA256":"1"*64},new:{"packageSHA256":"2"*64}};records={old:"3"*64,new:"4"*64}
        public={old:{"metadata":"5"*64,"application":"6"*64},new:{"metadata":"7"*64,"application":"8"*64}};products={old:"9"*64,new:"b"*64};identities={v:{"version":v,"commit":commit,"arch":arch} for v in VERSIONS}
        events=[("app-without-metadata-refused",old,"application",False),("product-clean-install",old,"product",True),("launchservices-live-product-upgrade-refused",new,"product",False),("product-upgrade",new,"product",True),("product-equal-reinstall",new,"product",True),("older-product-refused",old,"product",False),("changed-public-info-product-refused",new,"product",False),("changed-registration-product-refused",new,"product",False),("public-alias-product-refused",new,"product",False),("registration-alias-product-refused",new,"product",False),("restored-product-reinstall",new,"product",True),("metadata-fault-product-retry",new,"product",True),("controller-fault-product-retry",new,"product",True)]
        life={"schemaVersion":1,"sourceCommit":commit,"target":"darwin/"+arch,"runID":run,"lifecycleKind":"single-product","stage":"deactivation-and-owned-cleanup","failureType":None,"failureSourceLine":None,"corePackageSHA256":{v:c["packageSHA256"] for v,c in cores.items()},"desktopRecordSHA256":records,"desktopPackageSHA256":public,"productPackageSHA256":products}
        for key in ("passed","actualSingleProductLifecycleVerified","actualOrderedComponentsExecuted","publicAppAndProtectedRegistrationsVerified","coreUpgradeWithPublicEntryVerified","actualUserDataAndContainerProtectionPreserved","ownedFixturesRemoved"):life[key]=True
        for key in ("installedProductCodeExecutedAsRoot","publisherSignatureVerified","notarized","finderInteractiveQualificationComplete","singleProductDistributionQualified","productUninstallQualified","managedEndpointQualified","productionQualificationComplete"):life[key]=False
        life["operations"]=[{"name":name,"version":v,"component":role,"passed":True,"exitCode":0 if success else 1,"nativeReceiptVerified":success,"refusedStatePreserved":not success,"elapsedMilliseconds":1,"packageSHA256":products[v] if role=="product" else public[v][role]} for name,v,role,success in events]
        names=["initial-active","product-upgraded","product-reinstalled","restored-active","metadata-fault-old-active","metadata-recovery-active","controller-fault-old-active","controller-recovery-active","inactive-refused"]
        life["selections"]=[{"name":n,"expectedCoreBuild":identities[old] if n=="initial-active" else None if n=="inactive-refused" else identities[new],"installationAndUserDataPreserved":True,"passed":True,"exitCode":1 if n=="inactive-refused" else 0,"elapsedMilliseconds":1} for n in names]
        life["launchServices"]={k:True for k in ("defaultNoArgumentLaunch","kernelImageAndOrdinaryOwnerVerified","dashboardHTTPVerified","privateProfileLockVerified","authenticatedSavedProfileVerified","installerRefusalWhileServingVerified","controllerRemainedRunning","cleanShutdownVerified","passed")};life["launchServices"]["elapsedMilliseconds"]=1
        life["deactivation"]={"generation":7,"state":"inactive","operationRecordPublished":True,"exitCode":0,"elapsedMilliseconds":1}
        return life,(commit,arch,cores,records,public,products,identities,run)
    def test_complete_actual_product_operations_and_controller_have_narrow_scope(self):
        life,args=self.fixture();result=validate_product_lifecycle(life,*args)
        self.assertEqual(result["actualSingleProductInstallerOperations"],12);self.assertEqual(result["actualStandaloneAppRefusals"],1)
        self.assertTrue(result["actualSingleProductLifecycleVerified"]);self.assertFalse(result["productionQualificationComplete"])
    def test_skipped_reordered_unbound_or_unpreserved_operations_fail(self):
        for kind in ("missing","reordered","wrong-package","wrong-record","false-refusal","wrong-receipt","changed-preservation","wrong-source","wrong-run","wrong-target","component-report"):
            life,args=self.fixture();life=copy.deepcopy(life)
            if kind=="missing":life["operations"].pop()
            elif kind=="reordered":life["operations"][0],life["operations"][1]=life["operations"][1],life["operations"][0]
            elif kind=="wrong-package":life["operations"][1]["packageSHA256"]="c"*64
            elif kind=="wrong-record":life["desktopRecordSHA256"][VERSIONS[0]]="c"*64
            elif kind=="false-refusal":life["operations"][2]["exitCode"]=0
            elif kind=="wrong-receipt":life["operations"][3]["nativeReceiptVerified"]=False
            elif kind=="changed-preservation":life["operations"][5]["refusedStatePreserved"]=False
            elif kind=="wrong-source":life["sourceCommit"]="c"*40
            elif kind=="wrong-run":life["runID"]="8"
            elif kind=="wrong-target":life["target"]="darwin/arm64"
            elif kind=="component-report":life["lifecycleKind"]="components"
            with self.subTest(kind=kind),self.assertRaises(ValueError):validate_product_lifecycle(life,*args)
    def test_private_controller_ownership_cleanup_fence_and_scope_cannot_be_waived(self):
        for kind in ("privateProfileLockVerified","authenticatedSavedProfileVerified","kernelImageAndOrdinaryOwnerVerified","installerRefusalWhileServingVerified","controllerRemainedRunning","cleanShutdownVerified","cleanup","deactivation","old-core-selection","publisher","production"):
            life,args=self.fixture();life=copy.deepcopy(life)
            if kind in life["launchServices"]:life["launchServices"][kind]=False
            elif kind=="cleanup":life["ownedFixturesRemoved"]=False
            elif kind=="deactivation":life["deactivation"]["generation"]=3
            elif kind=="old-core-selection":life["selections"][1]["expectedCoreBuild"]=args[6][VERSIONS[0]]
            elif kind=="publisher":life["publisherSignatureVerified"]=True
            elif kind=="production":life["productionQualificationComplete"]=True
            with self.subTest(kind=kind),self.assertRaises(ValueError):validate_product_lifecycle(life,*args)


if __name__=="__main__":unittest.main()
