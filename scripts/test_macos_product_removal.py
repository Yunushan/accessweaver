import copy
import unittest

from verify_macos_desktop_provenance import VERSIONS,validate_product_removal_inspections


class ProductRemovalInspectionContracts(unittest.TestCase):
    def fixture(self):
        old,new=VERSIONS
        cores={old:{"manifestSHA256":"1"*64,"payloadSHA256":"2"*64},new:{"manifestSHA256":"3"*64,"payloadSHA256":"4"*64}}
        records={old:"5"*64,new:"6"*64};helpers={old:"7"*64,new:"8"*64}
        events=[("initial-complete",old,True,1),("serving-controller-refused",old,False,0),("older-helper-refused",old,False,3),("changed-public-info-refused",new,False,3),("changed-registration-refused",new,False,3),("public-alias-refused",new,False,3),("registration-alias-refused",new,False,3),("restored-complete",new,True,4),("changed-incoming-payload-refused",new,False,4),("changed-receipt-metadata-refused",new,False,4),("incoming-alias-refused",new,False,4),("receipt-file-alias-refused",new,False,4),("unrecorded-receipt-refused",new,False,4),("ownership-restored-complete",new,True,4),("unrecorded-copy-refused",new,False,4),("metadata-pending-copy-refused",new,False,4),("metadata-abandoned-copy-refused",new,False,4),("metadata-retained-copy-refused",new,False,5),("controller-pending-copy-refused",new,False,5),("controller-abandoned-copy-refused",new,False,5),("controller-retained-copy-refused",new,False,6),("inactive-core-refused",new,False,7)]
        items=[]
        for name,version,success,generation in events:
            result={"schemaVersion":2,"operation":"inspect-product-removal","state":"inspected" if success else "refused","version":version,"manifestSHA256":cores[version]["manifestSHA256"],"payloadSHA256":cores[version]["payloadSHA256"],"desktopRecordSHA256":records[version],"generation":generation,"retainedCoreCopies":generation if success else 0,"retainedStateRecords":generation*2+1 if success else 0,"desktopRegistrations":(1 if version==old else 2) if success else 0,"incomingPayloadCount":(1 if version==old else 2) if success else 0,"installerReceiptCount":(3 if version==old else 4) if success else 0,"receiptFileCount":(6 if version==old else 8) if success else 0,"installerReceiptPathsVerified":success,"inventorySHA256":("9"*64 if version==old else "b"*64 if name=="ownership-restored-complete" else "a"*64) if success else "","inventoryScope":"core-history-public-app-registrations-incoming-receipts"}
            for key in ("mutationPerformed","productUninstallQualified","productionQualificationComplete"):result[key]=False
            result["incomingPayloadsInspected"]=result["installerReceiptsInspected"]=success
            items.append({"name":name,"helperSHA256":helpers[version],"exitCode":0 if success else 1,"elapsedMilliseconds":1,"result":result,"installationAndPrivateDataPreserved":True,"passed":True})
        return items,(cores,records,helpers)

    def test_complete_and_refused_actual_inspections_keep_narrow_scope(self):
        items,args=self.fixture();summary=validate_product_removal_inspections(items,*args)
        self.assertEqual(summary["actualPackagedHelperInspectionCommands"],22)
        self.assertEqual(summary["completeInventories"],3);self.assertEqual(summary["preservingRefusals"],19)
        self.assertFalse(summary["deletionPerformed"]);self.assertFalse(summary["productUninstallQualified"])

    def test_changed_identity_missing_cases_false_preservation_and_scope_claims_refuse(self):
        for kind in ("missing","reordered","helper","manifest","payload","record","generation","generation-bool","exit-bool","false-success","refused-inventory","unknown-key","null-result","scope","incoming","receipt","receipt-paths","incoming-count","receipt-count","receipt-files","mutation","uninstall","production","fingerprint","reused-fingerprint","copy-count","history-capacity","private-data","elapsed"):
            items,args=self.fixture();items=copy.deepcopy(items);first=items[0];value=first["result"]
            if kind=="missing":items.pop()
            elif kind=="reordered":items[1],items[2]=items[2],items[1]
            elif kind=="helper":first["helperSHA256"]="b"*64
            elif kind=="manifest":value["manifestSHA256"]="b"*64
            elif kind=="payload":value["payloadSHA256"]="b"*64
            elif kind=="record":value["desktopRecordSHA256"]="b"*64
            elif kind=="generation":value["generation"]=2
            elif kind=="generation-bool":value["generation"]=True
            elif kind=="exit-bool":first["exitCode"]=False
            elif kind=="false-success":items[1]["result"]["state"]="inspected"
            elif kind=="refused-inventory":items[1]["result"]["inventorySHA256"]="a"*64
            elif kind=="unknown-key":value["deletePath"]="/Applications"
            elif kind=="null-result":first["result"]=None
            elif kind=="scope":value["inventoryScope"]="all-program-data"
            elif kind in ("incoming","receipt"):value[{"incoming":"incomingPayloadsInspected","receipt":"installerReceiptsInspected"}[kind]]=False
            elif kind in ("mutation","uninstall","production"):value[{"mutation":"mutationPerformed","uninstall":"productUninstallQualified","production":"productionQualificationComplete"}[kind]]=True
            elif kind=="receipt-paths":value["installerReceiptPathsVerified"]=False
            elif kind=="incoming-count":value["incomingPayloadCount"]=0
            elif kind=="receipt-count":value["installerReceiptCount"]=0
            elif kind=="receipt-files":value["receiptFileCount"]=0
            elif kind=="fingerprint":value["inventorySHA256"]="not-a-digest"
            elif kind=="reused-fingerprint":items[7]["result"]["inventorySHA256"]=value["inventorySHA256"]
            elif kind=="copy-count":value["retainedCoreCopies"]=0
            elif kind=="history-capacity":value["retainedStateRecords"]=130
            elif kind=="private-data":first["installationAndPrivateDataPreserved"]=False
            elif kind=="elapsed":first["elapsedMilliseconds"]=60001
            with self.subTest(kind=kind),self.assertRaises(ValueError):validate_product_removal_inspections(items,*args)


if __name__=="__main__":unittest.main()
