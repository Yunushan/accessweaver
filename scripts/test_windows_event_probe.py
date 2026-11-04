import copy
import hashlib
from pathlib import Path
import tempfile
import os
from unittest.mock import patch
import unittest
from verify_windows_event_probe import DEPENDENCIES,TRUE_FIELDS,FALSE_FIELDS,validate_probe,validate_adapter_failure,utc,unique,read_report

class ProbeContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for name in DEPENDENCIES:
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'fixture source, never executable')
    def fixture(self,status='captured'):
        h='0'*64;identity='c'*64
        domain={'beforeSHA256':h,'afterSHA256':h,'serializedEqual':True,'beforeRows':2,'afterRows':2,'added':0,'removed':0,'changed':0,'rowSerializationChanges':0,'recordOrderingChanged':False,'changes':[],'changesTruncated':False}
        baseline={'exactMatch':True,'beforeSHA256':h,'afterSHA256':h,'domains':{k:copy.deepcopy(domain) for k in ('services','firewall','dns')}}
        control=copy.deepcopy(baseline);control.update(exactMatch=False,afterSHA256='1'*64);d=control['domains']['firewall'];d.update(afterSHA256='1'*64,serializedEqual=False,afterRows=3,added=1,changes=[{'identitySHA256':identity,'kind':'added','classification':'other','beforeSHA256':None,'afterSHA256':'2'*64,'fields':[]}])
        diag={'schemaVersion':1,'source':'existing-local-firewall-event-log','status':status,'queryAttempted':True,'queryDeadlineMilliseconds':10000,'queryElapsedMilliseconds':1,'maxEvents':128,'maxRecords':16,'maxXmlBytes':65536,'maxFieldBytes':4096,'windowStartUtc':'2026-11-04T00:00:00.0000000Z','windowEndUtc':'2026-11-04T00:00:00.0000002Z','eventsExamined':0,'invalidEvents':0,'eventsLimitReached':False,'records':[],'recordsTruncated':False,'unavailable':status=='unavailable','eventLogConfigurationChanged':False,'extraFirewallRuleQueriesPerformed':False,'processOriginEstablished':False}
        return {'schemaVersion':2,'sourceCommit':'a'*40,'sourceRef':'refs/heads/main','runID':'7','target':'windows/amd64','powershellVersion':'5.1.26100.1','failureCategory':None,'nativeReadCompleted':status=='captured','localStore':'PersistentStore','ruleIdentitySHA256':identity,'ownershipSHA256':'d'*64,'controlledComparison':control,'baselineComparison':baseline,'firewallEventDiagnostics':diag,'adapterFailure':{'stage':'none' if status=='captured' else 'native-invocation','nativeFailureCategory':'none' if status=='captured' else 'other-native-error'},'reportMaxBytes':131072,'dependenciesSHA256':{n:hashlib.sha256((self.root/n).read_bytes()).hexdigest() for n in DEPENDENCIES},**dict.fromkeys(TRUE_FIELDS,True),**dict.fromkeys(FALSE_FIELDS,False)}
    def check(self,value):return validate_probe(value,'a'*40,'refs/heads/main','amd64','7',self.root)
    def test_captured_and_unavailable_are_truthfully_distinct(self):
        for status in ('captured','unavailable'):
            v=self.fixture(status);r=self.check(v);self.assertEqual(r['nativeReadCompleted'],status=='captured');self.assertFalse(r['processOriginEstablished']);self.assertFalse(r['cryptographicProvenanceAuthenticated'])
    def test_fixed_adapter_failure_stages_and_native_categories(self):
        for stage in ('native-invocation','native-output','json-decode','envelope-validation'):
            categories=('tool-timeout','tool-exit','other-native-error') if stage=='native-invocation' else ('none',)
            for category in categories:
                v=self.fixture('unavailable');failure={'stage':stage,'nativeFailureCategory':category};v['adapterFailure']=failure
                with self.subTest(stage=stage,category=category):self.assertEqual(self.check(v)['adapterFailure'],failure)
        # Preparation is meaningful failure evidence but not an attestable completed
        # probe: the original controlled-probe admission still requires a query attempt.
        v=self.fixture('unavailable');v['adapterFailure']={'stage':'preparation','nativeFailureCategory':'none'};v['firewallEventDiagnostics']['queryAttempted']=False
        self.assertEqual(validate_adapter_failure(v['adapterFailure'],v['firewallEventDiagnostics']),v['adapterFailure'])
        with self.assertRaises(ValueError):self.check(v)
    def test_adapter_failure_privacy_types_and_status_consistency_refuse(self):
        invalid=[None,[],{},True,{'stage':'none'},{'stage':'none','nativeFailureCategory':'none','rawError':'PRIVATE'},
                 {'stage':'PRIVATE','nativeFailureCategory':'none'},{'stage':'native-invocation','nativeFailureCategory':'PRIVATE'},
                 {'stage':True,'nativeFailureCategory':'none'},{'stage':['none'],'nativeFailureCategory':'none'},
                 {'stage':'none','nativeFailureCategory':False},{'stage':'none','nativeFailureCategory':['none']}]
        for status in ('captured','unavailable'):
            for failure in invalid:
                v=self.fixture(status);v['adapterFailure']=failure
                with self.subTest(status=status,failure=failure),self.assertRaises(ValueError):self.check(v)
        for status,stage,category in [('captured','native-invocation','tool-timeout'),('captured','none','tool-exit'),
                                      ('unavailable','none','none'),('unavailable','native-invocation','none'),
                                      ('unavailable','native-output','tool-timeout'),('unavailable','json-decode','tool-exit'),
                                      ('unavailable','envelope-validation','other-native-error'),('unavailable','preparation','none')]:
            v=self.fixture(status);v['adapterFailure']={'stage':stage,'nativeFailureCategory':category}
            with self.subTest(status=status,stage=stage,category=category),self.assertRaises(ValueError):self.check(v)
        v=self.fixture('unavailable');v['firewallEventDiagnostics']['queryAttempted']=False
        with self.assertRaises(ValueError):self.check(v)
    def test_missing_extra_raw_and_mutated_scope_fields_refuse(self):
        good=self.fixture();cases=[None,{},dict(good,rawRuleName='PRIVATE')]
        for k in good:
            v=copy.deepcopy(good);v.pop(k);cases.append(v)
        for k in TRUE_FIELDS:cases.append(dict(good,**{k:False}))
        for k in FALSE_FIELDS:cases.append(dict(good,**{k:True}))
        for k,v in [('schemaVersion',True),('schemaVersion',1),('runID',7),('target','windows/arm64'),('localStore','ActiveStore'),('powershellVersion','7.6.5'),('failureCategory','PRIVATE'),('ownershipSHA256','PRIVATE'),('nativeReadCompleted',False),('reportMaxBytes',131073)]:cases.append(dict(good,**{k:v}))
        for value in cases:
            with self.subTest(value=value),self.assertRaises(ValueError):self.check(value)
    def test_source_dependencies_and_identity_are_exact(self):
        for mode in ('changed','extra','missing'):
            v=self.fixture();deps=v['dependenciesSHA256']
            if mode=='changed':deps[DEPENDENCIES[0]]='f'*64
            if mode=='extra':deps['../PRIVATE']='f'*64
            if mode=='missing':deps.pop(DEPENDENCIES[0])
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.check(v)
        retained=self.fixture()
        (self.root/DEPENDENCIES[0]).write_bytes(b'changed source')
        with self.assertRaises(ValueError):self.check(retained)
    def test_unrelated_drift_and_rebaselining_refuse(self):
        for mode in ('dns','services','identity','rows','baseline','source-baseline','private-change'):
            v=self.fixture();c=v['controlledComparison']
            if mode in ('dns','services'):c['domains'][mode]['changed']=1
            if mode=='identity':c['domains']['firewall']['changes'][0]['identitySHA256']='e'*64
            if mode=='rows':c['domains']['firewall']['afterRows']=4
            if mode=='baseline':v['baselineComparison']['exactMatch']=False
            if mode=='source-baseline':c['beforeSHA256']='e'*64
            if mode=='private-change':c['domains']['firewall']['changes'][0]['rawName']='PRIVATE'
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.check(v)
    def record(self,v):
        d=v['firewallEventDiagnostics'];d['eventsExamined']=1;d['records']=[{'identitySHA256':v['ruleIdentitySHA256'],'eventId':12345,'recordId':'9007199254740993','occurredAtUtc':'2026-11-04T00:00:00.0000001Z','modifyingApplicationBasenameClass':'absent','fields':{n:{'present':False} for n in ('ModifyingApplication','ModifyingUser','ApplicationPath','ServiceName','Origin')}}];return d['records'][0]
    def test_named_hash_only_record_and_100ns_window(self):
        v=self.fixture();r=self.record(v);self.assertEqual(self.check(v)['correlatedRecords'],1)
        self.assertEqual(utc(r['occurredAtUtc'])-utc(v['firewallEventDiagnostics']['windowStartUtc']),1)
        r['occurredAtUtc']='2026-11-04T00:00:00.0000003Z'
        with self.assertRaises(ValueError):self.check(v)
    def test_private_oversized_ambiguous_or_unavailable_records_refuse(self):
        for mode in ('private','field','class','identity','record-overflow','record-int','events','records','unknown-key','unavailable','bad-time','limit'):
            v=self.fixture();r=self.record(v);d=v['firewallEventDiagnostics']
            if mode=='private':r['rawXML']='PRIVATE'
            if mode=='field':r['fields']['ModifyingUser']={'present':True,'utf8Bytes':4097,'sha256':'a'*64}
            if mode=='class':r['modifyingApplicationBasenameClass']='PRIVATE.exe'
            if mode=='identity':r['identitySHA256']='f'*64
            if mode=='record-overflow':r['recordId']='18446744073709551616'
            if mode=='record-int':r['recordId']=9007199254740993
            if mode=='events':d['eventsExamined']=129
            if mode=='records':d['records']*=17
            if mode=='unknown-key':d['private']='PRIVATE'
            if mode=='unavailable':d['status']='unavailable';d['unavailable']=True;v['nativeReadCompleted']=False
            if mode=='bad-time':r['occurredAtUtc']='2026-02-30T00:00:00.0000000Z'
            if mode=='limit':d['eventsLimitReached']=True
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.check(v)
    def test_report_read_is_descriptor_bound_and_capped_during_growth(self):
        p=self.root/'report.json';p.write_bytes(b'{}');self.assertEqual(read_report(p),b'{}')
        real=os.fdopen;requests=[]
        class GrowingReader:
            def __init__(self,fd,*args,**kwargs):self.file=real(fd,*args,**kwargs)
            def __enter__(self):return self
            def __exit__(self,*args):self.file.close()
            def read(self,count):
                requests.append(count)
                with p.open('ab') as out:out.write(b'x'*262144)
                return self.file.read(count)
        with patch('verify_windows_event_probe.os.fdopen',GrowingReader):
            with self.assertRaises(ValueError):read_report(p)
        self.assertEqual(requests,[131073])
    def test_report_input_links_and_oversize_refuse(self):
        p=self.root/'report.json';p.write_bytes(b'x'*131073)
        with self.assertRaises(ValueError):read_report(p)
        p.write_bytes(b'{}');alias=self.root/'alias.json';os.link(p,alias)
        with self.assertRaises(ValueError):read_report(alias)
    def test_duplicate_json_keys_refuse(self):
        with self.assertRaises(ValueError):unique([('private',1),('private',2)])
if __name__=='__main__':unittest.main()
