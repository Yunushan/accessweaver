#!/usr/bin/env python3
"""Validate the separate hosted event probe before attesting it. Never execute targets."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SHA=re.compile(r"[a-f0-9]{64}")
DEPENDENCIES=("scripts/test-windows-installer-event-native.ps1","scripts/windows-installer-event-fixture.ps1","scripts/test-windows-installer-lifecycle.ps1","scripts/windows-installer-state.ps1","scripts/windows-installer-native-state.ps1","scripts/windows-installer-event-state.ps1","internal/workflow/windows.ps1")
TRUE_FIELDS=("probeComplete","ownedTemporaryDirectoryRemoved","ruleCreationAttempted","ownedRuleCreated","ownedRuleDisabled","ownershipGuardVerified","ownedRuleRemoved","baselineRestored","controlledDriftRefused","adapterCalled","nativeAttemptSentinelPreserved","nativeReturnSentinelPreserved")
FALSE_FIELDS=("eventLogConfigurationChanged","unrelatedStateMutationAttempted","ownershipComparisonAtomic","installerExecutionPerformed","processOriginEstablished","productionQualificationComplete")
FIELDS={"schemaVersion","sourceCommit","sourceRef","runID","target","powershellVersion","failureCategory","nativeReadCompleted","localStore","ruleIdentitySHA256","ownershipSHA256","controlledComparison","baselineComparison","firewallEventDiagnostics","adapterFailure","reportMaxBytes","dependenciesSHA256",*TRUE_FIELDS,*FALSE_FIELDS}

def require(ok):
    if not ok:raise ValueError("Native event probe contract differs")

def hashed(v):return type(v) is str and SHA.fullmatch(v) is not None

def integer(v,low,high):return type(v) is int and low<=v<=high

def utc(v):
    require(type(v) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z",v) is not None)
    d=datetime.datetime.fromisoformat(v[:-2]+"+00:00")
    return ((d.toordinal()*86400+d.hour*3600+d.minute*60+d.second)*10000000+d.microsecond*10+int(v[-2]))

def validate_diagnostics(v,identity):
    fixed={"schemaVersion":1,"source":"existing-local-firewall-event-log","queryAttempted":True,"queryDeadlineMilliseconds":10000,"maxEvents":128,"maxRecords":16,"maxXmlBytes":65536,"maxFieldBytes":4096,"eventLogConfigurationChanged":False,"extraFirewallRuleQueriesPerformed":False,"processOriginEstablished":False}
    require(type(v) is dict and set(v)==set(fixed)|{"status","queryElapsedMilliseconds","windowStartUtc","windowEndUtc","eventsExamined","invalidEvents","eventsLimitReached","records","recordsTruncated","unavailable"})
    for k,w in fixed.items():require(type(v[k]) is type(w) and v[k]==w)
    require(v['status'] in ('captured','unavailable') and integer(v['queryElapsedMilliseconds'],0,7200000))
    start,end=utc(v['windowStartUtc']),utc(v['windowEndUtc']);require(0<=end-start<=7200*10000000)
    require(integer(v['eventsExamined'],0,128) and integer(v['invalidEvents'],0,v['eventsExamined']))
    require(type(v['eventsLimitReached']) is bool and type(v['recordsTruncated']) is bool and type(v['unavailable']) is bool)
    require(type(v['records']) is list and len(v['records'])<=min(16,v['eventsExamined']-v['invalidEvents']))
    require(v['unavailable']==(v['status']=='unavailable'))
    if v['status']=='unavailable':require(v['eventsExamined']==v['invalidEvents']==0 and v['records']==[] and not v['eventsLimitReached'] and not v['recordsTruncated'])
    if v['eventsLimitReached']:require(v['eventsExamined']==128)
    if v['recordsTruncated']:require(len(v['records'])==16 and v['eventsExamined']-v['invalidEvents']>16)
    for record in v['records']:
        require(type(record) is dict and set(record)=={'identitySHA256','eventId','recordId','occurredAtUtc','modifyingApplicationBasenameClass','fields'})
        require(record['identitySHA256']==identity and integer(record['eventId'],1,2147483647))
        require(type(record['recordId']) is str and re.fullmatch(r'[1-9][0-9]{0,19}',record['recordId']) is not None and int(record['recordId'])<=18446744073709551615)
        require(start<=utc(record['occurredAtUtc'])<=end)
        fields=record['fields'];require(type(fields) is dict and set(fields)=={'ModifyingApplication','ModifyingUser','ApplicationPath','ServiceName','Origin'})
        for field in fields.values():
            require(type(field) is dict and type(field.get('present')) is bool)
            if not field['present']:require(set(field)=={'present'})
            elif field.get('omitted') is True:require(set(field)=={'present','omitted'})
            else:require(set(field)=={'present','utf8Bytes','sha256'} and integer(field['utf8Bytes'],0,4096) and hashed(field['sha256']))
        application=fields['ModifyingApplication'];cls=record['modifyingApplicationBasenameClass']
        if not application['present']:require(cls=='absent')
        elif application.get('omitted') is True:require(cls=='omitted')
        else:require(cls in ('core','setup','uninstaller','other','service-host-basename'))
    return v['status']=='captured'

ADAPTER_STAGES=('none','preparation','native-invocation','native-output','json-decode','envelope-validation')
NATIVE_FAILURE_CATEGORIES=('none','tool-timeout','tool-exit','other-native-error')

def validate_adapter_failure(v,diagnostics):
    require(type(v) is dict and set(v)=={'stage','nativeFailureCategory'})
    stage,category=v['stage'],v['nativeFailureCategory']
    require(type(stage) is str and stage in ADAPTER_STAGES and type(category) is str and category in NATIVE_FAILURE_CATEGORIES)
    if diagnostics['status']=='captured':require(stage=='none' and category=='none')
    else:
        require(stage!='none' and diagnostics['queryAttempted'] is (stage!='preparation'))
        require((category!='none')==(stage=='native-invocation'))
    return {'stage':stage,'nativeFailureCategory':category}

DOMAIN_FIELDS={'beforeSHA256','afterSHA256','serializedEqual','beforeRows','afterRows','added','removed','changed','rowSerializationChanges','recordOrderingChanged','changes','changesTruncated'}
def validate_comparison(v,identity,controlled,baseline=None):
    require(type(v) is dict and set(v)=={'exactMatch','beforeSHA256','afterSHA256','domains'})
    require(v['exactMatch'] is (not controlled) and hashed(v['beforeSHA256']) and hashed(v['afterSHA256']))
    require((v['beforeSHA256']!=v['afterSHA256'])==controlled)
    require(type(v['domains']) is dict and set(v['domains'])=={'services','firewall','dns'})
    if baseline is not None:require(v['beforeSHA256']==baseline['beforeSHA256'])
    for name,d in v['domains'].items():
        added=controlled and name=='firewall'
        require(type(d) is dict and set(d)==DOMAIN_FIELDS and hashed(d['beforeSHA256']) and hashed(d['afterSHA256']))
        require(d['serializedEqual'] is (not added) and (d['beforeSHA256']!=d['afterSHA256'])==added)
        require(integer(d['beforeRows'],0,10000) and integer(d['afterRows'],0,10000) and d['afterRows']==d['beforeRows']+int(added))
        for key,wanted in {'added':int(added),'removed':0,'changed':0,'rowSerializationChanges':0}.items():require(type(d[key]) is int and d[key]==wanted)
        require(d['recordOrderingChanged'] is False and d['changesTruncated'] is False and type(d['changes']) is list)
        if baseline is not None:require(d['beforeSHA256']==baseline['domains'][name]['beforeSHA256'] and d['beforeRows']==baseline['domains'][name]['beforeRows'])
        if added:
            require(len(d['changes'])==1);change=d['changes'][0]
            require(type(change) is dict and set(change)=={'identitySHA256','kind','classification','beforeSHA256','afterSHA256','fields'})
            require(change['identitySHA256']==identity and change['kind']=='added' and change['classification']=='other' and change['beforeSHA256'] is None and hashed(change['afterSHA256']) and change['fields']==[])
        else:require(d['changes']==[])

def validate_probe(v,commit,ref,arch,run,root):
    require(type(v) is dict and set(v)==FIELDS)
    require(type(v['schemaVersion']) is int and v['schemaVersion']==2 and v['sourceCommit']==commit and re.fullmatch(r'[a-f0-9]{40}',commit) is not None)
    require(v['sourceRef']==ref and re.fullmatch(r'refs/heads/[A-Za-z0-9_./-]+',ref) is not None and '..' not in ref and '//' not in ref)
    require(type(v['runID']) is str and v['runID']==run and re.fullmatch(r'[1-9][0-9]{0,19}',run) is not None)
    require(arch in ('amd64','arm64') and v['target']=='windows/'+arch)
    require(type(v['powershellVersion']) is str and re.fullmatch(r'5\.1\.[0-9]+\.[0-9]+',v['powershellVersion']) is not None)
    require(v['failureCategory'] is None and v['localStore']=='PersistentStore' and type(v['reportMaxBytes']) is int and v['reportMaxBytes']==131072)
    require(all(v[k] is True for k in TRUE_FIELDS) and all(v[k] is False for k in FALSE_FIELDS))
    require(hashed(v['ruleIdentitySHA256']) and hashed(v['ownershipSHA256']))
    validate_comparison(v['baselineComparison'],v['ruleIdentitySHA256'],False)
    validate_comparison(v['controlledComparison'],v['ruleIdentitySHA256'],True,v['baselineComparison'])
    captured=validate_diagnostics(v['firewallEventDiagnostics'],v['ruleIdentitySHA256'])
    failure=validate_adapter_failure(v['adapterFailure'],v['firewallEventDiagnostics'])
    require(type(v['nativeReadCompleted']) is bool and v['nativeReadCompleted']==captured)
    require(type(v['dependenciesSHA256']) is dict and set(v['dependenciesSHA256'])==set(DEPENDENCIES))
    for name in DEPENDENCIES:require(v['dependenciesSHA256'][name]==hashlib.sha256((root/name).read_bytes()).hexdigest())
    return {'sourceCommit':commit,'target':v['target'],'controlledDriftAndCleanupVerified':True,'nativeReadCompleted':captured,'diagnosticStatus':v['firewallEventDiagnostics']['status'],'adapterFailure':failure,'correlatedRecords':len(v['firewallEventDiagnostics']['records']),'processOriginEstablished':False,'cryptographicProvenanceAuthenticated':False,'productionQualificationComplete':False}

def unique(pairs):
    out={}
    for k,v in pairs:
        if k in out:raise ValueError('Duplicate probe field')
        out[k]=v
    return out

def read_report(path):
    before=path.lstat();require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=131072)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NONBLOCK',0)|getattr(os,'O_NOFOLLOW',0))
    try:
        opened=os.fstat(fd);require(os.path.samestat(before,opened) and stat.S_ISREG(opened.st_mode) and opened.st_nlink==1 and opened.st_size==before.st_size)
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(131073)
        after=os.fstat(fd);named=path.lstat()
        require(len(raw)==before.st_size and len(raw)<=131072)
        require(all(os.path.samestat(before,x) and x.st_nlink==1 and x.st_size==before.st_size and x.st_mtime_ns==before.st_mtime_ns for x in (opened,after,named)))
        return raw
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--source-commit',required=True);p.add_argument('--source-ref',required=True);p.add_argument('--architecture',required=True);p.add_argument('--run-id',required=True);a=p.parse_args()
    try:
        raw=read_report(a.report)
        print(json.dumps(validate_probe(json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique),a.source_commit,a.source_ref,a.architecture,a.run_id,Path(__file__).resolve().parent.parent)));return 0
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        print('Native event probe validation failed',file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
