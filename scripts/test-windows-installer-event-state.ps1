# Pure synthetic diagnostics. No native event queries or process execution.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows-installer-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-native-state.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-event-state.ps1')
function Assert-Event([bool]$ok,[string]$message){if(-not $ok){throw $message}}
function Get-WinEvent {throw 'No native event query allowed in synthetic tests'}
$start=[datetime]::SpecifyKind([datetime]'2026-11-04T00:00:00',[DateTimeKind]::Utc);$end=$start.AddMinutes(10)
$identity=Get-InstallerStateTextHash 'PRIVATE_RULE_ID'
$xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Windows Firewall With Advanced Security"/><EventID>2071</EventID><TimeCreated SystemTime="2026-11-04T00:01:00.0000000Z"/><EventRecordID>9007199254740993</EventRecordID><Channel>Microsoft-Windows-Windows Firewall With Advanced Security/Firewall</Channel><Computer>PRIVATE_COMPUTER</Computer></System><EventData><Data Name="RuleId">PRIVATE_RULE_ID</Data><Data Name="RuleName">PRIVATE_RULE_NAME</Data><Data Name="ModifyingApplication">C:\PRIVATE_PATH\svchost.exe</Data><Data Name="ModifyingUser">PRIVATE_SID</Data><Data Name="ApplicationPath">C:\PRIVATE_APPLICATION</Data><Data Name="ServiceName">PRIVATE_SERVICE</Data><Data Name="Origin">PRIVATE_ORIGIN</Data><Data Name="CommandLine">PRIVATE_TOKEN</Data></EventData></Event>'
$record=Convert-InstallerFirewallEvent $xml @($identity) $start $end
Assert-Event ($record.identitySHA256 -ceq $identity -and $record.eventId -eq 2071 -and $record.recordId -ceq '9007199254740993' -and $record.modifyingApplicationBasenameClass -ceq 'service-host-basename') 'Exact event identity/large record ID/class lost'
Assert-Event ($record.fields.ModifyingUser.sha256 -ceq (Get-InstallerStateTextHash 'PRIVATE_SID')) 'Named field fingerprint differs'
$public=ConvertTo-Json -InputObject $record -Depth 12
foreach($private in @('PRIVATE_RULE','PRIVATE_PATH','PRIVATE_SID','PRIVATE_APPLICATION','PRIVATE_SERVICE','PRIVATE_ORIGIN','PRIVATE_TOKEN','PRIVATE_COMPUTER')){Assert-Event (-not $public.Contains($private)) 'Raw event data escaped'}
foreach($variant in @($xml.Replace('2071','2004'),$xml.Replace('2071','2097'),$xml.Replace('2071','12345'))){Assert-Event ($null -ne (Convert-InstallerFirewallEvent $variant @($identity) $start $end)) 'Diagnostic assumed a specific OS event ID'}
foreach($variant in @($xml.Replace('PRIVATE_RULE_ID','different-rule'),$xml.Replace('With Advanced Security"','With Advanced Security-other"'),$xml.Replace('Security/Firewall<','Security/Other<'),$xml.Replace('00:01:00.0000000Z','01:01:00.0000000Z'),$xml.Replace('Name="RuleId"','Name="RuleID"'))){Assert-Event ($null -eq (Convert-InstallerFirewallEvent $variant @($identity) $start $end)) 'Unmatched provider/channel/time/identity correlated'}
$missing=$xml.Replace('<Data Name="ModifyingUser">PRIVATE_SID</Data>','')
Assert-Event (-not (Convert-InstallerFirewallEvent $missing @($identity) $start $end).fields.ModifyingUser.present) 'Absent field fabricated'
$large=$xml.Replace('PRIVATE_SID',('x'*4097)).Replace('PRIVATE_SERVICE',(([string][char]0x754c)*2000))
$bounded=Convert-InstallerFirewallEvent $large @($identity) $start $end
Assert-Event ($bounded.fields.ModifyingUser.omitted -and $bounded.fields.ServiceName.omitted) 'Character/UTF8 field bounds differ'
$duplicate=$xml.Replace('<Data Name="RuleName">','<Data Name="RuleId">ambiguous</Data><Data Name="RuleName">')
$bad=@($duplicate,$xml.Replace('<System>','<System/><System>'),$xml.Replace('<EventID>2071</EventID>','<EventID>PRIVATE_BAD</EventID>'),$xml.Replace('<EventRecordID>9007199254740993</EventRecordID>','<EventRecordID>18446744073709551616</EventRecordID>'),$xml.Replace('00:01:00.0000000Z','PRIVATE_TIME'),('<!DOCTYPE Event [<!ENTITY external SYSTEM "file:///PRIVATE_FILE">]>'+$xml),('<!DOCTYPE Event [<!ENTITY x "PRIVATE_EXPANSION">]>'+$xml.Replace('PRIVATE_SID','&x;')),('x'*65537))
foreach($variant in $bad){$refused=$false;try{$null=Convert-InstallerFirewallEvent $variant @($identity) $start $end}catch{$refused=$true};Assert-Event $refused 'Ambiguous/DTD/oversized/malformed event accepted'}
$manyFields=$xml.Replace('</EventData>',((1..129 | ForEach-Object {'<Data Name="Extra'+$_+'">private</Data>'}) -join '')+'</EventData>')
$multiByte=$xml.Replace('PRIVATE_COMPUTER',(([string][char]0x754c)*22000))
foreach($variant in @($manyFields,$multiByte)){$refused=$false;try{$null=Convert-InstallerFirewallEvent $variant @($identity) $start $end}catch{$refused=$true};Assert-Event $refused 'Field-count or XML UTF8 byte cap ignored'}
$omittedClass=Convert-InstallerFirewallEvent ($xml.Replace('C:\PRIVATE_PATH\svchost.exe',('x'*4097))) @($identity) $start $end
Assert-Event ($omittedClass.modifyingApplicationBasenameClass -ceq 'omitted' -and $omittedClass.fields.ModifyingApplication.omitted) 'Oversized modifying application was classified'
$frames=Convert-InstallerFirewallEvents (@($xml)*20) @($identity) $start $end $true
Assert-Event ($frames.eventsExamined -eq 20 -and $frames.records.Count -eq 16 -and $frames.recordsTruncated -and $frames.eventsLimitReached -and -not $frames.processOriginEstablished -and -not $frames.eventLogConfigurationChanged -and -not $frames.extraFirewallRuleQueriesPerformed) 'Event/frame bounds or claim scope changed'
$mixed=Convert-InstallerFirewallEvents @($xml,'PRIVATE_BAD_XML') @($identity) $start $end
Assert-Event ($mixed.eventsExamined -eq 2 -and $mixed.invalidEvents -eq 1 -and $mixed.records.Count -eq 1 -and -not ((ConvertTo-Json $mixed -Depth 12).Contains('PRIVATE'))) 'Malformed event/privacy accounting differs'
foreach($case in @(@{start=$start;end=$end;ids=@($identity)*17},@{start=$start;end=$start.AddHours(3);ids=@($identity)},@{start=$end;end=$start;ids=@($identity)},@{start=$start;end=$end;ids=@('PRIVATE')})){$refused=$false;try{$null=Convert-InstallerFirewallEvents @($xml) $case.ids $case.start $case.end}catch{$refused=$true};Assert-Event $refused 'Invalid query bounds admitted'}
$refused=$false;try{$null=Convert-InstallerFirewallEvents (@($xml)*129) @($identity) $start $end}catch{$refused=$true};Assert-Event $refused 'Excess event input admitted'
$script:syntheticQueries=0
$read={param($filter,$maximum)
    $script:syntheticQueries++
    Assert-Event ($maximum -eq 129 -and $filter.LogName -ceq 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -and $filter.StartTime -eq $start -and $filter.EndTime -eq $end -and $filter.Keys.Count -eq 3) 'Query broadened or unbounded'
    foreach($index in 1..129){$event=[pscustomobject]@{Xml=$xml};$event | Add-Member ScriptMethod ToXml {return $this.Xml};$event}
}
$queried=Read-InstallerFirewallEventLog @($identity) $start $end $read
Assert-Event ($script:syntheticQueries -eq 1 -and $queried.eventsExamined -eq 128 -and $queried.eventsLimitReached -and $queried.records.Count -eq 16) 'Native adapter ignored read/sentinel bounds'
$project=Split-Path -Parent $PSScriptRoot
$tokens=$null;$issues=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'test-windows-installer-lifecycle.ps1'),[ref]$tokens,[ref]$issues)
Assert-Event (-not $issues.Count) 'Lifecycle source parse failed'
$nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Read-FirewallEventDiagnostic'})
Assert-Event ($nodes.Count -eq 1) 'Expected one event adapter';. ([scriptblock]::Create($nodes[0].Extent.Text))
$script:firewallOriginObservations=@();$script:firewallEventWindowStartUtc=$start;$script:syntheticChildCalls=0;$script:lastNativeAttempt=@{preserve='uninstaller'};$original=$script:lastNativeAttempt
function Invoke-Isolated([string]$binary,[string[]]$arguments,[int[]]$codes,[int]$Timeout){
    $script:syntheticChildCalls++
    Assert-Event ($Timeout -eq 10 -and $arguments[0] -ceq '-NoLogo' -and $arguments -notcontains '-ExecutionPolicy' -and $arguments -notcontains '-Command' -and $codes.Count -eq 1 -and $codes[0] -eq 0) 'Child timeout/policy/exit admission changed'
    $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($arguments[-1]))
    $childTokens=$null;$childIssues=$null;$null=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$childTokens,[ref]$childIssues)
    Assert-Event (-not $childIssues.Count) 'Encoded child command did not parse'
    Assert-Event ($body.Contains('Read-InstallerFirewallEventLog') -and -not $body.Contains('Set-WinEvent') -and -not $body.Contains('wevtutil') -and -not $body.Contains('PRIVATE_RULE_ID')) 'Unsafe child command/data boundary'
    if($script:syntheticChildMode -ceq 'throw'){throw 'PRIVATE_CHILD_ERROR'}
    if($script:syntheticChildMode -ceq 'incomplete'){return @{exitCode=0;outputComplete=$false;stdout='PRIVATE_CHILD_OUTPUT';stderr=''}}
    if($script:syntheticChildMode -ceq 'malformed'){return @{exitCode=0;outputComplete=$true;stdout='PRIVATE_CHILD_OUTPUT';stderr=''}}
    $value=New-InstallerFirewallEventDiagnostic;$value.status='captured';$value.queryAttempted=$true;$value.windowStartUtc=$script:firewallEventWindowStartUtc.ToString('o')
    $match=[regex]::Match($body,'\$end=\[datetime\]::ParseExact\(''([^'']+)''');Assert-Event $match.Success 'Child end-time argument lost';$value.windowEndUtc=$match.Groups[1].Value
    if($script:syntheticChildMode -ceq 'stale'){$value.windowStartUtc='PRIVATE_OLD_WINDOW'}
    return @{exitCode=0;outputComplete=$true;stdout=(ConvertTo-Json -InputObject $value -Depth 12 -Compress);stderr=''}
}
$nothing=Read-FirewallEventDiagnostic
Assert-Event ($nothing.status -ceq 'not-needed' -and $script:syntheticChildCalls -eq 0) 'Unchanged state launched event query'
$script:firewallOriginObservations=@(@{identitySHA256=$identity});$script:firewallEventWindowStartUtc=[datetime]::UtcNow.AddMinutes(-10);$script:syntheticChildMode='success'
$captured=Read-FirewallEventDiagnostic
Assert-Event ($captured.status -ceq 'captured' -and $script:syntheticChildCalls -eq 1 -and [object]::ReferenceEquals($original,$script:lastNativeAttempt)) 'Event query replaced original native attempt'
foreach($mode in @('throw','incomplete','malformed','stale')){$script:syntheticChildMode=$mode;$unavailable=Read-FirewallEventDiagnostic;Assert-Event ($unavailable.status -ceq 'unavailable' -and $unavailable.unavailable -and $unavailable.queryAttempted -and -not ((ConvertTo-Json $unavailable -Depth 12).Contains('PRIVATE'))) 'Unavailable query leaked or masked status'}
# Quoted source paths must remain data in the encoded command as well.
$project=$project+"' quoted project";$script:syntheticChildMode='success';$quoted=Read-FirewallEventDiagnostic
Assert-Event ($quoted.status -ceq 'captured') 'Quoted project path broke child command data binding'
$prior=$script:syntheticChildCalls;$script:firewallEventWindowStartUtc=[datetime]::MinValue;$unavailable=Read-FirewallEventDiagnostic
Assert-Event ($unavailable.unavailable -and -not $unavailable.queryAttempted -and $script:syntheticChildCalls -eq $prior) 'Invalid query input claimed dispatch'
Write-Output 'Synthetic event XML, privacy, DTD, correlation, query/frame bounds and failure adapter checks passed; no native queries/processes or system changes.'
