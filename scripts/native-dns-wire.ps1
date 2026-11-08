# Native-only helpers. Definitions have no top-level effects. Never run locally.
function New-NativeDNSWireState([string]$PrivateRoot,[string]$DecoderPath) {
    Assert-NativeOrdinaryPath $PrivateRoot
    # Application discovery may return multiple PATH matches. ProcessStartInfo
    # needs one application filename, never an array converted to a string.
    $applications=@(Get-Command node -CommandType Application -ErrorAction Stop)
    if($applications.Count -eq 0 -or $applications[0].Path -isnot [string] -or [string]::IsNullOrWhiteSpace($applications[0].Path)){throw 'Wire decoder application'}
    $node=$applications[0].Path
    Assert-NativeOrdinaryPath $node
    $flags=@{}
    foreach($name in @('baselineResolverPassed','filtersVerified','captureStarted','captureStopped','captureBounded','plaintextBlocked','ordinaryQueryPassed','tlsObserved','tlsBlocked','blockedQueryRejected','tlsBlockRemoved','resumedQueryPassed','originalStateVerified','rulesRemoved','filtersRemoved','originalResolverPassed')){$flags[$name]=$false}
    return @{workdir=$PrivateRoot;processFailureCode='none';failureExitCode=0;failureStdoutChars=0;failureStderrChars=0;failureElapsedMilliseconds=0;captureFileCode='not-inspected';decoder=$DecoderPath;etlBytes=0;pcapBytes=0;filterRows=0;filterCode='none';cleanupAttempted=$false;cleanupCompleted=$false;phase='preflight';failurePhase='none';decoderCode='none';before=$null;owner=('aw'+[guid]::NewGuid().ToString('N').Substring(0,10));tool=(Join-Path $env:SystemRoot 'System32\pktmon.exe');node=$node;etl=(Join-Path $PrivateRoot 'PktMon.etl');pcap=(Join-Path $PrivateRoot 'wire.pcapng');filters=@();rules=@();startAttempted=$false;stopped=$false;processes=0;joined=0;processFailed=$false;flags=$flags;tlsFlows=0;outRecords=0;inRecords=0;providers=0}
}
function Get-NativeDNSWireSetupCode([Exception]$Failure) {
    for($depth=0;$null -ne $Failure -and $depth -lt 16;$depth++){
        if($Failure -is [ComponentModel.Win32Exception]){
            return $(switch($Failure.NativeErrorCode){2{'start-not-found'}3{'start-not-found'}5{'start-access'}193{'start-image'}267{'start-directory'}206{'start-path-bound'}740{'start-elevation'}1260{'start-policy'}default{'start-os-other'}})
        }
        if($null -eq $Failure.InnerException){break};$Failure=$Failure.InnerException
    }
    if($Failure -is [ArgumentException]){return 'start-argument'}
    if($Failure -is [InvalidOperationException]){return 'start-state'}
    return 'setup'
}
function Wait-NativeDNSWireWrite([object]$Task) {
    # Runtime tasks may expose a generic completion value through PowerShell.
    # Only child stdout/stderr may contribute to the decoder response stream.
    [void]$Task.GetAwaiter().GetResult()
}
function Invoke-NativeDNSWireProcess([object]$State,[string]$Program,[string[]]$Arguments,[byte[]]$InputBytes=$null) {
    if($State.processes -ge 128){throw 'Wire process bound'}
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Program
    $quoted=@();foreach($arg in $Arguments){if($arg.Contains('"') -or $arg.Contains("`r") -or $arg.Contains("`n")){throw 'Wire argument shape'};$quoted+=@('"'+$arg+'"')}
    $start.Arguments=$quoted -join ' ';$start.WorkingDirectory=$State.workdir;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=($null -ne $InputBytes)
    $p=[Diagnostics.Process]::new();$p.StartInfo=$start;$started=$false;$wasJoined=$false;$captures=@();$bad=$false;$failureKind='none';$clock=$null;$write=$null;$closed=$null -eq $InputBytes
    try {
        if(-not $p.Start()){throw 'Wire process start'};$State.processes++;$started=$true
        $clock=[Diagnostics.Stopwatch]::StartNew();$captures=@()
        foreach($reader in @($p.StandardOutput,$p.StandardError)){$buffer=[char[]]::new(4096);$captures+=@{reader=$reader;buffer=$buffer;text=[Text.StringBuilder]::new();done=$false;task=$reader.ReadAsync($buffer,0,$buffer.Length)}}
        if(-not $closed){$write=$p.StandardInput.BaseStream.WriteAsync($InputBytes,0,$InputBytes.Length)}
        $kill=$false;$total=0
        while(-not $p.HasExited -or @($captures | Where-Object {-not $_.done}).Count -ne 0){
            if(-not $closed -and $write.IsCompleted){try{Wait-NativeDNSWireWrite $write}catch{$bad=$true;if($failureKind -ceq 'none'){$failureKind='write'}};$p.StandardInput.Close();$closed=$true}
            foreach($c in $captures){if(-not $c.done -and $c.task.IsCompleted){
                try{$n=$c.task.GetAwaiter().GetResult();if($n -eq 0){$c.done=$true}else{$total+=$n;if($total -gt 65536){$bad=$true;if($failureKind -ceq 'none'){$failureKind='output-bound'}}else{[void]$c.text.Append($c.buffer,0,$n)};$c.task=$c.reader.ReadAsync($c.buffer,0,$c.buffer.Length)}}
                catch{$bad=$true;if($failureKind -ceq 'none'){$failureKind='read'};$c.done=$true;$c.reader.Dispose()}
            }}
            if(($clock.Elapsed.TotalSeconds -ge 15 -or $bad) -and -not $kill -and -not $p.HasExited){$kill=$true;$bad=$true;if($failureKind -ceq 'none'){$failureKind='timeout'};try{$p.Kill()}catch{}}
            $pending=[Threading.Tasks.Task[]]@($captures | Where-Object {-not $_.done} | ForEach-Object {$_.task})
            if($pending.Length){[void][Threading.Tasks.Task]::WaitAny($pending,10)}else{Start-Sleep -Milliseconds 10}
        }
        $p.WaitForExit();$State.joined++;$wasJoined=$true
        if(-not $closed){try{Wait-NativeDNSWireWrite $write}catch{$bad=$true;if($failureKind -ceq 'none'){$failureKind='write'}};$p.StandardInput.Close()}
        if($bad -or $p.ExitCode -ne 0){if($failureKind -ceq 'none'){$failureKind='exit'};$State.processFailed=$true;throw 'Wire bounded child failed'}
        return ($captures[0].text.ToString()+$captures[1].text.ToString())
    } catch {
        $State.processFailed=$true
        if($State.processFailureCode -ceq 'none'){
            $State.processFailureCode=if($failureKind -ceq 'none'){Get-NativeDNSWireSetupCode $_.Exception}else{$failureKind}
            if($wasJoined){$State.failureExitCode=$p.ExitCode}
            if($captures.Count -gt 0){$State.failureStdoutChars=[Math]::Min(65537,$captures[0].text.Length)}
            if($captures.Count -gt 1){$State.failureStderrChars=[Math]::Min(65537,$captures[1].text.Length)}
            if($null -ne $clock){$State.failureElapsedMilliseconds=[long][Math]::Min(1200000,$clock.Elapsed.TotalMilliseconds)}
        };throw
    } finally {
        if($started -and -not $wasJoined){$State.processFailed=$true;try{if(-not $p.HasExited){$p.Kill()}}catch{};$p.WaitForExit();$State.joined++;foreach($c in $captures){$c.reader.Dispose()}}
        $p.Dispose()
    }
}
function Invoke-NativeDNSWireTool([object]$State,[string[]]$Arguments) {return (Invoke-NativeDNSWireProcess $State $State.tool $Arguments)}
function Assert-NativeDNSWireStopped([string]$Text) {
    if($Text.Trim() -notmatch '^(Packet Monitor|Packet monitoring|Logger) is not (currently )?(running|active)\.?$'){throw 'Wire monitor state'}
}
function Assert-NativeDNSWireEmptyFilters([string]$Text) {
    if($Text.Trim() -notmatch '^(Packet Filters:\s*)?(No (packet )?filters( configured)?\.?|None)$'){throw 'Wire filter state'}
}
function Get-NativeDNSWireFilterRows([string]$Text) {
    $rows=@()
    foreach($line in ($Text -split '\r?\n')){if($line -match '^\s*(\d+)\s+(\S+)'){
        $tokens=@($line.Trim() -split '\s+');$name=$tokens[1];if($name.Length -ge 2 -and $name.StartsWith('"') -and $name.EndsWith('"')){$name=$name.Substring(1,$name.Length-2)};$rows+=@{id=[int]$tokens[0];name=$name;values=@($tokens | Select-Object -Skip 2)}
    }}
    return @($rows)
}
function Assert-NativeDNSWireFilters([string]$Text,[object[]]$Plans) {
    $rows=@(Get-NativeDNSWireFilterRows $Text)
    if($rows.Count -ne $Plans.Count){throw 'Wire filter inventory'}
    $ids=@{};foreach($row in $rows){if($ids.ContainsKey($row.id)){throw 'Wire filter inventory'};$ids[$row.id]=$true}
    foreach($plan in $Plans){
        $matches=@($rows | Where-Object {$_.name -ceq $plan.name})
        if($matches.Count -ne 1){throw 'Wire filter identity'}
        $ip=0;$protocol=0;$port=0
        foreach($value in $matches[0].values){
            if($value.Contains('.') -or $value.Contains(':')){
                $address=$null;if(-not [Net.IPAddress]::TryParse($value,[ref]$address) -or $address.ToString() -cne ([Net.IPAddress]$plan.address).ToString()){throw 'Wire filter endpoint'};$ip++
            }elseif($value -ceq $plan.protocol -or $value -ceq $(if($plan.protocol -ceq 'TCP'){'6'}else{'17'})){$protocol++}
            elseif($value -ceq [string]$plan.port){$port++}
            elseif($value -cnotin @('IPv4','IPv6','2048','34525','0x800','0x86dd','0','-','--','*','Any','None','N/A')){throw 'Wire filter field'}
        }
        if($ip -ne 1 -or $protocol -ne 1 -or $port -ne 1){throw 'Wire filter semantics'}
    }
}
function Assert-NativeDNSWireFirewall {
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if($profiles.Count -eq 0 -or @( $profiles | Where-Object {[string]$_.Enabled -cne 'True' -or [string]$_.AllowLocalFirewallRules -ceq 'False' -or @($_.DisabledInterfaceAliases | Where-Object {$_ -and $_ -cne 'NotConfigured'}).Count -ne 0}).Count -ne 0 -or (Get-Service -Name MpsSvc -ErrorAction Stop).Status -ne 'Running'){throw 'Wire firewall policy'}
}
function Assert-NativeDNSWireRule([object]$Plan,[string]$Store='ActiveStore') {
    $rows=@(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop | Where-Object {$_.Name -ceq $Plan.name})
    if($rows.Count -ne 1 -or $rows[0].DisplayName -cne 'AccessWeaver native DNS wire fixture' -or $rows[0].Group -cne 'AccessWeaver native qualification' -or [string]$rows[0].Enabled -cne 'True' -or [string]$rows[0].Action -cne 'Block' -or [string]$rows[0].Direction -cne 'Outbound' -or [string]$rows[0].Profile -cne 'Any'){throw 'Wire rule ownership'}
    $ports=@($rows[0] | Get-NetFirewallPortFilter -ErrorAction Stop);$addresses=@($rows[0] | Get-NetFirewallAddressFilter -ErrorAction Stop)
    if($ports.Count -ne 1 -or [string]$ports[0].Protocol -cnotin @($Plan.protocol,$(if($Plan.protocol -ceq 'TCP'){'6'}else{'17'})) -or (@($ports[0].RemotePort) -join ',') -cne [string]$Plan.port -or $addresses.Count -ne 1){throw 'Wire rule port'}
    $actual=@($addresses[0].RemoteAddress)
    if($Plan.kind -ceq 'dns'){if($actual.Count -ne 1 -or $actual[0] -cne 'Any'){throw 'Wire rule address'}}
    else {
        if($actual.Count -ne 4){throw 'Wire rule address'}
        foreach($wanted in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
            if(@($actual | Where-Object {$_ -ceq $wanted -or $_ -ceq ($wanted+$(if($wanted.Contains(':')){'/128'}else{'/32'}))}).Count -ne 1){throw 'Wire rule address'}
        }
    }
}
function Add-NativeDNSWireRule([object]$State,[string]$Kind,[string]$Protocol) {
    $plan=@{kind=$Kind;protocol=$Protocol;port=$(if($Kind -ceq 'dns'){53}else{443});name=($State.owner+'-'+$Kind+'-'+$Protocol)}
    if(@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.Name -ceq $plan.name}).Count -ne 0){throw 'Wire rule collision'}
    $State.rules+=@($plan)
    $remote=if($Kind -ceq 'dns'){@('Any')}else{@('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')}
    [void](New-NetFirewallRule -Name $plan.name -DisplayName 'AccessWeaver native DNS wire fixture' -Group 'AccessWeaver native qualification' -PolicyStore PersistentStore -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol $Protocol -RemotePort $plan.port -RemoteAddress $remote -ErrorAction Stop)
    Assert-NativeDNSWireRule $plan
}
function Remove-NativeDNSWireRules([object]$State,[string]$Kind) {
    foreach($plan in @($State.rules | Where-Object {$_.kind -ceq $Kind})){
        $rows=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.Name -ceq $plan.name})
        if($rows.Count -gt 0){Assert-NativeDNSWireRule $plan 'PersistentStore';Remove-NetFirewallRule -Name $plan.name -PolicyStore PersistentStore -ErrorAction Stop}
        foreach($store in @('PersistentStore','ActiveStore')){if(@(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop | Where-Object {$_.Name -ceq $plan.name}).Count -ne 0){throw 'Wire rule removal'}}
    }
}
function Start-NativeDNSWireCapture([object]$State) {
    # Exercise the exact private working directory, executable and binary-stdin
    # adapter before capture, filters or product configuration can be attempted.
    $State.phase='decoder-preflight'
    $version=Invoke-NativeDNSWireProcess $State $State.node @('--version')
    if($version.Trim() -cne 'v26.8.2'){throw 'Wire decoder version'}
    try{$probe=(Invoke-NativeDNSWireProcess $State $State.node @($State.decoder) ([byte[]]@(0))) | ConvertFrom-Json}catch{$State.decoderCode='invalid-report';throw}
    if($probe.schemaVersion -ne 1 -or $probe.outcome -cne 'refused' -or $probe.code -cne 'capture-bound' -or $null -ne $probe.evidence){$State.decoderCode='invalid-report';throw 'Wire decoder preflight'}
    $State.phase='monitor-preflight'
    Assert-NativeDNSWireStopped (Invoke-NativeDNSWireTool $State @('status'))
    Assert-NativeDNSWireEmptyFilters (Invoke-NativeDNSWireTool $State @('filter','list'))
    if(@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop).Count -ne 0){throw 'Wire name policy'}
    $State.phase='firewall-preflight';Assert-NativeDNSWireFirewall
    $State.phase='baseline-resolver';[void](Invoke-NativeDNSWireQuery 'example.com');$State.flags.baselineResolverPassed=$true
    $State.phase='filter-creation';$ordinal=0
    foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
        foreach($pair in @(@{protocol='TCP';port=443},@{protocol='TCP';port=53},@{protocol='UDP';port=53})){
            $ordinal++;$plan=@{name=($State.owner+'-'+$ordinal);address=$address;protocol=$pair.protocol;port=$pair.port};$State.filters+=@($plan)
            [void](Invoke-NativeDNSWireTool $State @('filter','add',$plan.name,'-i',$address,'-t',$pair.protocol,'-p',[string]$pair.port))
        }
    }
    $State.phase='filter-verification';$listing=Invoke-NativeDNSWireTool $State @('filter','list');$State.filterRows=[Math]::Min(33,@(Get-NativeDNSWireFilterRows $listing).Count)
    try{Assert-NativeDNSWireFilters $listing $State.filters}catch{
        $State.filterCode='unexpected';$errorValue=$_.Exception
        for($depth=0;$null -ne $errorValue -and $depth -lt 16;$depth++){
            $code=switch -CaseSensitive ($errorValue.Message){'Wire filter inventory'{'inventory'}'Wire filter identity'{'identity'}'Wire filter endpoint'{'endpoint'}'Wire filter field'{'field'}'Wire filter semantics'{'semantics'}default{'unexpected'}}
            if($code -cne 'unexpected'){$State.filterCode=$code;break};$errorValue=$errorValue.InnerException
        };throw
    };$State.flags.filtersVerified=$true
    $State.phase='capture-start';$State.startAttempted=$true
    [void](Invoke-NativeDNSWireTool $State @('start','--capture','--comp','nics','--pkt-size','0','--flags','0x012','--file-name',$State.etl,'--file-size','16','--log-mode','circular'))
    $State.flags.captureStarted=$true
}
function Stop-NativeDNSWireCapture([object]$State) {
    if($State.startAttempted -and -not $State.stopped){
        [void](Invoke-NativeDNSWireTool $State @('stop'))
        Assert-NativeDNSWireStopped (Invoke-NativeDNSWireTool $State @('status'))
        $State.stopped=$true;$State.flags.captureStopped=$true
    }
}
function Get-NativeDNSWireItem([string]$Path) {
    Assert-NativeOrdinaryPath $Path
    return (Get-Item -LiteralPath $Path -Force -ErrorAction Stop)
}
function Measure-NativeDNSWireFile([object]$State,[string]$Kind) {
    if($Kind -cnotin @('etl','pcap')){throw 'Wire file kind'};$file=$State[$Kind]
    try{$item=Get-NativeDNSWireItem $file}catch{$State.captureFileCode='unavailable';throw}
    if($Kind -ceq 'etl'){$State.etlBytes=[Math]::Min(16777217,$item.Length)}else{$State.pcapBytes=[Math]::Min(16777217,$item.Length)}
    $State.captureFileCode='ordinary'
    if($item.PSIsContainer){$State.captureFileCode='container';throw 'Wire capture container'}
    if($item.Length -le 0){$State.captureFileCode='empty';throw 'Wire capture empty'}
    if($item.Length -gt 16MB){$State.captureFileCode='oversized';throw 'Wire capture file bound'}
}
function Read-NativeDNSWireCapture([object]$State) {
    Measure-NativeDNSWireFile $State 'etl';Measure-NativeDNSWireFile $State 'pcap'
    $stream=[IO.FileStream]::new($State.pcap,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try{
        $length=$stream.Length;if($length -le 0 -or $length -gt 16MB){throw 'Wire capture stream bound'};$bytes=[byte[]]::new([int]$length);$at=0
        while($at -lt $bytes.Length){$count=$stream.Read($bytes,$at,$bytes.Length-$at);if($count -le 0){throw 'Wire capture read'};$at+=$count}
        if($stream.ReadByte() -ne -1){throw 'Wire capture grew'};$State.flags.captureBounded=$true;return ,$bytes
    }finally{$stream.Dispose()}
}
function Invoke-NativeDNSWireQuery([string]$Name,[switch]$ExpectFailure) {
    if($Name -cnotin @('example.com','example.net','example.org')){throw 'Wire query name'}
    Clear-DnsClientCache -ErrorAction Stop
    if($ExpectFailure){
        $rejected=$false;try{[void](Resolve-DnsName $Name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)}catch{$rejected=$true}
        if(-not $rejected){throw 'Wire blocked query unexpectedly succeeded'};return $true
    }
    $rows=@(Resolve-DnsName $Name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
    if($rows.Count -eq 0 -or $rows.Count -gt 32){throw 'Wire answer bound'}
    $count=0;foreach($row in $rows){$address=$null;$property=$row.PSObject.Properties['IPAddress'];if($null -ne $property -and $property.Value -is [string] -and [Net.IPAddress]::TryParse($property.Value,[ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){$count++}}
    if($count -eq 0){throw 'Wire answer missing'};return $count
}
function Measure-NativeDNSWire([object]$State) {
    $State.phase='plaintext-block';Assert-NativeDNSWireFirewall;Add-NativeDNSWireRule $State 'dns' 'UDP';Add-NativeDNSWireRule $State 'dns' 'TCP';$State.flags.plaintextBlocked=$true
    $State.phase='ordinary-query';[void](Invoke-NativeDNSWireQuery 'example.net');$State.flags.ordinaryQueryPassed=$true
    $State.phase='capture-stop';Stop-NativeDNSWireCapture $State
    $State.phase='capture-file';Measure-NativeDNSWireFile $State 'etl'
    $State.phase='capture-conversion';[void](Invoke-NativeDNSWireTool $State @('etl2pcap',$State.etl,'--out',$State.pcap))
    $State.phase='decode';$bytes=Read-NativeDNSWireCapture $State
    $decoded=(Invoke-NativeDNSWireProcess $State $State.node @($State.decoder) $bytes) | ConvertFrom-Json
    if($decoded.code -is [string] -and $decoded.code -cmatch '^[a-z0-9-]{1,48}$'){$State.decoderCode=$decoded.code}else{$State.decoderCode='invalid-report'}
    if($decoded.schemaVersion -ne 1 -or $decoded.outcome -cne 'decoded' -or $State.decoderCode -cne 'none' -or $null -eq $decoded.evidence){throw 'Wire decoder refused'}
    $e=$decoded.evidence
    if($e.schemaVersion -ne 1 -or $e.observation -cne 'tls-observed' -or $e.plaintextPackets -ne 0 -or @($e.flows).Count -eq 0 -or @($e.flows).Count -gt 32 -or $e.productionQualificationComplete -isnot [bool] -or $e.productionQualificationComplete){throw 'Wire TLS evidence missing'}
    foreach($flow in $e.flows){
        $mask=switch -CaseSensitive ($flow.provider){'google-v4'{1}'quad9-v4'{2}'google-v6'{4}'quad9-v6'{8}default{throw 'Wire provider label'}}
        if($flow.clientHello -isnot [bool] -or -not $flow.clientHello -or $flow.serverHello -isnot [bool] -or -not $flow.serverHello -or $flow.outboundEncryptedRecords -lt 0 -or $flow.outboundEncryptedRecords -gt 4194304 -or $flow.inboundEncryptedRecords -lt 0 -or $flow.inboundEncryptedRecords -gt 4194304){throw 'Wire flow shape'}
        $State.providers=$State.providers -bor $mask;$State.outRecords+=$flow.outboundEncryptedRecords;$State.inRecords+=$flow.inboundEncryptedRecords;$State.tlsFlows++
    }
    $State.flags.tlsObserved=$true
    try{
        $State.phase='tls-block';Add-NativeDNSWireRule $State 'tls' 'TCP';$State.flags.tlsBlocked=$true
        $State.phase='blocked-query';[void](Invoke-NativeDNSWireQuery 'example.org' -ExpectFailure);$State.flags.blockedQueryRejected=$true
    }catch{if($State.failurePhase -ceq 'none'){$State.failurePhase=$State.phase};throw}finally{
        $State.phase='tls-unblock';Remove-NativeDNSWireRules $State 'tls';$State.flags.tlsBlockRemoved=$true
    }
    $State.phase='resumed-query';[void](Invoke-NativeDNSWireQuery 'example.org');$State.flags.resumedQueryPassed=$true
}
function Complete-NativeDNSWireCleanup([object]$State) {
    $State.cleanupAttempted=$true
    $State.phase='cleanup-stop';Stop-NativeDNSWireCapture $State
    if($null -eq $State.before){throw 'Wire original state missing'}
    $State.phase='cleanup-state';Assert-DNSAcceptanceRestored $State.before (Read-DNSAcceptanceState);$State.flags.originalStateVerified=$true
    $State.phase='cleanup-rules';Remove-NativeDNSWireRules $State 'tls';Remove-NativeDNSWireRules $State 'dns';$State.flags.rulesRemoved=$true
    $State.phase='cleanup-filters'
    $listing=Invoke-NativeDNSWireTool $State @('filter','list');$rows=@(Get-NativeDNSWireFilterRows $listing)
    if($rows.Count -gt 0){
        $remaining=@($State.filters | Where-Object {$planName=$_.name;@($rows | Where-Object {$_.name -ceq $planName}).Count -eq 1})
        if($remaining.Count -ne $rows.Count){throw 'Wire cleanup filter ownership'}
        Assert-NativeDNSWireFilters $listing $remaining
        # The documented remove command clears the set. Admit it only after
        # proving the complete current set consists of these owned filters.
        [void](Invoke-NativeDNSWireTool $State @('filter','remove'))
    }
    Assert-NativeDNSWireEmptyFilters (Invoke-NativeDNSWireTool $State @('filter','list'));$State.flags.filtersRemoved=$true
    $State.phase='cleanup-resolver';[void](Invoke-NativeDNSWireQuery 'example.com');$State.flags.originalResolverPassed=$true
    $State.phase='complete';$State.cleanupCompleted=$true
}
function Get-NativeDNSWireSummary([object]$State) {
    $passed=($State.flags.Count -eq 16 -and @($State.flags.Values | Where-Object {$_ -isnot [bool] -or -not $_}).Count -eq 0 -and $State.processes -eq $State.joined -and -not $State.processFailed -and $State.decoderCode -ceq 'none' -and $State.outRecords -gt 0 -and $State.inRecords -gt 0)
    return @{processFailureCode=$State.processFailureCode;failureExitCode=$State.failureExitCode;failureStdoutChars=$State.failureStdoutChars;failureStderrChars=$State.failureStderrChars;failureElapsedMilliseconds=$State.failureElapsedMilliseconds;captureFileCode=$State.captureFileCode;etlBytes=$State.etlBytes;pcapBytes=$State.pcapBytes;filterRows=$State.filterRows;filterCode=$State.filterCode;outcome=$(if($passed){'passed'}else{'failed'});phase=$State.phase;failurePhase=$State.failurePhase;decoderCode=$State.decoderCode;controls=$State.flags;toolProcesses=$State.processes;toolProcessesJoined=$State.joined;toolFailure=$State.processFailed;tlsFlows=$State.tlsFlows;outboundEncryptedRecords=$State.outRecords;inboundEncryptedRecords=$State.inRecords;providerMask=$State.providers;rawCapturePublished=$false;productionQualificationComplete=$false}
}
