# Called by the guarded, source-bound hosted port probe.
function New-FixtureDNSCryptQuestion([string]$Name) {
    if($Name -cnotmatch '\Aaw-[a-f0-9]{32}\.invalid\z'){throw 'Invalid fixture DNS question'}
    $question=[Collections.Generic.List[byte]]::new()
    foreach($label in $Name.Split('.')){
        $question.Add([byte]$label.Length)
        $question.AddRange([Text.Encoding]::ASCII.GetBytes($label))
    }
    $question.AddRange([byte[]]@(0,0,1,0,1))
    return ,$question.ToArray()
}

function Test-FixtureDNSCryptAnswer([byte[]]$Packet,[byte[]]$Request) {
    if($Request.Length -lt 17 -or $Packet.Length -lt ($Request.Length+16) -or $Packet.Length -gt 512 -or
       $Packet[0] -ne $Request[0] -or $Packet[1] -ne $Request[1] -or
       ($Packet[2] -band 0xfa) -ne 0x80 -or ($Packet[3] -band 0x0f) -ne 0 -or
       $Packet[4] -ne 0 -or $Packet[5] -ne 1 -or $Packet[6] -ne 0 -or $Packet[7] -ne 1 -or
       $Packet[8] -ne 0 -or $Packet[9] -ne 0 -or $Packet[10] -ne 0 -or $Packet[11] -ne 0){return $false}
    for($i=12;$i -lt $Request.Length;$i++){if($Packet[$i] -ne $Request[$i]){return $false}}
    $answer=$Request.Length
    if($Packet[$answer] -eq 0xc0 -and $Packet[$answer+1] -eq 12){$answer+=2}
    else{
        $nameLength=$Request.Length-16
        for($i=0;$i -lt $nameLength;$i++){
            if($answer+$i -ge $Packet.Length -or $Packet[$answer+$i] -ne $Request[12+$i]){return $false}
        }
        $answer+=$nameLength
    }
    return ($Packet.Length -eq ($answer+14) -and
        ($Packet[$answer..($answer+3)] -join ',') -ceq '0,1,0,1' -and
        ($Packet[($answer+8)..($answer+13)] -join ',') -ceq '0,4,192,0,2,42')
}

function New-FixtureDNSCryptRequest([string]$Name) {
    $question=New-FixtureDNSCryptQuestion $Name
    $transaction=[byte[]]::new(2)
    $random=[Security.Cryptography.RandomNumberGenerator]::Create()
    try{$random.GetBytes($transaction)}finally{$random.Dispose()}
    return ,[byte[]]($transaction+@(1,0,0,1,0,0,0,0,0,0)+$question)
}

function Test-FixtureDNSCryptUDP([Net.IPAddress]$Address,[string]$Name) {
    $request=New-FixtureDNSCryptRequest $Name
    $client=$null
    try{
        $client=[Net.Sockets.UdpClient]::new($Address.AddressFamily)
        $client.Client.ReceiveTimeout=500
        $client.Connect($Address,53)
        if($client.Send($request,$request.Length) -ne $request.Length){return $false}
        $sender=[Net.IPEndPoint]::new($Address,0)
        $packet=$client.Receive([ref]$sender)
        return Test-FixtureDNSCryptAnswer $packet $request
    }catch{
        return $false
    }finally{if($null -ne $client){$client.Dispose()}}
}

function Test-FixtureDNSCryptTCP([Net.IPAddress]$Address,[string]$Name) {
    $request=New-FixtureDNSCryptRequest $Name
    $client=$null
    try{
        $client=[Net.Sockets.TcpClient]::new($Address.AddressFamily)
        $connect=$client.ConnectAsync($Address,53)
        if(-not $connect.Wait(700)){return $false}
        $stream=$client.GetStream();$stream.ReadTimeout=700;$stream.WriteTimeout=700
        $frame=[byte[]](@(0,$request.Length)+$request)
        $stream.Write($frame,0,$frame.Length)
        $reader=[IO.BinaryReader]::new($stream)
        try{
            $header=$reader.ReadBytes(2)
            if($header.Length -ne 2){return $false}
            $length=256*[int]$header[0]+[int]$header[1]
            if($length -lt 12 -or $length -gt 512){return $false}
            $packet=$reader.ReadBytes($length)
            return ($packet.Length -eq $length -and (Test-FixtureDNSCryptAnswer $packet $request))
        }finally{$reader.Dispose()}
    }catch{return $false}
    finally{if($null -ne $client){$client.Dispose()}}
}

function Read-FixtureDNSCryptTCP {
    $rows=@(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetTCPConnection' -Filter 'LocalPort = 53 AND State = 2' -Property LocalAddress,OwningProcess -ErrorAction Stop -WarningAction Stop |
        Select-Object -First 4097)
    if($rows.Count -gt 4096){throw 'Fixture TCP inventory exceeded its limit'}
    foreach($row in $rows){
        $address=$null
        if($row.LocalAddress -isnot [string] -or -not [Net.IPAddress]::TryParse($row.LocalAddress,[ref]$address)){
            throw 'Fixture TCP inventory differs'
        }
        if($address.IsIPv4MappedToIPv6){$address=$address.MapToIPv4()}
        $literal=$address.ToString().Split('%')[0]
        if($literal -cin @('127.0.0.1','::1','0.0.0.0','::')){
            if($row.OwningProcess -isnot [uint32]){throw 'Fixture TCP owner differs'}
            [pscustomobject]@{localAddress=$literal;owner=$row.OwningProcess}
        }
    }
}

function Test-FixtureDNSCryptOwner([uint32]$ProcessId,[string[]]$Baseline) {
    $inventory=@(Read-FixtureUDP53)
    $remaining=@($inventory | Where-Object {$_.scope -cin @('ipv4-wildcard','ipv6-wildcard')} |
        ForEach-Object {$_.scope+'='+$_.owner} | Sort-Object)
    if(($remaining -join ',') -cne ($Baseline -join ',')){return $false}
    $udp=@($inventory | Where-Object {$_.scope -cin @('ipv4-loopback','ipv6-loopback')})
    if($udp.Count -ne 2 -or @($udp | Where-Object owner -NE $ProcessId).Count -or
       @($udp.scope | Sort-Object -Unique).Count -ne 2){return $false}
    $tcp=@(Read-FixtureDNSCryptTCP)
    return ($tcp.Count -eq 2 -and @($tcp.localAddress | Sort-Object -Unique).Count -eq 2 -and
        @($tcp | Where-Object {$_.owner -ne $ProcessId -or $_.localAddress -cnotin @('127.0.0.1','::1')}).Count -eq 0)
}

function Invoke-FixtureDNSCryptEngine([string]$Project,[string]$Architecture,$Evidence) {
    $work=$null;$process=$null;$output=$null;$errors=$null
    $baseline=@(Read-FixtureUDP53 | ForEach-Object {$_.scope+'='+$_.owner} | Sort-Object)
    try{
        $Evidence.stage='stage-bundle'
        $driver=Join-Path $Project 'scripts\test-native-doh.ps1'
        $tokens=$null;$issues=$null
        $ast=[Management.Automation.Language.Parser]::ParseFile($driver,[ref]$tokens,[ref]$issues)
        if($issues.Count){throw 'Pinned DNSCrypt source unavailable'}
        foreach($function in @('Assert-NativeOrdinaryPath','New-NativeDNSCryptBundle')){
            $nodes=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $function})
            if($nodes.Count -ne 1){throw 'Pinned DNSCrypt function unavailable'}
            . ([scriptblock]::Create($nodes[0].Extent.Text))
        }
        . (Join-Path $Project 'scripts\native-doh-scenario.ps1')
        $temp=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
        Assert-NativeOrdinaryPath $temp
        $target=Join-Path $temp ('accessweaver-dnscrypt-engine-'+[guid]::NewGuid().ToString('N'))
        [void](New-Item -Path $target -ItemType Directory -ErrorAction Stop)
        $work=$target
        $component=New-NativeDNSCryptBundle $work $Architecture
        $Evidence.binarySHA256=$component.binarySHA256
        $directory=$component.directory
        $executable=Join-Path $directory 'dnscrypt-proxy.exe'
        if((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Evidence.binarySHA256){
            throw 'Pinned DNSCrypt fixture binary changed'
        }
        $config=Join-Path $directory 'listener-fixture.toml'
        $cloaks=Join-Path $directory 'listener-fixture.txt'
        $records=@(foreach($i in 1..4){'aw-'+[guid]::NewGuid().ToString('N')+'.invalid'})
        [IO.File]::WriteAllLines($cloaks,[string[]]@($records | ForEach-Object {$_+' 192.0.2.42'}),[Text.Encoding]::ASCII)
        [IO.File]::WriteAllLines($config,[string[]]@(
            "listen_addresses = ['127.0.0.1:53','[::1]:53']"
            'offline_mode = true'
            'netprobe_timeout = 0'
            'cache = false'
            'block_unqualified = false'
            'block_undelegated = false'
            "cloaking_rules = 'listener-fixture.txt'"
        ),[Text.Encoding]::ASCII)
        $Evidence.stage='port-recheck'
        $now=@(Read-FixtureUDP53 | ForEach-Object {$_.scope+'='+$_.owner} | Sort-Object)
        if(($now -join ',') -cne ($baseline -join ',') -or @(Read-FixtureDNSCryptTCP).Count){
            throw 'Fixture port inventory changed or TCP is already occupied'
        }
        $Evidence.stage='start-engine'
        $start=[Diagnostics.ProcessStartInfo]::new()
        $start.FileName=$executable
        $start.Arguments='-config listener-fixture.toml'
        $start.WorkingDirectory=$directory
        $start.UseShellExecute=$false
        $start.CreateNoWindow=$true
        $start.RedirectStandardOutput=$true
        $start.RedirectStandardError=$true
        $process=[Diagnostics.Process]::Start($start)
        $output=$process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
        $errors=$process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $Evidence.stage='loopback-owner'
        do{
            if($process.HasExited){throw 'Pinned DNSCrypt fixture exited during startup'}
            $Evidence.loopbackOwnersVerified=Test-FixtureDNSCryptOwner ([uint32]$process.Id) $baseline
            if($Evidence.loopbackOwnersVerified){break}
            Start-Sleep -Milliseconds 200
        }while($clock.Elapsed.TotalSeconds -lt 15)
        if(-not $Evidence.loopbackOwnersVerified){throw 'Fixture listener ownership could not be verified'}
        $Evidence.stage='loopback-answers'
        $loopback=[Net.IPAddress]::Loopback
        $loopback6=[Net.IPAddress]::IPv6Loopback
        $Evidence.udp4=Test-FixtureDNSCryptUDP $loopback $records[0]
        $Evidence.udp6=Test-FixtureDNSCryptUDP $loopback6 $records[1]
        $Evidence.tcp4=Test-FixtureDNSCryptTCP $loopback $records[2]
        $Evidence.tcp6=Test-FixtureDNSCryptTCP $loopback6 $records[3]
        $Evidence.loopbackOwnersConfirmedAfter=$false
        if(-not $process.HasExited){
            $Evidence.loopbackOwnersConfirmedAfter=Test-FixtureDNSCryptOwner ([uint32]$process.Id) $baseline
        }
        if(-not ($Evidence.udp4 -and $Evidence.udp6 -and $Evidence.tcp4 -and $Evidence.tcp6 -and $Evidence.loopbackOwnersConfirmedAfter)){
            throw 'Fixture loopback answers could not be verified'
        }
        $Evidence.stage='complete'
    }finally{
        if($null -ne $process){
            try{
                if(-not $process.HasExited){$process.Kill()}
                if(-not $process.WaitForExit(5000)){throw 'Fixture DNSCrypt process exit was not confirmed'}
                $Evidence.processJoined=$true
                $tasks=@($output,$errors | Where-Object {$null -ne $_})
                foreach($task in $tasks){if(-not $task.Wait(2000)){throw 'Fixture process pipe did not close'}}
            }finally{$process.Dispose()}
        }
        if($work -and ($null -eq $process -or $Evidence.processJoined)){
            Assert-NativeOrdinaryPath $work
            $bundle=Join-Path $work 'upstream-dnscrypt'
            Assert-NativeOrdinaryPath $bundle
            if([IO.Directory]::Exists($bundle)){
                foreach($leaf in @('upstream.zip','dnscrypt-proxy.exe','example-dnscrypt-proxy.toml','listener-fixture.toml','listener-fixture.txt')){
                    [IO.File]::Delete((Join-Path $bundle $leaf))
                }
                [IO.Directory]::Delete($bundle)
            }
            [IO.Directory]::Delete($work)
            $Evidence.privateFilesRemoved=$true
        }
        $after=@(Read-FixtureUDP53 | ForEach-Object {$_.scope+'='+$_.owner} | Sort-Object)
        $Evidence.originalUDPInventoryRestored=($after -join ',') -ceq ($baseline -join ',')
    }
}
