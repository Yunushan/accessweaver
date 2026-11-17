# Only invoked by the guarded hosted DNSCrypt port probe.
function New-FixtureServiceRoot {
    $user=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{
        if(-not ([Security.Principal.WindowsPrincipal]::new($user)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
            throw 'Hosted service probe requires an administrator token'
        }
        $programData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
        if(-not $programData -or [IO.Path]::GetFullPath($env:ProgramData) -ine $programData){
            throw 'Fixture ProgramData identity differs'
        }
        $root=Join-Path $programData 'AccessWeaver'
        Assert-NativeOrdinaryPath $root
        if((Test-Path -LiteralPath $root) -or @(Get-CimInstance -ClassName Win32_Service -Filter "Name LIKE 'AccessWeaver-%'" -Property Name -ErrorAction Stop).Count){
            throw 'Preexisting AccessWeaver state refused'
        }
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($user.User)
        $acl.SetAccessRuleProtection($true,$false)
        foreach($id in @($user.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique){
            $sid=[Security.Principal.SecurityIdentifier]::new($id)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        [void][IO.Directory]::CreateDirectory($root,$acl)
        Assert-NativeOrdinaryPath $root
        $readback=Get-Acl -LiteralPath $root -ErrorAction Stop
        $expected=@($user.User.Value,'S-1-5-18','S-1-5-32-544' | Select-Object -Unique)
        $observed=@($readback.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if(-not $readback.AreAccessRulesProtected -or $readback.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $user.User.Value -or
           $observed.Count -ne $expected.Count -or
           @($expected | Where-Object {$_ -notin $observed.IdentityReference.Value}).Count -or
           @($observed | Where-Object {$_.IsInherited -or $_.AccessControlType -ne 'Allow' -or $_.FileSystemRights -ne 'FullControl' -or
               [int]$_.InheritanceFlags -ne 3 -or $_.PropagationFlags -ne 'None'}).Count){
            throw 'Fixture machine directory ACL differs'
        }
        return $root
    }finally{$user.Dispose()}
}

function New-FixtureServiceRecord([string]$Root,[string]$Controller,[string]$ExpectedHash,[string]$Executable,[string]$Directory) {
    $source=[IO.Path]::GetFullPath($Controller)
    $workspace=[IO.Path]::GetFullPath($env:GITHUB_WORKSPACE).TrimEnd('\')+'\'
    Assert-NativeOrdinaryPath $source
    if(-not $source.StartsWith($workspace,[StringComparison]::OrdinalIgnoreCase) -or
       $ExpectedHash -cnotmatch '\A[a-f0-9]{64}\z' -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedHash){
        throw 'Fixture service controller differs from the native build'
    }
    $services=Join-Path $Root 'services'
    $logs=Join-Path $Root 'logs'
    [void][IO.Directory]::CreateDirectory($services)
    [void][IO.Directory]::CreateDirectory($logs)
    $hostImage=Join-Path $services 'fixture-host.exe'
    [IO.File]::Copy($source,$hostImage)
    if((Get-FileHash -LiteralPath $hostImage -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedHash){
        throw 'Sealed service host differs from the native build'
    }
    $nonce=[guid]::NewGuid().ToString('N')
    $name='AccessWeaver-dnscrypt-probe-'+$nonce
    $config=Join-Path $services 'fixture.json'
    $log=Join-Path $logs 'fixture.log'
    $options=@{name=$name;binary=$Executable;args=@('-config','listener-fixture.toml');directory=$Directory;logPath=$log}
    [IO.File]::WriteAllText($config,($options | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $command='"'+$hostImage+'" service-host "'+$config+'" --instance='+$nonce
    return @{name=$name;command=$command;hostImage=$hostImage;engineImage=$Executable}
}

function Get-FixtureServiceRegistration($Record) {
    if($Record.name -cnotmatch '\AAccessWeaver-dnscrypt-probe-[a-f0-9]{32}\z'){throw 'Invalid fixture service identity'}
    $rows=@(Get-CimInstance -ClassName Win32_Service -Filter ("Name = '"+$Record.name+"'") -Property Name,PathName,ProcessId,StartName,StartMode,State -ErrorAction Stop -WarningAction Stop)
    if($rows.Count -eq 0){return}
    $service=$rows[0]
    if($rows.Count -ne 1 -or $service.Name -cne $Record.name -or $service.PathName -cne $Record.command -or
       $service.StartName -notin @('LocalSystem','.\LocalSystem','NT AUTHORITY\SYSTEM') -or $service.StartMode -cne 'Manual'){
        throw 'Fixture service registration differs'
    }
    return $service
}

function Get-FixtureServiceChild($Record) {
    $service=Get-FixtureServiceRegistration $Record
    if($null -eq $service -or $service.State -cne 'Running' -or $service.ProcessId -isnot [uint32] -or $service.ProcessId -eq 0){return}
    $owner=$service.ProcessId
    $fields=@('ProcessId','ParentProcessId','ExecutablePath','CreationDate')
    $hosts=@(Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = "+$owner) -Property $fields -ErrorAction Stop)
    $children=@(Get-CimInstance -ClassName Win32_Process -Filter ("ParentProcessId = "+$owner) -Property $fields -ErrorAction Stop | Select-Object -First 2)
    if($hosts.Count -ne 1 -or $children.Count -ne 1){return}
    $hostProcess=$hosts[0];$child=$children[0]
    if($hostProcess.ProcessId -ne $owner -or $hostProcess.ExecutablePath -ine $Record.hostImage -or
       $hostProcess.CreationDate -isnot [datetime] -or $child.ParentProcessId -ne $owner -or
       $child.ProcessId -isnot [uint32] -or $child.ProcessId -eq 0 -or $child.ExecutablePath -ine $Record.engineImage -or
       $child.CreationDate -isnot [datetime] -or $child.CreationDate -lt $hostProcess.CreationDate){return}
    return @{id=$child.ProcessId; identity=('{0}:{1}:{2}:{3}' -f $owner,$hostProcess.CreationDate.Ticks,$child.ProcessId,$child.CreationDate.Ticks)}
}

function Remove-FixtureService($Record) {
    $service=Get-FixtureServiceRegistration $Record
    if($null -eq $service){return}
    if($service.State -cne 'Stopped'){
        $controller=Get-Service -Name $Record.name -ErrorAction Stop
        try{
            if($controller.Status -ne 'StopPending'){Stop-Service -InputObject $controller -ErrorAction Stop}
            $controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
        }finally{$controller.Dispose()}
    }
    $service=Get-FixtureServiceRegistration $Record
    if($null -eq $service){return}
    if($service.State -cne 'Stopped' -or $service.ProcessId -ne 0){throw 'Fixture service did not stop'}
    if((Invoke-CimMethod -InputObject $service -MethodName Delete -ErrorAction Stop).ReturnValue -ne 0 -or
       (Get-FixtureServiceRegistration $Record)){throw 'Fixture service removal was not confirmed'}
}

function Remove-FixtureServiceRoot([string]$Root) {
    foreach($name in @('services','logs')){
        $folder=Join-Path $Root $name
        Assert-NativeOrdinaryPath $folder
        if(-not [IO.Directory]::Exists($folder)){continue}
        $files=if($name -ceq 'services'){@('fixture-host.exe','fixture.json')}else{@('fixture.log','fixture.log.1','fixture.log.2')}
        foreach($leaf in $files){[IO.File]::Delete((Join-Path $folder $leaf))}
        [IO.Directory]::Delete($folder)
    }
    [IO.Directory]::Delete($Root)
}
