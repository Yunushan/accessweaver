# Pure binding/projection helpers. The guarded collector supplies fresh state.
function New-DoHIPAuthorityBinding {
    return @{schemaVersion=1;mode='unbound';sourceCommit='';policySHA256='';prerequisiteSHA256='';providerMask=0;readbackVerified=$false}
}
function Test-DoHIPAuthorityBinding([object]$Binding,[string]$SourceCommit) {
    $keys=@('schemaVersion','mode','sourceCommit','policySHA256','prerequisiteSHA256','providerMask','readbackVerified')
    if($Binding -is [Collections.IDictionary]){$names=@($Binding.Keys)}elseif($Binding -is [pscustomobject]){$names=@($Binding.PSObject.Properties.Name)}else{return $false}
    if($names.Count -ne 7 -or @($names | Where-Object {$_ -cnotin $keys}).Count -ne 0){return $false}
    return (($Binding.schemaVersion -is [int] -or $Binding.schemaVersion -is [long]) -and $Binding.schemaVersion -eq 1 -and $Binding.mode -ceq 'configured-ip-authority' -and $Binding.sourceCommit -is [string] -and $Binding.sourceCommit -cmatch '^[a-f0-9]{40}$' -and $Binding.sourceCommit -ceq $SourceCommit -and $Binding.policySHA256 -is [string] -and $Binding.policySHA256 -ceq 'b9df8a688891af4b185a3d6835f9c02b60e765aa485e6cb9c1dced1358fd2198' -and $Binding.prerequisiteSHA256 -is [string] -and $Binding.prerequisiteSHA256 -ceq 'f283959a6b8267a5a576e2d0b1725728d9647276db8421242c3f3b54716c703c' -and ($Binding.providerMask -is [int] -or $Binding.providerMask -is [long]) -and $Binding.providerMask -eq 15 -and $Binding.readbackVerified -is [bool] -and $Binding.readbackVerified)
}
function New-DoHVerifiedIPAuthorityBinding([object]$Before,[object]$Current,[string]$SourceCommit,[object]$PrerequisiteSHA256) {
    if($SourceCommit -cnotmatch '^[a-f0-9]{40}$' -or $PrerequisiteSHA256 -isnot [string] -or $PrerequisiteSHA256 -cne 'f283959a6b8267a5a576e2d0b1725728d9647276db8421242c3f3b54716c703c'){throw 'IP-authority prerequisite binding refused'}
    Assert-DNSAcceptanceConfigured $Before $Current 'doh'
    $index=Get-DNSAcceptanceIndex $Current;$text=[Text.StringBuilder]::new()
    foreach($address in @('8.8.8.8','9.9.9.9','2001:4860:4860::8888','2620:fe::fe')){
        $entry=$index.doh[$address]
        [void]$text.Append($address+'|'+$entry.template+'|0|1'+[char]10)
    }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($text.ToString());$algorithm=[Security.Cryptography.SHA256]::Create()
    try{$digest=[BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
    $binding=@{schemaVersion=1;mode='configured-ip-authority';sourceCommit=$SourceCommit;policySHA256=$digest;prerequisiteSHA256=$PrerequisiteSHA256;providerMask=15;readbackVerified=$true}
    if(-not (Test-DoHIPAuthorityBinding $binding $SourceCommit)){throw 'IP-authority configured policy binding refused'}
    return $binding
}
function Get-DoHIPAuthorityTlsEvidence([string]$Text,[object]$ExpectedBinding,[string]$SourceCommit) {
    $bad=New-DoHNetEventTlsEvidence 'invalid';$bad.observation='refused'
    if(-not (Test-DoHIPAuthorityBinding $ExpectedBinding $SourceCommit) -or $Text.Length -gt 16384){return $bad}
    try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $keys=@('schemaVersion','outcome','code','evidence','identityBinding')
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 5 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or -not (Test-DoHIPAuthorityBinding $v.identityBinding $SourceCommit)){return $bad}
    $legacy=@{schemaVersion=$v.schemaVersion;outcome=$v.outcome;code=$v.code;evidence=$v.evidence} | ConvertTo-Json -Depth 8 -Compress
    return (Get-DoHNetEventTlsEvidence $legacy)
}
