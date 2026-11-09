# Pure closed public endpoint projection. No certificate/name/path is admitted.
function New-DoHIPAuthorityEndpoint([int]$Mask,[string]$Code='not-inspected') {return @{schemaVersion=1;endpointMask=$Mask;outcome='failed';code=$Code;httpStatus=0;httpStage='not-inspected';tlsAuthorized=$false;ipIdentityVerified=$false;certificateMask=0;responseValidated=$false;socketStarted=$false;closed=$false;peerEnded=$false;socketJoined=$true;productionQualificationComplete=$false}}
function Get-DoHIPAuthorityEndpoint([string]$Text,[int]$Mask) {
    $bad=New-DoHIPAuthorityEndpoint $Mask 'invalid';if($Mask -cnotin @(1,2) -or $Text.Length -gt 4096){return $bad};try{$v=$Text | ConvertFrom-Json -ErrorAction Stop}catch{return $bad}
    $flags=@('tlsAuthorized','ipIdentityVerified','responseValidated','socketStarted','closed','peerEnded','socketJoined','productionQualificationComplete');$keys=@('schemaVersion','endpointMask','outcome','code','certificateMask','httpStatus','httpStage')+$flags
    if($v -isnot [pscustomobject] -or @($v.PSObject.Properties).Count -ne 15 -or @($v.PSObject.Properties.Name | Where-Object {$_ -cnotin $keys}).Count -ne 0 -or $v.schemaVersion -isnot [int] -or $v.schemaVersion -ne 1 -or $v.endpointMask -isnot [int] -or $v.endpointMask -ne $Mask -or $v.outcome -cnotin @('passed','failed') -or $v.code -cnotin @('none','environment','network','tls','identity','http','response','bound','timeout','close')){return $bad}
    foreach($key in $flags){if($v.$key -isnot [bool]){return $bad}};$allowed=$Mask*5
    if($v.certificateMask -isnot [int] -or $v.certificateMask -lt 0 -or $v.certificateMask -gt 15 -or ($v.certificateMask -band (15 -bxor $allowed)) -ne 0 -or $v.productionQualificationComplete -or $v.socketJoined -ne ((-not $v.socketStarted) -or $v.closed)){return $bad}
    if(($v.tlsAuthorized -and -not $v.socketStarted) -or ($v.certificateMask -ne 0 -and (-not $v.tlsAuthorized -or -not $v.ipIdentityVerified)) -or ($v.ipIdentityVerified -and ((-not $v.tlsAuthorized) -or ($v.certificateMask -band $Mask) -eq 0)) -or ($v.responseValidated -and -not $v.ipIdentityVerified) -or (($v.closed -or $v.peerEnded) -and -not $v.socketStarted)){return $bad}
    if($v.httpStatus -isnot [int] -or $v.httpStatus -cnotin @(-1,0,200,301,302,303,307,308,400,401,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,421,425,426,429,431,451,500,501,502,503,504,505) -or $v.httpStage -cnotin @('not-inspected','incomplete','body','header-bound','headers','status','duplicate-header','framing','length','transfer','complete')){return $bad}
    if($v.httpStage -ceq 'not-inspected' -and $v.httpStatus -ne 0){return $bad};if($v.responseValidated -and ($v.httpStatus -ne 200 -or $v.httpStage -cne 'complete')){return $bad}
    $good=($v.tlsAuthorized -and $v.ipIdentityVerified -and $v.responseValidated -and $v.socketStarted -and $v.closed -and $v.peerEnded -and $v.socketJoined)
    if(($v.outcome -ceq 'passed') -ne ($v.code -ceq 'none') -or ($v.outcome -ceq 'passed' -and -not $good)){return $bad}
    $r=New-DoHIPAuthorityEndpoint $Mask $v.code;$r.outcome=$v.outcome;$r.httpStatus=$v.httpStatus;$r.httpStage=$v.httpStage;$r.certificateMask=$v.certificateMask;foreach($key in $flags){$r[$key]=$v.$key};return $r
}
function Test-DoHIPAuthorityCoverage([object[]]$Rows) {
    if($Rows.Count -ne 2 -or $Rows[0].endpointMask -ne 1 -or $Rows[1].endpointMask -ne 2){return $false}
    foreach($row in $Rows){if($row.outcome -cne 'passed' -or $row.code -cne 'none' -or -not $row.tlsAuthorized -or -not $row.ipIdentityVerified -or -not $row.responseValidated -or -not $row.socketStarted -or -not $row.closed -or -not $row.peerEnded -or -not $row.socketJoined){return $false}}
    return (($Rows[0].certificateMask -bor $Rows[1].certificateMask) -eq 15)
}
