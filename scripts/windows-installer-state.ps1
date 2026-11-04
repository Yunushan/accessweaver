# Pure diagnostics for exact installer-state comparisons. No OS queries or writes.
function Get-InstallerStateTextHash([string]$Text) {
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($algorithm.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($Text))).Replace('-','').ToLowerInvariant()} finally {$algorithm.Dispose()}
}
function Get-InstallerStateValueHash($Value) {
    return Get-InstallerStateTextHash (ConvertTo-Json -InputObject $Value -Depth 16 -Compress)
}
function New-InstallerStateRows([object[]]$Rows,[string]$Domain) {
    if($Rows.Count -gt 10000){throw 'Installer state diagnostics exceed row budget'}
    $map=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($row in $Rows){
        if($null -eq $row){throw 'Installer state diagnostics require complete rows'}
        if($Domain -ceq 'dns'){
            if($null -eq $row.InterfaceIndex -or $null -eq $row.AddressFamily){throw 'DNS state row has no identity'}
            $key=([string]$row.InterfaceIndex)+'|'+([string]$row.AddressFamily)
        }else{
            $key=[string]$row.name
            if([string]::IsNullOrWhiteSpace($key)){throw 'Installer state row has no identity'}
        }
        if($map.ContainsKey($key)){throw 'Installer state diagnostics require unique row identities'}
        $map.Add($key,$row)
    }
    return ,$map
}
function Compare-InstallerState([string]$Before,[string]$After) {
    if($Before.Length -gt 16MB -or $After.Length -gt 16MB){throw 'Installer state diagnostics exceed JSON budget'}
    $left=$Before | ConvertFrom-Json;$right=$After | ConvertFrom-Json
    $domains=[ordered]@{}
    foreach($domain in @('services','firewall','dns')){
        if($null -eq $left.PSObject.Properties[$domain] -or $null -eq $right.PSObject.Properties[$domain]){throw 'Incomplete installer state snapshot'}
        $oldRows=@($left.$domain);$newRows=@($right.$domain)
        $oldMap=New-InstallerStateRows $oldRows $domain;$newMap=New-InstallerStateRows $newRows $domain
        $changes=[Collections.Generic.List[object]]::new();$added=0;$removed=0;$changed=0;$serialization=0
        $keys=@(@($oldMap.Keys)+@($newMap.Keys) | Sort-Object -CaseSensitive -Unique)
        foreach($key in $keys){
            $hasOld=$oldMap.ContainsKey($key);$hasNew=$newMap.ContainsKey($key)
            $oldHash=$null;$newHash=$null;$fields=@();$kind=$null
            if($hasOld){$oldHash=Get-InstallerStateValueHash $oldMap[$key]}
            if($hasNew){$newHash=Get-InstallerStateValueHash $newMap[$key]}
            if(-not $hasOld){$added++;$kind='added'}
            elseif(-not $hasNew){$removed++;$kind='removed'}
            elseif($oldHash -cne $newHash){
                $properties=@(@($oldMap[$key].PSObject.Properties.Name)+@($newMap[$key].PSObject.Properties.Name) | Sort-Object -CaseSensitive -Unique)
                foreach($property in $properties){
                    $a=$oldMap[$key].PSObject.Properties[$property];$b=$newMap[$key].PSObject.Properties[$property]
                    if($null -eq $a -or $null -eq $b -or (Get-InstallerStateValueHash $a.Value) -cne (Get-InstallerStateValueHash $b.Value)){$fields+=,$property}
                }
                if($fields.Count){$changed++;$kind='changed'}else{$serialization++;$kind='row-serialization'}
            }
            if($kind -and $changes.Count -lt 32){
                $classification='other'
                if($domain -cne 'dns' -and $key -match '^AccessWeaver-'){$classification='product-prefix'}
                $changes.Add([ordered]@{identitySHA256=(Get-InstallerStateTextHash $key);kind=$kind;classification=$classification;beforeSHA256=$oldHash;afterSHA256=$newHash;fields=$fields})
            }
        }
        $oldDomainHash=Get-InstallerStateValueHash $oldRows;$newDomainHash=Get-InstallerStateValueHash $newRows
        $domains[$domain]=[ordered]@{beforeSHA256=$oldDomainHash;afterSHA256=$newDomainHash;serializedEqual=($oldDomainHash -ceq $newDomainHash);beforeRows=$oldRows.Count;afterRows=$newRows.Count;added=$added;removed=$removed;changed=$changed;rowSerializationChanges=$serialization;recordOrderingChanged=($oldDomainHash -cne $newDomainHash -and $added -eq 0 -and $removed -eq 0 -and $changed -eq 0 -and $serialization -eq 0);changes=@($changes.ToArray());changesTruncated=(($added+$removed+$changed+$serialization) -gt 32)}
    }
    return [ordered]@{exactMatch=($Before -ceq $After);beforeSHA256=(Get-InstallerStateTextHash $Before);afterSHA256=(Get-InstallerStateTextHash $After);domains=$domains}
}

function New-InstallerStateCheckpoint([string]$Phase,[string]$Baseline,[string]$Previous,[string]$Current) {
    if($Phase -cnotmatch '^[a-z][a-z0-9-]{0,79}$'){throw 'Installer state checkpoint has an invalid fixed phase'}
    # Both comparisons retain hashes/field names only. Keep the original
    # baseline even when a previous observation already differs from it.
    return [ordered]@{
        phase=$Phase
        comparison=(Compare-InstallerState $Baseline $Current)
        transition=(Compare-InstallerState $Previous $Current)
    }
}

# Metadata only from the already returned Get-NetFirewallRule objects. No extra
# native query, origin/process inference, rule mutation or acceptance predicate.
function Get-InstallerCapturedFirewallMetadata($Rule) {
    if($null -eq $Rule){return [ordered]@{present=$false}}
    $fields=[ordered]@{}
    foreach($name in @('PolicyStoreSourceType','PolicyStoreSource','Owner','Group','Profile','PrimaryStatus','EnforcementStatus')){
        $property=$Rule.PSObject.Properties[$name]
        if($null -eq $property){$fields[$name]=[ordered]@{present=$false};continue}
        if($null -eq $property.Value){$fields[$name]=[ordered]@{present=$true;isNull=$true};continue}
        $value=[string]$property.Value
        if($value.Length -gt 4096){$fields[$name]=[ordered]@{present=$true;omitted=$true};continue}
        $bytes=[Text.UTF8Encoding]::new($false).GetByteCount($value)
        if($bytes -gt 4096){$fields[$name]=[ordered]@{present=$true;omitted=$true};continue}
        $fields[$name]=[ordered]@{present=$true;utf8Bytes=$bytes;sha256=(Get-InstallerStateTextHash $value)}
    }
    $sourceClass='unclassified'
    $source=$Rule.PSObject.Properties['PolicyStoreSourceType']
    if($null -eq $source){$sourceClass='absent'}
    elseif($null -ne $source.Value -and @('Local','GroupPolicy','Dynamic','Generated','Hardcoded') -ccontains ([string]$source.Value)){$sourceClass=[string]$source.Value}
    return [ordered]@{present=$true;policySourceClass=$sourceClass;fields=$fields}
}
function New-InstallerCapturedFirewallMap([object[]]$Rules) {
    if($Rules.Count -gt 10000){throw 'Captured firewall metadata exceeds row budget'}
    $map=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($rule in $Rules){
        if($null -eq $rule){throw 'Captured firewall metadata requires complete rows'}
        $name=[string]$rule.Name
        if([string]::IsNullOrEmpty($name) -or $name.Length -gt 4096){throw 'Captured firewall identity is unavailable or excessive'}
        $key=Get-InstallerStateTextHash $name
        if($map.ContainsKey($key)){throw 'Captured firewall identities are ambiguous'}
        $map.Add($key,$rule)
    }
    return ,$map
}
function New-InstallerFirewallOrigins([string]$Phase,[object[]]$Changes,[object[]]$BeforeRules,[object[]]$AfterRules,[int]$Remaining) {
    if($Phase -cnotmatch '^[a-z][a-z0-9-]{0,79}$' -or $Remaining -lt 0 -or $Remaining -gt 16 -or $Changes.Count -gt 32){throw 'Invalid captured firewall metadata budget'}
    if($Remaining -eq 0 -or $Changes.Count -eq 0){return ,@()}
    $before=New-InstallerCapturedFirewallMap $BeforeRules
    $after=New-InstallerCapturedFirewallMap $AfterRules
    $records=[Collections.Generic.List[object]]::new()
    foreach($change in $Changes){
        if($records.Count -ge $Remaining){break}
        $identity=[string]$change.identitySHA256;$kind=[string]$change.kind
        if($identity -cnotmatch '^[a-f0-9]{64}$' -or @('added','removed','changed','row-serialization') -cnotcontains $kind){throw 'Invalid captured firewall change identity'}
        $old=$null;$next=$null
        if($before.ContainsKey($identity)){$old=$before[$identity]}
        if($after.ContainsKey($identity)){$next=$after[$identity]}
        $records.Add([ordered]@{phase=$Phase;identitySHA256=$identity;kind=$kind;before=(Get-InstallerCapturedFirewallMetadata $old);after=(Get-InstallerCapturedFirewallMetadata $next)})
    }
    return ,@($records.ToArray())
}
