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
