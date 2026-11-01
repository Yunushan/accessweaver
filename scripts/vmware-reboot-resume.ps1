# One-shot startup verifier installed only by the disposable-VM test controller.
$ErrorActionPreference='Stop'
$share='\\vmware-host\Shared Folders\AccessWeaver-Results'
try{
    $binary=(Get-Content C:\AccessWeaver-Results\reboot-controller.txt -Raw).Trim()
    $binary=[IO.Path]::GetFullPath($binary)
    if((Split-Path -Parent $binary) -ne 'C:\AccessWeaver-Test' -or (Split-Path -Leaf $binary) -notmatch '^accessweaver[a-zA-Z0-9-]*\.exe$'){throw 'Unexpected test controller path'}
    & C:\AccessWeaver-Test\test-windows-reboot.ps1 -Phase Verify -Executable $binary
}finally{
    $deadline=[DateTime]::UtcNow.AddMinutes(2)
    do{
        & robocopy.exe C:\AccessWeaver-Results $share /E /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
        if($LASTEXITCODE -le 7){break};Start-Sleep -Seconds 5
    }while([DateTime]::UtcNow -lt $deadline)
    Unregister-ScheduledTask -TaskName 'AccessWeaver-Parity-Reboot-Verify' -Confirm:$false -ErrorAction SilentlyContinue
}
