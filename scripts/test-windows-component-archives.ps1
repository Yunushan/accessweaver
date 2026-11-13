# Selected archive functions and inert ZIP/file fixtures only. No worker top level,
# native executable, download, service, host policy or network action is invoked.
[CmdletBinding()]
param([switch]$RequireWindowsPowerShell)
$ErrorActionPreference='Stop'
if($RequireWindowsPowerShell -and ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -cne 'Desktop')){throw 'Windows PowerShell 5.1 Desktop is required'}
$archiveProject=Split-Path -Parent $PSScriptRoot
$archiveTokens=$null;$archiveParseErrors=$null
$archiveAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $archiveProject 'internal\workflow\windows.ps1'),[ref]$archiveTokens,[ref]$archiveParseErrors)
if($archiveParseErrors.Count){throw 'Component archive source did not parse'}
foreach($archiveName in @('Under','No-Reparse','Save-Journal','Backup-File','Expected-Hash','Read-ComponentZip64Fields','Assert-ComponentZipLocalMember','Assert-ComponentZipBudget','Component-ArchivePlan','Get-WorkflowFileHash','Copy-WorkflowFileToNewPath','Replace-ComponentArchiveFile','Publish-ComponentArchiveFile','Expand-Safe')){
    $archiveNodes=@($archiveAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $archiveName})
    if($archiveNodes.Count -ne 1){throw 'Required component archive function is unavailable'}
    . ([scriptblock]::Create($archiveNodes[0].Extent.Text))
}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$script:archiveChecks=0
function Assert-ArchiveFixture([bool]$Condition,[string]$Message){
    $script:archiveChecks++
    if(-not $Condition){throw $Message}
}
function Reject-ArchiveFixture([scriptblock]$Action,[string]$Message){
    $failure=$null
    try{& $Action|Out-Null}catch{$failure=$_.Exception}
    Assert-ArchiveFixture ($null -ne $failure) $Message
    return $failure
}
function New-ArchiveFixtureStream([string[]]$Names){
    $stream=[IO.MemoryStream]::new();$zip=$null
    try{
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
        foreach($name in $Names){
            $entry=$zip.CreateEntry($name,[IO.Compression.CompressionLevel]::NoCompression);$entry.ExternalAttributes=0
            if(-not $name.EndsWith('/')){
                $payload=$entry.Open()
                try{$bytes=[byte[]](1,2,127,128,254);$payload.Write($bytes,0,$bytes.Length)}finally{$payload.Dispose()}
            }
        }
        $zip.Dispose();$zip=$null;$stream.Position=0
        return ,$stream
    }catch{$stream.Dispose();throw}finally{if($zip){$zip.Dispose()}}
}
function Get-ArchiveFixturePlan([string[]]$Names,[string]$Destination){
    $stream=New-ArchiveFixtureStream $Names;$zip=$null
    try{
        Assert-ComponentZipBudget $stream
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        return @(Component-ArchivePlan $zip $Destination)
    }finally{if($zip){$zip.Dispose()};$stream.Dispose()}
}
$archiveTemp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$archiveRoot=Join-Path $archiveTemp ('accessweaver-archive-source-'+[guid]::NewGuid().ToString('N'))
if([IO.File]::Exists($archiveRoot) -or [IO.Directory]::Exists($archiveRoot)){throw 'Fresh component archive fixture path is unavailable'}
$archiveRootItem=[IO.Directory]::CreateDirectory($archiveRoot);$archiveRootCreated=$archiveRootItem.CreationTimeUtc.Ticks
$script:archiveFiles=[Collections.Generic.Dictionary[string,long]]::new([StringComparer]::OrdinalIgnoreCase)
$script:archiveDirs=[Collections.Generic.Dictionary[string,long]]::new([StringComparer]::OrdinalIgnoreCase)
$script:archiveDirs.Add($archiveRoot,$archiveRootCreated)
function Register-ArchiveFixturePath([string]$Path,[bool]$Directory){
    $item=Get-Item -LiteralPath $Path -Force
    Assert-ArchiveFixture ((Under $item.FullName $archiveRoot) -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) -and $item.PSIsContainer -eq $Directory) 'Archive fixture path changed before ownership capture'
    if($Directory){$script:archiveDirs.Add($item.FullName,$item.CreationTimeUtc.Ticks)}else{$script:archiveFiles.Add($item.FullName,$item.CreationTimeUtc.Ticks)}
}
function New-ArchiveFixtureFile([string]$Name,[string[]]$Names){
    $path=Join-Path $archiveRoot $Name;$memory=New-ArchiveFixtureStream $Names;$output=$null
    try{
        $output=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $memory.CopyTo($output);$output.Flush($true);$output.Dispose();$output=$null
    }finally{if($output){$output.Dispose()};$memory.Dispose()}
    Register-ArchiveFixturePath $path $false
    return $path
}
function Assert-ArchiveFixtureUnchanged([string]$Archive,[string]$Digest,[string]$Destination){
    Assert-ArchiveFixture ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -ceq $Digest) 'Rejected archive source bytes changed'
    Assert-ArchiveFixture (-not [IO.Directory]::Exists($Destination) -and -not [IO.File]::Exists($Destination)) 'Rejected archive created its extraction root'
    Assert-ArchiveFixture ($script:undo.Count -eq 0) 'Rejected archive recorded or copied a backup'
}
$script:root=$archiveRoot;$script:journalPath=$null;$script:undo=[Collections.Generic.List[object]]::new()
try{
    $backups=Join-Path $archiveRoot 'backups';[void][IO.Directory]::CreateDirectory($backups);Register-ArchiveFixturePath $backups $true
    # 2730 distinct three-object paths plus one root-level file and the root
    # itself are exactly8192. Only2731 central entries are needed.
    $boundaryNames=[Collections.Generic.List[string]]::new()
    for($i=0;$i -lt 2730;$i++){$boundaryNames.Add(('g{0:d4}/s/f.bin' -f $i))}
    $boundaryNames.Add('last.bin')
    $boundaryDestination=Join-Path $archiveRoot 'boundary-not-created'
    # Geometry proof only: avoid repeating thousands of ancestor provider walks.
    # The real helper is restored before every actual Expand-Safe/refusal case;
    # smaller planning/extraction cases below keep real filesystem checks too.
    $geometryNoReparse=(Get-Command No-Reparse).ScriptBlock
    try{
        Set-Item -LiteralPath Function:script:No-Reparse -Value {param([string]$Path)}
        $boundaryPlan=@(Get-ArchiveFixturePlan $boundaryNames.ToArray() $boundaryDestination)
    }finally{Set-Item -LiteralPath Function:script:No-Reparse -Value $geometryNoReparse}
    Assert-ArchiveFixture ($boundaryPlan.Count -eq 8192 -and @($boundaryPlan|Where-Object {$_.directory}).Count -eq 5461) 'Exact filesystem-object boundary was not admitted'
    Assert-ArchiveFixture (-not [IO.Directory]::Exists($boundaryDestination)) 'Successful archive planning created its destination'
    $boundaryNames.Add('one-over.bin')
    $objectArchive=New-ArchiveFixtureFile 'objects-over.zip' $boundaryNames.ToArray();$objectHash=(Get-FileHash -LiteralPath $objectArchive -Algorithm SHA256).Hash
    $failure=Reject-ArchiveFixture {Expand-Safe $objectArchive $boundaryDestination} 'One object over the filesystem limit was admitted'
    Assert-ArchiveFixture ($failure.Message -ceq 'Component archive exceeds the 8192-object filesystem limit') 'Object-budget refusal did not identify the actual boundary'
    Assert-ArchiveFixtureUnchanged $objectArchive $objectHash $boundaryDestination
    # Depth includes the leaf component, relative to the extraction root.
    $depth32=(@(1..31|ForEach-Object {'d'})+@('leaf.bin')) -join '/'
    $depthDestination=Join-Path $archiveRoot 'depth-not-created'
    $depthPlan=@(Get-ArchiveFixturePlan @($depth32) $depthDestination)
    Assert-ArchiveFixture ($depthPlan.Count -eq 33) 'Exact32-component path was not admitted'
    Assert-ArchiveFixture (-not [IO.Directory]::Exists($depthDestination)) 'Depth planning created its destination'
    $depth33='d/'+$depth32
    $depthArchive=New-ArchiveFixtureFile 'depth-over.zip' @('first.bin',$depth33);$depthHash=(Get-FileHash -LiteralPath $depthArchive -Algorithm SHA256).Hash
    $failure=Reject-ArchiveFixture {Expand-Safe $depthArchive $depthDestination} 'One level over the path-depth limit was admitted'
    Assert-ArchiveFixture ($failure.Message -ceq 'Component archive exceeds the 32-level path-depth limit') 'Depth refusal did not identify the actual boundary'
    Assert-ArchiveFixtureUnchanged $depthArchive $depthHash $depthDestination
    # Case/separator-normalized shared parents are charged once; an explicit
    # directory following an implicit one is still a single planned object.
    $sharedNames=[Collections.Generic.List[string]]::new()
    for($i=0;$i -lt 100;$i++){$sharedNames.Add(('shared/nested/f{0:d3}.bin' -f $i))}
    $sharedNames.Add('SHARED/');$sharedNames.Add('SHARED\NESTED\other.bin')
    $sharedPlan=@(Get-ArchiveFixturePlan $sharedNames.ToArray() (Join-Path $archiveRoot 'shared-not-created'))
    Assert-ArchiveFixture ($sharedPlan.Count -eq 104 -and @($sharedPlan|Where-Object {$_.directory}).Count -eq 3) 'Shared case/separator-normalized parents were charged more than once'
    $emptyPlan=@(Get-ArchiveFixturePlan @('empty/','nested/child/') (Join-Path $archiveRoot 'empty-not-created'))
    Assert-ArchiveFixture ($emptyPlan.Count -eq 4 -and @($emptyPlan|Where-Object {-not $_.directory}).Count -eq 0) 'Root-level and nested empty directories were omitted from the object plan'
    foreach($case in @(
        @{Name='duplicate';Entries=@('root.bin','root.bin')},
        @{Name='case';Entries=@('root.bin','ROOT.BIN')},
        @{Name='separator';Entries=@('folder/file.bin','folder\file.bin')},
        @{Name='file-parent';Entries=@('folder','folder/child.bin')},
        @{Name='late-file-parent';Entries=@('folder/child.bin','FOLDER')},
        @{Name='directory-file';Entries=@('folder/','FOLDER')},
        @{Name='root-directory';Entries=@('first.bin','/')},
        @{Name='traversal';Entries=@('first.bin','../outside.bin')}
    )){
        $path=New-ArchiveFixtureFile ($case.Name+'.zip') $case.Entries;$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $destination=Join-Path $archiveRoot ($case.Name+'-not-created')
        [void](Reject-ArchiveFixture {Expand-Safe $path $destination} 'Archive path conflict was admitted')
        Assert-ArchiveFixtureUnchanged $path $hash $destination
    }
    # A missing immediate parent must not be implicitly created outside the
    # extraction-root budget, on either the planning or extraction path.
    $missingParent=Join-Path $archiveRoot 'missing-parent';$missingDestination=Join-Path $missingParent 'output'
    $missingArchive=New-ArchiveFixtureFile 'missing-parent.zip' @('first.bin');$missingHash=(Get-FileHash -LiteralPath $missingArchive -Algorithm SHA256).Hash
    $failure=Reject-ArchiveFixture {Expand-Safe $missingArchive $missingDestination} 'Archive extraction created unplanned destination ancestors'
    Assert-ArchiveFixture ($failure.Message -ceq 'Component archive destination parent must already exist' -and -not [IO.Directory]::Exists($missingParent)) 'Missing destination parent was created or admitted'
    Assert-ArchiveFixtureUnchanged $missingArchive $missingHash $missingDestination
    # Existing filesystem type conflicts are also discovered before a valid
    # first entry could replace or create anything.
    $existingRoot=Join-Path $archiveRoot 'existing';[void][IO.Directory]::CreateDirectory($existingRoot);Register-ArchiveFixturePath $existingRoot $true
    $existingFile=Join-Path $existingRoot 'folder';[IO.File]::WriteAllBytes($existingFile,[byte[]](9,8,7));Register-ArchiveFixturePath $existingFile $false
    $existingArchive=New-ArchiveFixtureFile 'existing-conflict.zip' @('first.bin','folder/child.bin');$existingHash=(Get-FileHash -LiteralPath $existingArchive -Algorithm SHA256).Hash
    [void](Reject-ArchiveFixture {Expand-Safe $existingArchive $existingRoot} 'Existing file was admitted as a planned directory')
    Assert-ArchiveFixture (([Convert]::ToBase64String([IO.File]::ReadAllBytes($existingFile))) -ceq 'CQgH' -and -not [IO.File]::Exists((Join-Path $existingRoot 'first.bin')) -and $script:undo.Count -eq 0) 'Filesystem conflict changed existing bytes or created an earlier entry'
    Assert-ArchiveFixture ((Get-FileHash -LiteralPath $existingArchive -Algorithm SHA256).Hash -ceq $existingHash) 'Filesystem-conflict refusal changed source archive bytes'
    # Small actual extraction proves implicit parents and empty directories are
    # created from the completed plan and files preserve their exact bytes.
    $validArchive=New-ArchiveFixtureFile 'valid.zip' @('empty/','shared/nested/file.bin','SHARED/','SHARED/other.bin')
    $validDestination=Join-Path $archiveRoot 'valid-output';Expand-Safe $validArchive $validDestination
    foreach($relative in @('','empty','shared','shared\nested')){
        $path=if($relative){Join-Path $validDestination $relative}else{$validDestination};Register-ArchiveFixturePath $path $true
    }
    foreach($relative in @('shared\nested\file.bin','shared\other.bin')){
        $path=Join-Path $validDestination $relative;Register-ArchiveFixturePath $path $false
        Assert-ArchiveFixture (([Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) -ceq 'AQJ/gP4=') 'Bounded planned extraction changed payload bytes'
    }
    Assert-ArchiveFixture ($script:undo.Count -eq 2 -and [IO.Directory]::GetFileSystemEntries((Join-Path $validDestination 'empty')).Length -eq 0) 'Actual extraction omitted an empty directory or changed journal ownership'
    Assert-ArchiveFixture ([IO.Directory]::GetFileSystemEntries($backups).Length -eq 0) 'Fresh extraction copied an unnecessary original backup'
    # No unplanned extraction temporary or arbitrary path may be cleaned away.
    $observed=@(Get-ChildItem -LiteralPath $archiveRoot -Recurse -Force)
    Assert-ArchiveFixture ($observed.Count -eq $script:archiveFiles.Count+$script:archiveDirs.Count-1) 'Archive fixture contains an unplanned filesystem object'
    foreach($item in $observed){Assert-ArchiveFixture ($script:archiveFiles.ContainsKey($item.FullName) -or $script:archiveDirs.ContainsKey($item.FullName)) 'Archive extraction created an unregistered object'}
    Write-Output ('PASS component archive source contracts ('+$script:archiveChecks+' checks; native worker not executed)')
}finally{
    # Nonrecursive exact-object cleanup. Any changed root, alias, object or
    # creation identity is retained rather than broad-deleted after a failure.
    $fresh=Get-Item -LiteralPath $archiveRoot -Force
    if($fresh.CreationTimeUtc.Ticks -ne $archiveRootCreated -or ($fresh.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Changed archive fixture root was preserved'}
    foreach($entry in $script:archiveFiles.GetEnumerator()){
        $item=Get-Item -LiteralPath $entry.Key -Force
        if($item.PSIsContainer -or $item.CreationTimeUtc.Ticks -ne $entry.Value -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Changed archive fixture file was preserved'}
        [IO.File]::Delete($entry.Key)
    }
    foreach($entry in @($script:archiveDirs.GetEnumerator()|Sort-Object {$_.Key.Length} -Descending)){
        $item=Get-Item -LiteralPath $entry.Key -Force
        if(-not $item.PSIsContainer -or $item.CreationTimeUtc.Ticks -ne $entry.Value -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Changed archive fixture directory was preserved'}
        [IO.Directory]::Delete($entry.Key,$false)
    }
}
