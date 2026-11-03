#ifndef EvidenceRoot
  #error EvidenceRoot must name the owned native fixture output directory
#endif
[Setup]
AppId=AccessWeaverRestorationContracts
AppName=AccessWeaver restoration ownership contracts
AppVersion=1.0.0
CreateAppDir=no
Uninstallable=no
CreateUninstallRegKey=no
PrivilegesRequired=lowest
DefaultDirName={tmp}\AccessWeaverRestorationContracts
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
CloseApplications=no
RestartApplications=no
OutputDir={#EvidenceRoot}
OutputBaseFilename=installer-restoration-contracts
[Files]
Source: "windows-installer-restore.iss"; Flags: dontcopy
[Code]
#include "windows-installer-restore.iss"
function InitializeSetup: Boolean;
var Code: LongWord; Failure, Executable, Directory: String; Accepted: Boolean;
begin
  Result := False;
  Executable := ExpandConstant('{param:Controller|}');
  Directory := ExtractFileDir(Executable);
  Accepted := AWRunBoundedRestoration(Executable,
    'system apply "' + Directory + '\uninstall-system.json" --confirm',
    Directory, 5000, Code, Failure);
  { A zero controller exit must not hide a still-running descendant. }
  if Accepted or (Code <> 1460) then Exit;
  Result := True;
end;
