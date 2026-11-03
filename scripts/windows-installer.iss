#ifndef BuildRoot
  #error BuildRoot must name the staged release directory
#endif
#ifndef ReleaseVersion
  #define ReleaseVersion "0.1.0"
#endif
#ifndef TargetArch
  #error TargetArch must identify the verified staged payload
#endif
#if TargetArch == "amd64"
  #define InstallArchitecture "x64compatible"
#elif TargetArch == "arm64"
  #define InstallArchitecture "arm64"
#else
  #error TargetArch must be amd64 or arm64
#endif
[Setup]
AppId={{B13D4677-4660-4E63-B3DB-03077ACBB092}
AppName=AccessWeaver
AppVersion={#ReleaseVersion}
AppPublisher=AccessWeaver contributors
AppPublisherURL=https://github.com/Yunushan/accessweaver
DefaultDirName={autopf}\AccessWeaver
DefaultGroupName=AccessWeaver
AllowNoIcons=yes
ArchitecturesAllowed={#InstallArchitecture}
ArchitecturesInstallIn64BitMode={#InstallArchitecture}
PrivilegesRequired=admin
LicenseFile={#BuildRoot}\LICENSE
OutputDir={#BuildRoot}\..
OutputBaseFilename=accessweaver-{#ReleaseVersion}-windows-{#TargetArch}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\accessweaver.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
SetupMutex=Global\AccessWeaver-Setup-B13D4677-4660-4E63-B3DB-03077ACBB092
[Files]
Source: "{#BuildRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\AccessWeaver"; Filename: "{app}\accessweaver.exe"; Parameters: "ui"
[Code]
#include "windows-installer-version.iss"

function AWReadRegisteredVersion(const Root: Integer; var Found: Boolean; var Version: String): String;
var Names: TArrayOfString; I: Integer; HasUninstall: Boolean;
    Parent, Leaf: String;
begin
  Result := ''; Found := False; Version := '';
  Parent := 'SOFTWARE\Microsoft\Windows\CurrentVersion';
  Leaf := '{B13D4677-4660-4E63-B3DB-03077ACBB092}_is1';
  { Enumerate a readable fixed parent: access denied must not look uninstalled. }
  if not RegGetSubkeyNames(Root, Parent, Names) then begin
    Result := 'Cannot inspect machine installation registration. Review access and retry.'; Exit;
  end;
  if GetArrayLength(Names) > 65536 then begin Result := 'Machine installation registration exceeds its inspection limit.'; Exit; end;
  HasUninstall := False;
  for I := 0 to GetArrayLength(Names) - 1 do
    if CompareText(Names[I], 'Uninstall') = 0 then HasUninstall := True;
  if not HasUninstall then Exit;
  Parent := Parent + '\Uninstall';
  if not RegGetSubkeyNames(Root, Parent, Names) then begin
    Result := 'Cannot inspect machine installation registration. Review access and retry.'; Exit;
  end;
  if GetArrayLength(Names) > 65536 then begin Result := 'Machine installation registration exceeds its inspection limit.'; Exit; end;
  for I := 0 to GetArrayLength(Names) - 1 do
    if CompareText(Names[I], Leaf) = 0 then begin
      Found := True;
      if not RegQueryStringValue(Root, Parent + '\' + Leaf, 'DisplayVersion', Version) then
        Result := 'The installed AccessWeaver version cannot be read. Review the installation and recovery records before retrying.';
      Exit;
    end;
end;

function AWVersionPreflight: String;
var Found64, Found32: Boolean; Version64, Version32, Installed: String; Ordering: Integer;
begin
  Result := AWReadRegisteredVersion(HKLM64, Found64, Version64);
  if Result <> '' then Exit;
  Result := AWReadRegisteredVersion(HKLM32, Found32, Version32);
  if Result <> '' then Exit;
  if Found64 and Found32 then begin
    Result := 'Multiple machine installations of AccessWeaver are registered. Review them before retrying.'; Exit;
  end;
  if not AWCompare('{#ReleaseVersion}', '{#ReleaseVersion}', Ordering) then begin
    Result := 'This installer has invalid release version metadata.'; Exit;
  end;
  if not Found64 and not Found32 then Exit;
  if Found64 then Installed := Version64 else Installed := Version32;
  if not AWCompare('{#ReleaseVersion}', Installed, Ordering) then begin
    Result := 'The installed AccessWeaver version is invalid. Review the installation and recovery records before retrying.'; Exit;
  end;
  if Ordering < 0 then
    Result := 'A newer AccessWeaver version is installed. Use a current or newer installer. This installer will not downgrade it.';
end;

function InitializeSetup: Boolean;
var Failure: String;
begin
  Failure := AWVersionPreflight;
  Result := Failure = '';
  if not Result then begin
    Log(Failure);
    if not WizardSilent then SuppressibleMsgBox(Failure, mbCriticalError, MB_OK, IDOK);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  { Recheck after wizard interaction, while the product SetupMutex remains held. }
  Result := AWVersionPreflight;
end;

function InitializeUninstall: Boolean;
var
  ResultCode: Integer;
begin
  { Abort before deleting the controller when restoration fails. The user can
    inspect the protected recovery journal and retry the uninstaller. }
  Result := Exec(ExpandConstant('{app}\accessweaver.exe'),
    'system apply "' + ExpandConstant('{app}\uninstall-system.json') + '" --confirm',
    ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := Result and (ResultCode = 0);
  if not Result then
  begin
    Log('AccessWeaver system restoration failed; process result/error code: ' + IntToStr(ResultCode));
    { Unattended deployment must fail without waiting on an interactive dialog. }
    if not UninstallSilent then
      MsgBox('AccessWeaver could not restore its system changes. Review the recovery journal in ProgramData\AccessWeaver\logs, then retry uninstalling.', mbError, MB_OK);
  end;
end;

#ifdef EvidenceOutput
  #expr SaveToFile(EvidenceOutput)
#endif
