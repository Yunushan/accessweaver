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
[Files]
Source: "{#BuildRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\AccessWeaver"; Filename: "{app}\accessweaver.exe"; Parameters: "ui"
[Code]
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
