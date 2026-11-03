#define AWVersionContractCases 41
#ifndef EvidenceRoot
  #error EvidenceRoot must name the owned native fixture output directory
#endif
[Setup]
AppId=AccessWeaverVersionContracts
AppName=AccessWeaver installer version contracts
AppVersion=1.0.0
CreateAppDir=no
Uninstallable=no
CreateUninstallRegKey=no
PrivilegesRequired=lowest
DefaultDirName={tmp}\AccessWeaverVersionContracts
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
CloseApplications=no
RestartApplications=no
OutputDir={#EvidenceRoot}
OutputBaseFilename=installer-version-contracts
[Files]
Source: "windows-installer-version.iss"; Flags: dontcopy
[Code]
#include "windows-installer-version.iss"
function AWExpect(const Left, Right: String; const Expected: Integer): Boolean;
var ForwardOrder, ReverseOrder: Integer;
begin
  Result := AWCompare(Left, Right, ForwardOrder) and AWCompare(Right, Left, ReverseOrder);
  if Result then Result := (ForwardOrder = Expected) and (ReverseOrder = -Expected);
end;
function AWReject(const Value: String): Boolean;
var Ordering: Integer;
begin
  Result := not AWCompare(Value, '1.0.0', Ordering);
  if Result then Result := not AWCompare('1.0.0', Value, Ordering);
end;
function InitializeSetup: Boolean;
begin
  Result := False;
  if not AWExpect('1.0.0-alpha', '1.0.0-alpha.1', -1) then begin Log('Version precedence case 1 failed'); Exit; end;
  if not AWExpect('1.0.0-alpha.1', '1.0.0-alpha.beta', -1) then begin Log('Version precedence case 2 failed'); Exit; end;
  if not AWExpect('1.0.0-alpha.beta', '1.0.0-beta', -1) then begin Log('Version precedence case 3 failed'); Exit; end;
  if not AWExpect('1.0.0-beta', '1.0.0-beta.2', -1) then begin Log('Version precedence case 4 failed'); Exit; end;
  if not AWExpect('1.0.0-beta.2', '1.0.0-beta.11', -1) then begin Log('Version precedence case 5 failed'); Exit; end;
  if not AWExpect('1.0.0-beta.11', '1.0.0-rc.1', -1) then begin Log('Version precedence case 6 failed'); Exit; end;
  if not AWExpect('1.0.0-rc.1', '1.0.0', -1) then begin Log('Version precedence case 7 failed'); Exit; end;
  if not AWExpect('1.9.9', '1.10.0', -1) then begin Log('Version precedence case 8 failed'); Exit; end;
  if not AWExpect('1.0.10', '1.0.2', 1) then begin Log('Version precedence case 9 failed'); Exit; end;
  if not AWExpect('1.0.0+001', '1.0.0+different', 0) then begin Log('Version precedence case 10 failed'); Exit; end;
  if not AWExpect('1.0.0-alpha+one', '1.0.0-alpha+two', 0) then begin Log('Version precedence case 11 failed'); Exit; end;
  if not AWExpect('99999999999999999999.0.0', '100000000000000000000.0.0', -1) then begin Log('Version precedence case 12 failed'); Exit; end;
  if not AWExpect('1.0.0-99999999999999999999', '1.0.0-100000000000000000000', -1) then begin Log('Version precedence case 13 failed'); Exit; end;
  if not AWExpect('1.0.0-9', '1.0.0-A', -1) then begin Log('Version precedence case 14 failed'); Exit; end;
  if not AWExpect('1.0.0-A', '1.0.0-a', -1) then begin Log('Version precedence case 15 failed'); Exit; end;
  if not AWExpect('1.0.0--', '1.0.0-0', 1) then begin Log('Version precedence case 16 failed'); Exit; end;
  if not AWExpect('0.0.0', '0.0.0', 0) then begin Log('Version precedence case 17 failed'); Exit; end;
  if not AWExpect('1.0.0-alpha', '1.0.0-alpha', 0) then begin Log('Version precedence case 18 failed'); Exit; end;
  if not AWExpect('1.0.0-alpha.1', '1.0.0-alpha.1.1', -1) then begin Log('Version precedence case 19 failed'); Exit; end;
  if not AWExpect('1.0.0-alpha.2', '1.0.0-alpha.10', -1) then begin Log('Version precedence case 20 failed'); Exit; end;
  if not AWExpect('1.0.0+0001', '1.0.0+1', 0) then begin Log('Version precedence case 21 failed'); Exit; end;
  if not AWReject('') then begin Log('Version rejection case 1 failed'); Exit; end;
  if not AWReject('v1.0.0') then begin Log('Version rejection case 2 failed'); Exit; end;
  if not AWReject('01.0.0') then begin Log('Version rejection case 3 failed'); Exit; end;
  if not AWReject('1.00.0') then begin Log('Version rejection case 4 failed'); Exit; end;
  if not AWReject('1.0.00') then begin Log('Version rejection case 5 failed'); Exit; end;
  if not AWReject('1.0') then begin Log('Version rejection case 6 failed'); Exit; end;
  if not AWReject('1.0.0.1') then begin Log('Version rejection case 7 failed'); Exit; end;
  if not AWReject('1.0.0-') then begin Log('Version rejection case 8 failed'); Exit; end;
  if not AWReject('1.0.0-alpha.01') then begin Log('Version rejection case 9 failed'); Exit; end;
  if not AWReject('1.0.0+') then begin Log('Version rejection case 10 failed'); Exit; end;
  if not AWReject('1.0.0+a..b') then begin Log('Version rejection case 11 failed'); Exit; end;
  if not AWReject('1.0.0+a+b') then begin Log('Version rejection case 12 failed'); Exit; end;
  if not AWReject('1.0.0-..') then begin Log('Version rejection case 13 failed'); Exit; end;
  if not AWReject('1.0.0-alpha.') then begin Log('Version rejection case 14 failed'); Exit; end;
  if not AWReject('1.0.0-+build') then begin Log('Version rejection case 15 failed'); Exit; end;
  if not AWReject('1.0.0 x') then begin Log('Version rejection case 16 failed'); Exit; end;
  if not AWExpect('1.0.0-' + StringOfChar('a', 250), '1.0.0-' + StringOfChar('a', 250), 0) then begin Log('Bounded valid version failed'); Exit; end;
  if not AWReject('1.0.0-' + StringOfChar('a', 251)) then begin Log('Oversized version was accepted'); Exit; end;
  if not AWReject('1.0.0' + #10) then begin Log('Control character version was accepted'); Exit; end;
  if not AWReject('1.0.0-' + #233) then begin Log('Non-ASCII version was accepted'); Exit; end;
  Result := True;
end;
