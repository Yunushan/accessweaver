{ Bounded SemVer 2.0 comparison shared by production setup and the native fixture.
  Numeric identifiers are compared as strings, without integer overflow. }
function AWNumeric(const Value: String): Boolean;
var I: Integer;
begin
  Result := False;
  if Value = '' then Exit;
  for I := 1 to Length(Value) do
    if (Value[I] < '0') or (Value[I] > '9') then Exit;
  Result := True;
end;

function AWPop(var Remaining: String): String;
var P: Integer;
begin
  P := Pos('.', Remaining);
  if P = 0 then begin Result := Remaining; Remaining := ''; end
  else begin Result := Copy(Remaining, 1, P - 1); Delete(Remaining, 1, P); end;
end;

function AWIdentifiers(const Value: String; const NoLeadingZero: Boolean): Boolean;
var Remaining, Identifier: String; I: Integer;
begin
  Result := False;
  if Value = '' then Exit;
  if Value[Length(Value)] = '.' then Exit;
  Remaining := Value;
  while Remaining <> '' do begin
    Identifier := AWPop(Remaining);
    if Identifier = '' then Exit;
    for I := 1 to Length(Identifier) do
      if not (((Identifier[I] >= '0') and (Identifier[I] <= '9')) or
        ((Identifier[I] >= 'A') and (Identifier[I] <= 'Z')) or
        ((Identifier[I] >= 'a') and (Identifier[I] <= 'z')) or (Identifier[I] = '-')) then Exit;
    if NoLeadingZero and AWNumeric(Identifier) and
      (Length(Identifier) > 1) and (Identifier[1] = '0') then Exit;
  end;
  Result := True;
end;

function AWParse(const Value: String; var Major, Minor, Patch, Pre: String): Boolean;
var Core, Build: String; P: Integer;
begin
  Result := False;
  Major := ''; Minor := ''; Patch := ''; Pre := '';
  if (Length(Value) = 0) or (Length(Value) > 256) then Exit;
  Core := Value;
  P := Pos('+', Core);
  if P > 0 then begin
    Build := Copy(Core, P + 1, Length(Core));
    if not AWIdentifiers(Build, False) then Exit;
    Delete(Core, P, Length(Core));
  end;
  P := Pos('-', Core);
  if P > 0 then begin
    Pre := Copy(Core, P + 1, Length(Core));
    if not AWIdentifiers(Pre, True) then Exit;
    Delete(Core, P, Length(Core));
  end;
  { Both separators are required; a fourth core component is not SemVer. }
  if Pos('.', Core) = 0 then Exit;
  Major := AWPop(Core);
  if Pos('.', Core) = 0 then Exit;
  Minor := AWPop(Core); Patch := Core;
  if not AWNumeric(Major) or not AWNumeric(Minor) or not AWNumeric(Patch) then Exit;
  if ((Length(Major) > 1) and (Major[1] = '0')) or
     ((Length(Minor) > 1) and (Minor[1] = '0')) or
     ((Length(Patch) > 1) and (Patch[1] = '0')) then Exit;
  Result := True;
end;

function AWOrdinal(const Left, Right: String): Integer;
var I, Limit: Integer;
begin
  Result := 0;
  Limit := Length(Left); if Length(Right) < Limit then Limit := Length(Right);
  for I := 1 to Limit do begin
    if Ord(Left[I]) < Ord(Right[I]) then begin Result := -1; Exit; end;
    if Ord(Left[I]) > Ord(Right[I]) then begin Result := 1; Exit; end;
  end;
  if Length(Left) < Length(Right) then Result := -1
  else if Length(Left) > Length(Right) then Result := 1;
end;

function AWNumberCompare(const Left, Right: String): Integer;
begin
  if Length(Left) < Length(Right) then Result := -1
  else if Length(Left) > Length(Right) then Result := 1
  else Result := AWOrdinal(Left, Right);
end;

function AWCompare(const Left, Right: String; var Ordering: Integer): Boolean;
var LM, LN, LP, LA, RM, RN, RP, RA, LI, RI: String;
    LNumeric, RNumeric: Boolean;
begin
  Result := False; Ordering := 0;
  if not AWParse(Left, LM, LN, LP, LA) or not AWParse(Right, RM, RN, RP, RA) then Exit;
  Result := True;
  Ordering := AWNumberCompare(LM, RM); if Ordering <> 0 then Exit;
  Ordering := AWNumberCompare(LN, RN); if Ordering <> 0 then Exit;
  Ordering := AWNumberCompare(LP, RP); if Ordering <> 0 then Exit;
  if (LA = '') and (RA = '') then Exit;
  if LA = '' then begin Ordering := 1; Exit; end;
  if RA = '' then begin Ordering := -1; Exit; end;
  while (LA <> '') and (RA <> '') do begin
    LI := AWPop(LA); RI := AWPop(RA);
    LNumeric := AWNumeric(LI); RNumeric := AWNumeric(RI);
    if LNumeric and RNumeric then Ordering := AWNumberCompare(LI, RI)
    else if LNumeric then Ordering := -1
    else if RNumeric then Ordering := 1
    else Ordering := AWOrdinal(LI, RI);
    if Ordering <> 0 then Exit;
  end;
  if LA <> '' then Ordering := 1 else if RA <> '' then Ordering := -1;
end;
