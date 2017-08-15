program OVPN_Auth;

{$APPTYPE CONSOLE}

{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$SetPEFlags 1}  { <- $SetPEFlags IMAGE_FILE_RELOCS_STRIPPED}

{$R *.res}



{

формат файла:

<логин>:<common name>:<хеш пароля>:<метка активности учетки>:<список ip/подсетей, с которых разрешено соединяться>

все поля, кроме <логин> являются необязательными

метка активности учетки - строки "enabled"/"disabled" или "0"/"1"
указывает активна учетка или учетка отключена.

}





uses
  Winapi.Windows,
  System.SysUtils,
  flcHash in 'fundamentals5\Source\Utils\flcHash.pas',
  PasswordDatabase in 'PasswordDatabase.pas';





var
  _ExitCode: Integer = 1;
  IPStr: RawByteString;
  Username: RawByteString;
  Password: RawByteString;
  PasswordHash: RawByteString;
  CommonName: RawByteString;
  DBFileName: String;
  Str: String;
  TestDB: Boolean;

  IP, Mask: DWORD;
  //IPBelongsToNets: Boolean;
  Nets: RawByteString;


begin
  _ExitCode := 100;

  {$IFDEF DEBUG}ReportMemoryLeaksOnShutdown := True;{$ENDIF}
  IsMultiThread := False;
  try

    Str := AnsiLowerCase(ParamStr(1));
    TestDB := (Str = 'testdb') or (Str = '/testdb') or (Str = '-testdb') or (Str = '--testdb');

    if not TestDB then
    begin

      Username := AnsiLowerCase(Trim(GetEnvironmentVariable('username')));
      CommonName := AnsiLowerCase(Trim(GetEnvironmentVariable('common_name')));
      Password := Trim(GetEnvironmentVariable('password'));
      IPStr := Trim(GetEnvironmentVariable('untrusted_ip'));
      if (IPStr = '') or (Username = '') or (Password = '') or (CommonName = '') then
      begin
        _ExitCode := 2;
        raise Exception.Create('Environment variable error.');
      end;

      PasswordHash := SHA256DigestToHexA(CalcSHA256(Password));
      CharLowerBuffA(PAnsiChar(PasswordHash), Length(PasswordHash));
      {$IFDEF DEBUG}WriteLn('PasswordHash: "' + PasswordHash + '"');{$ENDIF}


      IP := 0;
      Mask := 0;
      if not IPStrToInt(PAnsiChar(IPStr), True, IP, Mask) or (Mask <> $FFFFFFFF) then
      begin
        _ExitCode := 3;
        raise Exception.Create('IP-address is not in the correct format.');
      end;

    end
    else
    begin
      Username := 'test';
      CommonName := 'test';
      PasswordHash := '123';
      IPStr := '192.168.1.1';
    end;

    DBFileName := ChangeFileExt(ThisModulePath, '.pwd');
    {$IFDEF DEBUG}WriteLn('DBFileName: "' + DBFileName + '"');{$ENDIF}

    {$IFDEF DEBUG}WriteLn;{$ENDIF}
    _ExitCode := CheckUser(DBFileName, Username, CommonName, PasswordHash, IP, TestDB);
    {$IFDEF DEBUG}WriteLn;{$ENDIF}

  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
  System.ExitCode := _ExitCode;
  {$IFDEF DEBUG}
  Writeln; Writeln; Writeln;
  Writeln('Exit code: ', System.ExitCode);
  Writeln;
  Writeln('Press Enter...');
  ReadLn;
  {$ENDIF}
end.


