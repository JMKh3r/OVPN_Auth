{

формат файла:

<логин>:<common name>:<хеш пароля>:<метка активности учетки>:<список ip/подсетей, с которых разрешено соединяться>

все поля, кроме <логин> являются необязательными
метка активности учетки - строки "enabled"/"disabled" или "0"/"1"

}

unit PasswordDatabase;

{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}

interface

uses
  Winapi.Windows,
  System.SysUtils, System.Classes;




type
  EPasswordDatabase = class(Exception);



function CheckUser(AFileName: String; const AUsername, ACommonName, APasswordHash: RawByteString; const IP: DWORD; const ATestDB: Boolean): Integer;


function IPStrToInt(const AIPStr: PAnsiChar; const AFullIP: Boolean; var AIP, AMask: DWORD): Boolean;
function CheckIP(const AIP: DWORD; const ANets: PAnsiChar; var AIPBelongsToNets: Boolean; const ATestDB: Boolean): Boolean;

function ThisModulePath: String;



implementation

type
  AnsiCharPointer = ^AnsiChar;
  PAnsiCharPointer = ^AnsiCharPointer;






////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function ThisModulePath: String;
var
  _StrBufferPtr: Pointer;
  _BufferSize: Integer;
  _BufferLength: DWORD;
  _FileName: String;
  _StrLength: DWORD;
  I: Integer;
begin
  Result := '';
  _FileName := '';
  _BufferLength := 0;
  _StrBufferPtr := nil;
  try
    for I := 1 to 100 do
    begin
      Inc(_BufferLength, 1024);
      _BufferSize := _BufferLength * SizeOf(Char);
      ReallocMem(_StrBufferPtr, _BufferSize);
      FillChar(_StrBufferPtr^, _BufferSize, 0);
      _StrLength := GetModuleFileName(0, PChar(_StrBufferPtr), _BufferLength);
      if (_StrLength > 0) and (_StrLength < _BufferLength) then
      begin
        SetString(Result, PChar(_StrBufferPtr), _StrLength);
        Exit;
      end
      else if _StrLength = _BufferLength then
      begin
        Continue;
      end
      else
      begin
        Exit;
      end;
    end;
    Exit;
  finally
    if _StrBufferPtr <> nil then FreeMem(_StrBufferPtr);
  end;
end;




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
procedure RaisePasswordDatabaseError(const Msg: String);
var
  _P: Pointer;
  _EventLog: Integer;
  _Source: array[0..260] of Char;
begin
  GetModuleFileName(0, _Source, Length(_Source));
  _EventLog := RegisterEventSource(nil, _Source);
  if _EventLog <> 0 then
  try
    _P := PChar(Msg);
    ReportEvent(_EventLog, EVENTLOG_ERROR_TYPE, 0, 0, nil, 1, 0, @_P, nil);
  finally
    DeregisterEventSource(_EventLog);
  end;
  raise EPasswordDatabase.Create(Msg);
end;












////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function IPStrToInt(const AIPStr: PAnsiChar; const AFullIP: Boolean; var AIP, AMask: DWORD): Boolean;
var
  _CurrTextChar, _CurrOctetChar: AnsiCharPointer;
  _OctetStr: array[0..3] of AnsiChar;
  _Len, _OctetLen, I: Integer;
  _Octet: Integer;
  _IP: DWORD;
  _ShiftLen: Integer;
begin
  Result := False;
  _Len := StrLen(AIPStr);

  if _Len < 1 then
  begin
    AIP := 0;
    AMask := 0;
    Result := True;
    Exit;
  end;

  FillChar(_OctetStr, SizeOf(_OctetStr), 0);
  _CurrTextChar := Pointer(AIPStr);
  _CurrOctetChar := @(_OctetStr[0]);
  _OctetLen := 0;
  _IP := 0;
  _ShiftLen := 24;
  for I := 0 to _Len do
  begin
    if (I = _Len) or (_CurrTextChar^ = '.') then
    begin
      if _OctetLen < 1 then
      begin
        if I = _Len then Break else Exit;
      end;
      _CurrOctetChar^ := #0;
      if not TryStrToInt(_OctetStr, _Octet) then Exit;
      if (_Octet < 0) or (_Octet > 255) then Exit;
      _IP := _IP or (_Octet shl _ShiftLen);
      if (_ShiftLen < 1) and (I < _Len) then Exit;
      Dec(_ShiftLen, 8);
      _CurrOctetChar := @(_OctetStr[0]);
      _OctetLen := 0;
    end
    else if _CurrTextChar^ in ['0'..'9'] then
    begin
      _CurrOctetChar^ := _CurrTextChar^;
      Inc(_CurrOctetChar);
      Inc(_OctetLen);
      if _OctetLen > 3 then Exit;
    end
    else Exit;
    Inc(_CurrTextChar);
  end;
  if AFullIP and (_ShiftLen >= 0) then Exit;
  AIP := _IP;
  AMask := $FFFFFFFF shl (_ShiftLen + 8);
  Result := True;
end;




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function CheckIP(const AIP: DWORD; const ANets: PAnsiChar; var AIPBelongsToNets: Boolean; const ATestDB: Boolean): Boolean;
type
  TParseState = (psNull, psSlash, psComma, psText1, psText2);
var
  _CurrTextChar: AnsiCharPointer;
  L: Integer;
  _Len: Integer;
  _ParseState: TParseState;
  _Text1, _Text2: PAnsiChar;
  _IP, _Mask: DWORD;
  _MaskBitCount: Integer;
  _InclusionCount: Integer;
begin
  Result := False;

  _Len := StrLen(ANets);
  if _Len < 1 then
  begin
    AIPBelongsToNets := True;
    Result := True;
    Exit;
  end;

  _InclusionCount := 0;
  _CurrTextChar := @(ANets[_Len]);
  _CurrTextChar^ := ',';
  _CurrTextChar := Pointer(ANets);
  _ParseState := psComma;
  _Text1 := nil;
  _Text2 := nil;
  Inc(_Len);
  for L := 1 to _Len do  // перебор символов в прочитаннм буфере
  begin
    case _CurrTextChar^ of
      '0'..'9', '.':
        begin
          if _ParseState = psComma then
          begin
            _ParseState := psText1;
            _Text1 := Pointer(_CurrTextChar);
          end
          else if _ParseState = psSlash then
          begin
            _ParseState := psText2;
            _Text2 := Pointer(_CurrTextChar);
          end;
        end;
      '/':
        begin
          if _ParseState <> psText1 then
          begin
            Exit;
          end;
          _ParseState := psSlash;
          _CurrTextChar^ := #0;
        end;
      ',':
        begin
          if (_ParseState <> psText1) and (_ParseState <> psText2) then
          begin
            Exit;
          end;
          _CurrTextChar^ := #0;

          _Mask := 0;

          if _Text1 = nil then Exit;
          if not IPStrToInt(_Text1, False, _IP, _Mask) then Exit;

          if _Text2 <> nil then
          begin
            if _Mask <> $FFFFFFFF then Exit;
            if not TryStrToInt(_Text2, _MaskBitCount) then Exit;
            if (_MaskBitCount < 1) or (_MaskBitCount > 32) then Exit;
            _Mask := $FFFFFFFF shl (32 - _MaskBitCount);
          end;

          if (_IP and not _Mask) <> 0 then Exit;

          if (_IP and _Mask) = (AIP and _Mask) then
          begin
            if not ATestDB then
            begin
              AIPBelongsToNets := True;
              Result := True;
              Exit;
            end;
            Inc(_InclusionCount);
          end;

          _Text1 := nil;
          _Text2 := nil;
          _ParseState := psComma;
        end;
    else
      Exit;
    end;
    Inc(_CurrTextChar);
  end;
  AIPBelongsToNets := _InclusionCount > 0;
  Result := True;
end;







////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function CheckUser(AFileName: String; const AUsername, ACommonName, APasswordHash: RawByteString; const IP: DWORD; const ATestDB: Boolean): Integer;
const
  MAX_FILE_SIZE = 16*1024*1024;
  {$IFDEF DEBUG}
  FILE_BUFFER_SIZE = 10;
  {$ELSE}
  FILE_BUFFER_SIZE = 128*1024;
  {$ENDIF}
  _FILE_READ_MAX_COUNT = MAX_FILE_SIZE div FILE_BUFFER_SIZE + 100;

  FILE_LINE_PART_MAX_LENGTH = 500;

type
  TParseState = (psNull, psSkipLine, ps10, ps13, {ps9,} psText1, psText2, psText3, psText4, psText5);
  TFileLinePart = array[0..FILE_LINE_PART_MAX_LENGTH] of AnsiChar;

var
  _LastError: DWORD;
  _BoolRes: BOOL;
  _S: String;
  _FileBuffer: Pointer;
  _FLogFileHandle: THandle;
  _FileSizeHigh, _FileSizeLow: DWORD;
  _FinishParsing: Boolean;
  _ParseState: TParseState;
  _CorruptedLine: Boolean;  // флаг поврежденной строки - такую строку пропускаем и ищем следующий признак конца строки #13#10
  _CurrTextChar: AnsiCharPointer;
  _CurrTextLength: Cardinal;
  _LineNum: Cardinal;
  _NumberOfBytesToRead, _NumberOfBytesRead: DWORD;
  _CurrBufChar: AnsiCharPointer;
  K, L: Integer;
  _Login: TFileLinePart;
  _CN: TFileLinePart;
  _Hash: TFileLinePart;
  _Enabled: TFileLinePart;
  _Nets: TFileLinePart;
  _IPBelongsToNets: Boolean;

           AAA: Integer;


begin
  Result := 200;

  _LineNum := 0;

  AFileName := '\\?\' + AFileName;

  _FLogFileHandle := CreateFile(PChar(AFileName), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if _FLogFileHandle = INVALID_HANDLE_VALUE then
    RaisePasswordDatabaseError('Failure to open password file. ' + SysErrorMessage(GetLastError) + '. File: "' + AFileName + '"');
  try

    // проверяем размер файла
    _FileSizeHigh := 0;
    _FileSizeLow := GetFileSize(_FLogFileHandle, @_FileSizeHigh);
    if (_FileSizeHigh <> 0) or (_FileSizeLow > MAX_FILE_SIZE) then
      RaisePasswordDatabaseError('Password file too large. File: "' + AFileName + '"');

    // парсинг файла
    _ParseState := ps10;
    _CorruptedLine := False;
    _CurrTextChar := nil;
    _CurrTextLength := 0;
    _LineNum := 1;
    FillChar(_Login, SizeOf(TFileLinePart), 0);
    FillChar(_CN, SizeOf(TFileLinePart), 0);
    FillChar(_Hash, SizeOf(TFileLinePart), 0);
    FillChar(_Enabled, SizeOf(TFileLinePart), 0);
    FillChar(_Nets, SizeOf(TFileLinePart), 0);


    GetMem(_FileBuffer, FILE_BUFFER_SIZE);
    try
      _FinishParsing := False;
      for K := 1 to _FILE_READ_MAX_COUNT do // чтобы гарантированно когда-либо выйти из цикла чтения, даже если у нас ошибка, которая приводит к бесконечному зацикливанию
      begin

        _NumberOfBytesToRead := FILE_BUFFER_SIZE;
        _NumberOfBytesRead := 0;
        _BoolRes := ReadFile(_FLogFileHandle, _FileBuffer^, _NumberOfBytesToRead, _NumberOfBytesRead, nil);
        if not _BoolRes then
          RaisePasswordDatabaseError('Password file read error. ' + SysErrorMessage(GetLastError) + '. File: "' + AFileName + '"');
        if _NumberOfBytesRead = 0 then
        begin
          _CurrBufChar := _FileBuffer;
          _CurrBufChar^ := #13;
          Inc(_CurrBufChar);
          _CurrBufChar^ := #10;
          _CurrBufChar := nil;
          _NumberOfBytesRead := 2;
          _FinishParsing := True;
        end;

        //  парсим данные в буфере
        _CurrBufChar := _FileBuffer;
        for L := 1 to _NumberOfBytesRead do  // перебор символов в прочитаннм буфере
        begin
          case _CurrBufChar^ of
            #10:
              begin
                // началась новая строка
                if _ParseState = ps13 then
                begin
                  // анализируем данные предыдущей строки файла
                  if not _CorruptedLine then
                  begin
                    FillChar(_Login, SizeOf(TFileLinePart), 0);
                    FillChar(_CN, SizeOf(TFileLinePart), 0);
                    FillChar(_Hash, SizeOf(TFileLinePart), 0);
                    FillChar(_Enabled, SizeOf(TFileLinePart), 0);
                    FillChar(_Nets, SizeOf(TFileLinePart), 0);
                  end;
                end;
                _CorruptedLine := False;
                _ParseState := ps10;
                Inc(_LineNum);
              end;

            #13, ':':
              begin

                // сначала обрабатываем найденные данные
                if not _CorruptedLine then
                begin
                  case _ParseState of

                    ps10: ;

                    psText1:
                      begin
                        // нашли логин - сравниваем
                        CharLowerBuffA(@_Login, StrLen(_Login));
                        if (StrComp(PAnsiChar(AUsername), @_Login) = 0) or ATestDB then
                        begin
                          _CurrTextChar := @_CN;
                          _CurrTextLength := 0;
                          _ParseState := psText2;
                        end
                        else
                        begin
                          _CurrTextChar := nil;
                          _CurrTextLength := 0;
                          _ParseState := psSkipLine;
                        end;
                      end;

                    psText2:
                      begin
                        // нашли common name - сравниваем
                        CharLowerBuffA(@_CN, StrLen(_CN));
                        if (StrComp(PAnsiChar(ACommonName), @_CN) = 0) or ATestDB then
                        begin
                          _CurrTextChar := @_Hash;
                          _CurrTextLength := 0;
                          _ParseState := psText3;
                        end
                        else
                        begin
                          // имя пользователя совпало - т.е. учетную запись нашли, но Common Name не совпало - выходим с ошибкой авторизации
                          Result := 10;
                          WriteLn('Unauthorized. Wrong common name. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                          Exit;
                        end;
                      end;

                    psText3:
                      begin
                        // нашли хеш - сравниваем
                        CharLowerBuffA(@_Hash, StrLen(_Hash));
                        if (StrComp(PAnsiChar(APasswordHash), @_Hash) = 0) or ATestDB then
                        begin
                          _CurrTextChar := @_Enabled;
                          _CurrTextLength := 0;
                          _ParseState := psText4;
                        end
                        else
                        begin
                          // имя пользователя и Common Name совпало - т.е. учетную запись нашли, но Hash не совпал - выходим с ошибкой авторизации
                          Result := 11;
                          WriteLn('Unauthorized. Wrong password. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                          Exit;
                        end;
                      end;

                    psText4:
                      begin
                        // нашли флаг активации учетки - сравниваем
                        CharLowerBuffA(@_Enabled, StrLen(_Enabled));
                        if (_Enabled = String('1')) or (_Enabled = 'enabled') or (_Enabled = 'enable') then
                        begin
                          _CurrTextChar := @_Nets;
                          _CurrTextLength := 0;
                          _ParseState := psText5;
                        end
                        else
                        begin
                          if (StrLen(_Enabled) = 0) or (_Enabled = String('0')) or (_Enabled = 'disabled') or (_Enabled = 'disable') then
                          begin
                            if not ATestDB then
                            begin
                              // учетная запись отключена - выходим с ошибкой авторизации
                              Result := 12;
                              WriteLn('Unauthorized. Account disabled. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                              Exit;
                            end
                            else
                            begin
                              // тест базы паролей - переходим к следующему полю
                              _CurrTextChar := @_Nets;
                              _CurrTextLength := 0;
                              _ParseState := psText5;
                            end;
                          end
                          else
                          begin
                            // ошибка в формате данных учетной записи - выходим с ошибкой авторизации
                            Result := 201;
                            WriteLn('Unauthorized. Password file format error. Line: ' + IntToStr(_LineNum));
                            Exit;
                          end;
                        end;
                      end;

                    psText5:
                      begin
                        // вдруг нашли разделитель
                        if _CurrBufChar^ = ':' then
                        begin
                          // ошибка в формате данных учетной записи - выходим с ошибкой авторизации
                          Result := 201;
                          WriteLn('Unauthorized. Password file format error. Line: ' + IntToStr(_LineNum));
                          Exit;
                        end;

                        // анализ подсетей
                        if not CheckIP(IP, @_Nets, _IPBelongsToNets, ATestDB) then
                        begin
                          // ошибка в формате данных учетной записи - выходим с ошибкой авторизации
                          Result := 201;
                          WriteLn('Unauthorized. Password file format error. Line: ' + IntToStr(_LineNum));
                          Exit;
                        end;
                        if not ATestDB then
                        begin
                          if _IPBelongsToNets then
                          begin
                            Result := 0;
                            WriteLn('Authorized. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                            Exit;
                          end
                          else
                          begin
                            // доступ с данного ip запрещен
                            Result := 13;
                            WriteLn('Unauthorized. Access is denied from this IP. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                            Exit;
                          end;
                        end;
                      end;

                  else
                    _CorruptedLine := True;
                  end;
                end;


                // отрабатываем вариант конца строки
                if _CurrBufChar^ = #13 then
                begin
                  if not ATestDB then
                  begin
                    case _ParseState of
                      psText2:
                        begin
                          // заполнены поля: логин
                          // успешно сравнили логин - сравниваем common name и хеш
                          if (ACommonName = '') and (APasswordHash = '') then
                          begin
                            // логин совпал, а common name и хеш пустые - учетная запись отключена
                            Result := 12;
                            WriteLn('Unauthorized. Account disabled. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                            Exit;
                          end
                          else
                          begin
                            Result := 10;
                            WriteLn('Unauthorized. Wrong common name. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                            Exit;
                          end;
                        end;
                      psText3:
                        begin
                          // заполнены поля: логин, common name
                          // успешно сравнили логин и common name - сравниваем хеш
                          if APasswordHash = '' then
                          begin
                            // логин и common name совпали, а хеш пуст - учетная запись отключена
                            Result := 12;
                            WriteLn('Unauthorized. Account disabled. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                            Exit;
                          end
                          else
                          begin
                            Result := 11;
                            WriteLn('Unauthorized. Wrong password. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                            Exit;
                          end;
                        end;
                      psText4:
                        begin
                          // заполнены поля: логин, common name, хеш
                          // успешно сравнили логин, common name, хеш - учетная запись отключена
                          Result := 12;
                          WriteLn('Unauthorized. Account disabled. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                          Exit;
                        end;
                      psText5:
                        begin
                          // заполнены поля: логин, common name, хеш, флаг активации учетной записи
                          // успешно сравнили логин, common name, хеш, флаг активации учетной записи
                          Result := 0;
                          WriteLn('Authorized. Login: "' + AUsername + '", Common name: "' + ACommonName + '". Password file line: ' + IntToStr(_LineNum));
                          Exit;
                        end;
                    end;
                  end;
                  _CurrTextChar := nil;
                  _CurrTextLength := 0;
                  _ParseState := ps13;
                end;

              end; // #13, ':':

            else
              begin
                if not _CorruptedLine then
                begin
                  if _ParseState = ps10 then
                  begin
                    _CurrTextChar := @_Login;
                    _CurrTextLength := 0;
                    _ParseState := psText1;
                  end;
                  if _ParseState in [psText1, psText2, psText3, psText4, psText5] then
                  begin
                    if _CurrBufChar^ >= #32 then
                    begin
                      if _CurrTextLength < FILE_LINE_PART_MAX_LENGTH then
                      begin
                        Assert(_CurrTextChar <> nil);
                        _CurrTextChar^ := _CurrBufChar^;
                        Inc(_CurrTextChar); Inc(_CurrTextLength);
                      end
                      else
                      begin
                        _CorruptedLine := True;
                      end;
                    end
                    else
                    begin
                      _CorruptedLine := True;
                    end;
                  end
                  else
                  begin
                    _CorruptedLine := True;
                  end;
                end;
              end;
          end;
          Inc(_CurrBufChar);
          if ATestDB and _CorruptedLine then
          begin
            // ошибка в формате данных учетной записи - выходим с ошибкой авторизации
            Result := 201;
            WriteLn('Unauthorized. Password file format error. Line: ' + IntToStr(_LineNum));
            Exit;
          end;
        end; // for L := 1 to _NumberOfBytesRead do  // перебор символов в прочитаннм буфере

        if _FinishParsing then Break;
      end; // for K := 1 to _FILE_READ_MAX_COUNT do

    finally
      FreeMem(_FileBuffer);
    end;

  finally
    CloseHandle(_FLogFileHandle);
  end;

  if not ATestDB then
  begin
    Result := 14;
    WriteLn('Unauthorized. Account not found. Login: "' + AUsername + '", Common name: "' + ACommonName + '".');
  end
  else
  begin
    Result := 250;
    WriteLn('Database test was successful.');
  end;

end;














end.
