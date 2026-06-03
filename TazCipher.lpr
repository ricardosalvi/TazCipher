library TazCipher;

{$mode objfpc}{$H+}

uses
  Classes,
  SysUtils,

  DCPrijndael,
  DCPsha256,

  Base64;


function StringToStream(Data: String): TStream;
begin
  Result := TStringStream.Create(Data, TEncoding.ANSI);
end;

function Encrypt(Data, Key: PAnsiChar): PAnsiChar; stdcall;
var
  DataEncrypted: PAnsiChar;
  Cipher: TDCP_rijndael;
begin
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.InitStr(Key, TDCP_sha256);
    DataEncrypted := PAnsiChar(Cipher.EncryptString(Data));
    Result := PAnsiChar(EncodeStringBase64(DataEncrypted));
  finally
    Cipher.Burn;
    FreeAndNil(Cipher);
  end;
end;

function Decrypt(Data, Key: PAnsiChar): PAnsiChar; stdcall;
var
  DataDecrypted: PAnsiChar;
  Cipher: TDCP_rijndael;
begin
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.InitStr(Key, TDCP_sha256);
    DataDecrypted := PAnsiChar(DecodeStringBase64(Data));
    Result := PAnsiChar(Cipher.DecryptString(DataDecrypted));
  finally
    Cipher.Burn;
    FreeAndNil(Cipher);
  end;
end;

procedure FreeStream(Data: TStream); stdcall;
begin
  if Assigned(Data) then
    FreeAndNil(Data);
end;

exports
  Encrypt,
  Decrypt,
  FreeStream;

{$R *.res}

begin
  //
end.
