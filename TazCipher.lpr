library TazCipher;

{$mode objfpc}{$H+}

uses
  Classes,
  SysUtils,

  DCPrijndael,
  DCPsha256,

  Base64;


function StringToStream(const Data: String): TStream;
begin
  Result := TStringStream.Create(Data, TEncoding.ANSI);
end;

function Encrypt(const Data, Key: TStream): TStream; stdcall;
var
  DataStream, KeyStream: TStringStream;
  Cipher: TDCP_rijndael;
  DataString, KeyString: String;
begin
  Data.Position := 0;
  Key.Position := 0;
  DataStream := TStringStream.Create('', TEncoding.ANSI);
  KeyStream := TStringStream.Create('', TEncoding.ANSI);
  Cipher := TDCP_rijndael.Create(nil);
  try
    DataStream.CopyFrom(Data, Data.Size);
    KeyStream.CopyFrom(Key, Key.Size);
    DataString := DataStream.DataString;
    KeyString := KeyStream.DataString;
    Cipher.InitStr(KeyString, TDCP_sha256);
    DataString := Cipher.EncryptString(DataString);
    Result := StringToStream(EncodeStringBase64(DataString));
  finally
    Cipher.Burn;
    FreeAndNil(Cipher);
    FreeAndNil(DataStream);
    FreeAndNil(KeyStream);
  end;
end;

function Decrypt(const Data, Key: TStream): TStream; stdcall;
var
  DataStream, KeyStream: TStringStream;
  Cipher: TDCP_rijndael;
  DataString, KeyString: String;
begin
  Data.Position := 0;
  Key.Position := 0;
  DataStream := TStringStream.Create('', TEncoding.ANSI);
  KeyStream := TStringStream.Create('', TEncoding.ANSI);
  Cipher := TDCP_rijndael.Create(nil);
  try
    DataStream.CopyFrom(Data, Data.Size);
    KeyStream.CopyFrom(Key, Key.Size);
    DataString := DataStream.DataString;
    KeyString := KeyStream.DataString;
    Cipher.InitStr(KeyString, TDCP_sha256);
    DataString := DecodeStringBase64(DataString);
    Result := StringToStream(Cipher.DecryptString(DataString));
  finally
    Cipher.Burn;
    FreeAndNil(Cipher);
    FreeAndNil(DataStream);
    FreeAndNil(KeyStream);
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
