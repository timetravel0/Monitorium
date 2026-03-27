[Setup]
AppName=Client Service
AppVersion=1.0
DefaultDirName={pf}\ClientService
DefaultGroupName=Client Service
UninstallDisplayIcon={app}\ClientService.exe
OutputDir=output
OutputBaseFilename=ClientServiceSetup
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\probe.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{app}\probe.exe"; Description: "Install Client Service"; Flags: postinstall nowait runhidden