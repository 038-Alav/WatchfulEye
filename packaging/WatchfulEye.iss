#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif

#define AppName "Watchful Eye"
#define AppExeName "WatchfulEye.exe"
#define AppPublisher "Watchful Eye"

[Setup]
AppId={{D1E15C82-26F1-4F9D-B13D-A4E0C0B1286B}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Watchful Eye
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=WatchfulEye-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
UninstallDisplayName={#AppName}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\WatchfulEye\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
function IsNpcapInstalled(): Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll')) or
    FileExists(ExpandConstant('{sys}\wpcap.dll'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and (not IsNpcapInstalled()) then
  begin
    MsgBox(
      'Watchful Eye has been installed. Some packet-based discovery features on Windows require Npcap. ' +
      'The application can start without it, but ARP/ICMP packet operations and passive packet capture ' +
      'may be unavailable. Install Npcap separately from https://npcap.com/ and restart Watchful Eye.',
      mbInformation,
      MB_OK
    );
  end;
end;
