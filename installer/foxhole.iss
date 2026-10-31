; Foxhole installer (Inno Setup 6). Build the exes first, then compile this script:
;   cargo build --release
;   ISCC.exe installer\foxhole.iss        ->  installer\Output\Foxhole-Setup-<version>.exe
;
; The installer copies the files and owns the Installed-apps entry and removal. Registering the
; Windows service and pointing DNS at it stays in foxhole.exe (hidden `install-service`,
; `prepare-upgrade` and `uninstall-service` commands), so `foxhole on/off` share the same code.

#define BinDir "..\target\release"
#define AppVersion GetStringFileInfo(BinDir + "\foxhole.exe", "ProductVersion")

[Setup]
; Never change AppId: it is how upgrades and the uninstaller find an existing install.
AppId={{9E57A5C3-1D88-4E68-9BBA-3EC9E345B62D}
AppName=Foxhole
AppVersion={#AppVersion}
AppVerName=Foxhole {#AppVersion}
AppPublisher=Foxhole
AppPublisherURL=https://github.com/FlashFennec22/Foxhole
UninstallDisplayName=Foxhole DNS Ad Blocker
UninstallDisplayIcon={app}\foxhole.exe
DefaultDirName={autopf}\Foxhole
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 2004: the first version with SetInterfaceDnsSettings.
MinVersion=10.0.19041
SetupIconFile=..\resources\foxhole.ico
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=Foxhole-Setup-{#AppVersion}
VersionInfoVersion={#AppVersion}
VersionInfoDescription=Foxhole DNS ad blocker setup
; Upgrades normally stop everything in PrepareToInstall. Restart Manager is the fallback for
; tray icons from versions before this installer, which don't listen for the exit signal and
; ignore Restart Manager's close request, hence "force".
CloseApplications=force
RestartApplications=no

[Files]
Source: "{#BinDir}\foxhole.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\foxhole-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"

[Icons]
Name: "{autoprograms}\Foxhole"; Filename: "{app}\foxhole-tray.exe"; Comment: "Show the Foxhole status icon"

[Registry]
; Versions before this installer registered their own Installed-apps entry under this key.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\Foxhole"; Flags: deletekey dontcreatekey

[UninstallDelete]
; Inno only removes folders it created; the self-installing versions before it created this one.
Type: dirifempty; Name: "{app}"

[Run]
; Runs un-elevated as the user who started Setup. Also runs for silent installs.
Filename: "{app}\foxhole-tray.exe"; Description: "Show the Foxhole icon in the notification area"; Flags: nowait postinstall runasoriginaluser

[Code]
function RunFoxhole(const Params: String): Integer;
begin
  if not Exec(ExpandConstant('{app}\foxhole.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Result) then
    Result := -1;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  // Upgrade: stop the service (which restores DNS) and close tray icons so the files can be replaced.
  // Versions before this installer don't know `prepare-upgrade`; `off` does the same for them.
  if FileExists(ExpandConstant('{app}\foxhole.exe')) then
    if RunFoxhole('prepare-upgrade') <> 0 then
      RunFoxhole('off');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    Code := RunFoxhole('install-service');
    if Code <> 0 then
      SuppressibleMsgBox('Foxhole was installed, but protection could not be turned on (error ' + IntToStr(Code) + ').'
        + #13#10#13#10 + 'Details are in ' + ExpandConstant('{commonappdata}') + '\Foxhole\foxhole.log.',
        mbError, MB_OK, IDOK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  // Before any files are removed: stop protection, restore the original DNS settings, close tray
  // icons and delete the service.
  if CurUninstallStep = usUninstall then
    RunFoxhole('uninstall-service');

  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\Foxhole');
    if DirExists(DataDir) then
      if SuppressibleMsgBox('Also delete Foxhole''s settings, cached blocklists and logs?',
           mbConfirmation, MB_YESNO, IDNO) = IDYES then
        DelTree(DataDir, True, True, True);
  end;
end;
