# Foxhole (draft)

Local DNS ad blocker for Windows. Ingests AdGuard-style (`||domain^`), hosts and plain-domain lists;
defaults to **Hagezi Pro++**. Upstream DNS is DoH (Cloudflare Security) with a plain-UDP fallback.

Requires Windows 10 version 2004 or later (x64).

## Build
    cargo test
    cargo build --release          # target\release\foxhole.exe + foxhole-tray.exe
    ISCC.exe installer\foxhole.iss # installer\Output\Foxhole-Setup-<version>.exe

`ISCC.exe` comes with [Inno Setup 6](https://jrsoftware.org/isinfo.php) (`winget install JRSoftware.InnoSetup`).

## Use
Run `Foxhole-Setup-<version>.exe`: it installs to Program Files, starts the service (protection ON)
and shows the tray icon. Uninstall from Settings > Apps, which also restores your DNS settings.

    foxhole off          # restore original DNS, stay off across reboots
    foxhole on           # turn back on (also restarts it, to apply config.toml changes)
    foxhole status
    foxhole uninstall    # opens the uninstaller
    foxhole run --no-system-dns   # foreground debug mode on 127.0.0.1:53, no install needed

Config / cache / logs: `%ProgramData%\Foxhole\` (config.toml, lists\, dns-state.json, foxhole.log).
Only SYSTEM and Administrators can write there, so editing config.toml takes an elevated editor. The installer
and the service enforce this: anything in the folder not owned by SYSTEM or Administrators is removed when the
service starts, and an untrusted config.toml is renamed to config.toml.untrusted.

## How it works
1. Service (auto-start, auto-restart) listens on 127.0.0.1:53 and [::1]:53 (UDP+TCP).
2. Blocked names (domain + all subdomains) get 0.0.0.0 / :: (A / AAAA) or an empty NOERROR; everything else is forwarded upstream.
3. Active adapters are pointed at loopback; originals are saved first and restored on stop/off.
   Adapters that appear or change later (Wi-Fi, VPN, docking) are picked up within seconds.
4. Lists refresh every 24h; the last good cache is kept if a download fails.
5. If the service can't start (bad config.toml, port 53 in use), it puts the original DNS settings back,
   so the PC stays online, and tries again after 10, 30, 60 and 120 seconds. `foxhole off` or the tray's
   "Stop trying" ends that early. After the fifth failed attempt it stops and writes `start-failed.json`,
   which the tray icon shows to each signed-in user once; protection then stays off until it is turned on
   again or Windows restarts.

## Tray icon
`foxhole-tray.exe` (unelevated, no console window) shows a fox head coloured by status (green with eyes open = on;
eyes shut: grey = off, amber = working, red = not installed), blocked-query counts
(from `%ProgramData%\Foxhole\stats.json`, written by the service every 10 s), and toggles protection by
starting/stopping the service. The installer grants interactive users start/stop (not reconfigure) rights on the service.
Menu "Turn protection off" stops the service until the next reboot; `foxhole off` keeps it off across reboots.

## Updates
The tray checks GitHub's latest release once a day (menu: "Check for updates", and a checkbox to turn the
daily check off; settings in `HKCU\Software\Foxhole`). A newer version pops up once; after that the menu
item reads "Install Foxhole x.y.z…". Installing downloads the release's installer to
`%LOCALAPPDATA%\Foxhole\updates\`, checks it against the signed SHA-256 digest (below), and runs it with
`/SILENT` (Windows asks for admin rights).

### Update signing
Updates are signed with an offline [minisign](https://jedisct1.github.io/minisign/) (Ed25519) key, so
control of the GitHub repository or account isn't enough to push an update. Each release carries
`foxhole-update.json` (version, installer name, size, SHA-256, notes) and its signature. The tray verifies
that against `resources/update-signing.pub`, compiled into the exe, before showing or doing anything. Nothing
else GitHub says is trusted, and a release with a missing or invalid signature is never offered.

One-time setup (the build needs `resources/update-signing.pub`; `winget install jedisct1.minisign`):

    minisign -G -p resources\update-signing.pub -s <somewhere outside this repo>\foxhole.key

Commit the `.pub` file. **Keep the `.key` file and its password out of this repository and off GitHub,
including Actions secrets**, and keep a backup: without the key, installed copies can't receive updates
and users must reinstall by hand. To replace the key, publish a release signed with the old key that
contains the new `.pub` file; versions after it are then signed with the new key.

To publish a release the checker can use:
1. Bump `version` in `Cargo.toml` **first**: the installer reads it from the exe.
2. Build the exes and the installer (above).
3. Sign it: `.\installer\sign-release.ps1 -SecretKey <path>\foxhole.key -NotesFile notes.txt`
4. Tag it `vX.Y.Z` and attach `Foxhole-Setup-X.Y.Z.exe` (not zipped), `foxhole-update.json` and
   `foxhole-update.json.minisig` from `installer\Output\` to the release.

Versions before signing don't check any of this, so they stay exposed until they update to a signed version.
