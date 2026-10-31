# Foxhole (draft)

Local DNS ad blocker for Windows. Ingests AdGuard-style (`||domain^`), hosts and plain-domain lists;
defaults to **Hagezi Pro++**. Upstream DNS is DoH (Cloudflare) with a plain-UDP fallback.

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

## How it works
1. Service (auto-start, auto-restart) listens on 127.0.0.1:53 and [::1]:53 (UDP+TCP).
2. Blocked names (domain + all subdomains) get 0.0.0.0 / :: (A / AAAA) or an empty NOERROR; everything else is forwarded upstream.
3. Active adapters are pointed at loopback; originals are saved first and restored on stop/off.
   Adapters that appear or change later (Wi-Fi, VPN, docking) are picked up within seconds.
4. Lists refresh every 24h; the last good cache is kept if a download fails.

## Tray icon
`foxhole-tray.exe` (unelevated, no console window) shows green/grey/amber/red status, blocked-query counts
(from `%ProgramData%\Foxhole\stats.json`, written by the service every 10 s), and toggles protection by
starting/stopping the service. The installer grants interactive users start/stop (not reconfigure) rights on the service.
Menu "Turn protection off" stops the service until the next reboot; `foxhole off` keeps it off across reboots.
