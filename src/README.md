# Foxhole (draft)

Local DNS ad blocker for Windows. Ingests AdGuard-style (`||domain^`), hosts and plain-domain lists;
defaults to **Hagezi Pro++**. Upstream DNS is DoH (Cloudflare) with a plain-UDP fallback.

## Build
    cargo test
    cargo build --release          # target\release\foxhole.exe + foxhole-tray.exe
    # keep both exes together: the installer copies both to Program Files

## Use
    foxhole.exe          # double-click: UAC prompt -> installs service -> protection ON
    foxhole off          # restore original DNS, stay off across reboots
    foxhole on           # turn back on
    foxhole status
    foxhole uninstall
    foxhole run --no-system-dns   # foreground debug mode (admin needed for port 53)

Config / cache / logs: `%ProgramData%\Foxhole\` (config.toml, lists\, dns-state.json, foxhole.log).

## How it works
1. Service (auto-start, auto-restart) listens on 127.0.0.1:53 and [::1]:53 (UDP+TCP).
2. Blocked names (domain + all subdomains) get 0.0.0.0 / :: (A / AAAA) or an empty NOERROR; everything else is forwarded upstream.
3. Active adapters are pointed at loopback; originals are saved first and restored on stop/off.
4. Lists refresh every 24h; the last good cache is kept if a download fails.

## Tray icon
`foxhole-tray.exe` (unelevated, no console window) shows green/grey/amber/red status, blocked-query counts
(from `%ProgramData%\Foxhole\stats.json`, written by the service every 10 s), and toggles protection by
starting/stopping the service. Installing grants interactive users start/stop (not reconfigure) rights on the service.
Menu "Turn protection off" stops the service until the next reboot; `foxhole off` keeps it off across reboots.
