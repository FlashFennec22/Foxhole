//! Points Windows' adapters at 127.0.0.1 / ::1 and restores them afterwards.
//!
//! Uses PowerShell's NetTCPIP cmdlets (no extra crates, stable across Win10/11).
//! The original per-adapter settings are saved to %ProgramData%\Foxhole\dns-state.json
//! *before* any change, so `restore()` also works after a crash or from `foxhole off`.

#[cfg(windows)]
pub use win::{apply, restore};
#[cfg(not(windows))]
pub use stub::{apply, restore};

#[cfg(not(windows))]
mod stub {
    pub fn apply(_ipv6: bool) -> anyhow::Result<()> { Ok(()) }
    pub fn restore() -> anyhow::Result<()> { Ok(()) }
}

#[cfg(windows)]
mod win {
    use crate::config::data_dir;
    use anyhow::{bail, Context, Result};
    use serde::{Deserialize, Serialize};
    use std::{net::IpAddr, os::windows::process::CommandExt, path::PathBuf, process::Command};
    use tracing::{info, warn};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[derive(Serialize, Deserialize, Clone)]
    struct Saved {
        index: u32,
        name: String,
        /// Static IPv4 DNS servers the adapter had before. Empty = it used DHCP.
        original: Vec<String>,
    }

    struct Live {
        index: u32,
        name: String,
        static_dns: Vec<String>,
    }

    fn state_path() -> PathBuf {
        data_dir().join("dns-state.json")
    }

    fn load_state() -> Vec<Saved> {
        std::fs::read_to_string(state_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    fn ps(script: &str) -> Result<String> {
        let out = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .context("failed to launch powershell.exe")?;
        if !out.status.success() {
            bail!("powershell: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Active adapters plus any *static* DNS servers configured on them (read from the registry;
    /// DHCP-provided servers are deliberately not captured, so restoring = "reset to DHCP").
    fn live_adapters() -> Result<Vec<Live>> {
        let script = r#"$r = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
  $ns = $null
  try { $ns = (Get-ItemProperty -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $_.InterfaceGuid) -Name NameServer -ErrorAction Stop).NameServer } catch {}
  [pscustomobject]@{ Index = [int]$_.ifIndex; Name = [string]$_.Name; Static = [string]$ns }
})
ConvertTo-Json -InputObject $r -Compress"#;
        let text = ps(script)?;
        if text.is_empty() {
            return Ok(vec![]);
        }
        let v: serde_json::Value = serde_json::from_str(&text).context("parsing adapter list")?;
        let items = match v {
            serde_json::Value::Array(a) => a,
            obj @ serde_json::Value::Object(_) => vec![obj],
            _ => vec![],
        };
        Ok(items
            .iter()
            .filter_map(|i| {
                let index = i.get("Index")?.as_u64()? as u32;
                let name = i.get("Name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                let static_dns = i
                    .get("Static")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .split(|c: char| c == ',' || c == ' ')
                    .filter(|s| s.parse::<IpAddr>().is_ok())
                    .map(String::from)
                    .collect();
                Some(Live { index, name, static_dns })
            })
            .collect())
    }

    fn set_dns(index: u32, servers: &[String]) -> Result<()> {
        // Only validated IP literals ever get interpolated into the script.
        let list: Vec<String> = servers.iter().filter(|s| s.parse::<IpAddr>().is_ok()).map(|s| format!("'{s}'")).collect();
        if list.is_empty() {
            bail!("no valid DNS servers to set");
        }
        ps(&format!("Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses ({})", list.join(",")))?;
        Ok(())
    }

    fn reset_dns(index: u32) -> Result<()> {
        ps(&format!("Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"))?;
        Ok(())
    }

    fn flush() {
        let _ = ps("Clear-DnsClientCache");
    }

    /// Idempotent: only touches adapters that don't already point at us.
    pub fn apply(ipv6: bool) -> Result<()> {
        let ours: Vec<String> = if ipv6 { vec!["127.0.0.1".into(), "::1".into()] } else { vec!["127.0.0.1".into()] };
        let mut saved = load_state();
        let todo: Vec<Live> = live_adapters()?
            .into_iter()
            .filter(|a| !a.static_dns.iter().any(|s| s == "127.0.0.1"))
            .collect();
        if todo.is_empty() {
            return Ok(());
        }

        // Save originals first, so a crash mid-way can still be undone.
        for a in &todo {
            match saved.iter_mut().find(|s| s.index == a.index) {
                Some(s) => s.original = a.static_dns.clone(),
                None => saved.push(Saved { index: a.index, name: a.name.clone(), original: a.static_dns.clone() }),
            }
        }
        std::fs::create_dir_all(data_dir())?;
        std::fs::write(state_path(), serde_json::to_string_pretty(&saved)?)?;

        for a in &todo {
            match set_dns(a.index, &ours) {
                Ok(()) => info!(adapter = %a.name, "DNS now points at Foxhole"),
                Err(e) => warn!(adapter = %a.name, error = %e, "could not set DNS"),
            }
        }
        flush();
        Ok(())
    }

    pub fn restore() -> Result<()> {
        let saved = load_state();
        for s in &saved {
            // Reset clears both IPv4 and IPv6 entries (including our ::1); then re-add any static IPv4 servers.
            let r = reset_dns(s.index).and_then(|_| if s.original.is_empty() { Ok(()) } else { set_dns(s.index, &s.original) });
            match r {
                Ok(()) => info!(adapter = %s.name, "DNS restored"),
                Err(e) => warn!(adapter = %s.name, error = %e, "could not restore DNS"),
            }
        }
        // Safety sweep: anything still pointing at loopback (e.g. the state file was lost)
        // goes back to automatic DNS, so we never leave a machine with a dead resolver.
        if let Ok(live) = live_adapters() {
            for a in live.iter().filter(|a| a.static_dns.iter().any(|s| s == "127.0.0.1")) {
                match reset_dns(a.index) {
                    Ok(()) => info!(adapter = %a.name, "DNS reset to automatic"),
                    Err(e) => warn!(adapter = %a.name, error = %e, "could not reset DNS"),
                }
            }
        }
        let _ = std::fs::remove_file(state_path());
        flush();
        Ok(())
    }
}
