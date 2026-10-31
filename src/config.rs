use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

pub const APP_NAME: &str = "Foxhole";

/// %ProgramData%\Foxhole (service runs as LocalSystem, so use a machine-wide location).
pub fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join(APP_NAME)
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(format!("./{}-data", APP_NAME.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// How often to re-download blocklists.
    pub update_interval_hours: u64,
    pub lists: Vec<ListSource>,
    pub upstream: UpstreamConfig,
    /// Domains (and their subdomains) that are never blocked.
    pub allow: Vec<String>,
    /// Extra domains (and their subdomains) to always block.
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSource {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub mirrors: Vec<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamConfig {
    /// Per-attempt timeout for each upstream, in milliseconds.
    pub timeout_ms: u64,
    /// Plain-UDP last resort if every DoH server is down. Set to [] to never fall back to unencrypted DNS.
    pub fallback: Vec<SocketAddr>,
    /// DNS-over-HTTPS servers, tried in order. Servers that fail are skipped for 30 s.
    pub doh: Vec<DohServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DohServer {
    pub url: String,
    /// Hostname in `url`; pinned to `ips` so we never need DNS to reach DNS.
    pub host: String,
    pub ips: Vec<IpAddr>,
}

fn yes() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            update_interval_hours: 24,
            lists: vec![ListSource {
                name: "hagezi-pro-plus".into(),
                url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt".into(),
                mirrors: vec![
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt".into(),
                ],
                enabled: true,
            }],
            upstream: UpstreamConfig::default(),
            allow: vec![],
            block: vec![],
        }
    }
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 1500,
            fallback: vec!["1.1.1.1:53".parse().unwrap(), "9.9.9.9:53".parse().unwrap()],
            doh: vec![
                DohServer {
                    url: "https://cloudflare-dns.com/dns-query".into(),
                    host: "cloudflare-dns.com".into(),
                    ips: vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
                },
                DohServer {
                    url: "https://dns.quad9.net/dns-query".into(),
                    host: "dns.quad9.net".into(),
                    ips: vec!["9.9.9.9".parse().unwrap(), "149.112.112.112".parse().unwrap()],
                },
            ],
        }
    }
}

impl Config {
    pub fn path() -> PathBuf {
        data_dir().join("config.toml")
    }

    pub fn load_or_create() -> Result<Self> {
        let path = Self::path();
        std::fs::create_dir_all(data_dir()).context("creating data directory")?;
        if path.exists() {
            let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            return toml::from_str(&text).with_context(|| format!("parsing {}", path.display()));
        }
        let cfg = Config::default();
        let header = "# Foxhole configuration. Restart the service after editing (`foxhole on`).\n\
                      # Add more AdGuard-style / hosts / domain lists as extra [[lists]] entries.\n\n";
        std::fs::write(&path, format!("{header}{}", toml::to_string_pretty(&cfg)?))?;
        Ok(cfg)
    }
}
