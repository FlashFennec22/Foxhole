use crate::{config::{data_dir, Config}, rules::{self, Matcher}};
use anyhow::{anyhow, bail, Result};
use std::{path::PathBuf, time::Duration};
use tracing::{info, warn};

fn lists_dir() -> PathBuf {
    data_dir().join("lists")
}

pub fn cache_path(name: &str) -> PathBuf {
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    lists_dir().join(format!("{safe}.txt"))
}

/// Build a matcher from the cached list files plus the user's custom allow/block entries.
pub fn build_matcher(cfg: &Config) -> Matcher {
    let mut m = Matcher::default();
    for l in cfg.lists.iter().filter(|l| l.enabled) {
        match std::fs::read_to_string(cache_path(&l.name)) {
            Ok(text) => m.add_list(&text),
            Err(_) => info!(list = %l.name, "no cached copy yet"),
        }
    }
    for d in &cfg.block { m.block_domain(d); }
    for d in &cfg.allow { m.allow_domain(d); }
    m
}

pub struct Outcome {
    pub changed: bool,
    pub failed: bool,
}

/// Download any list whose cache is missing or older than the update interval.
pub async fn refresh(cfg: &Config, client: &reqwest::Client) -> Outcome {
    let max_age = Duration::from_secs(cfg.update_interval_hours.max(1) * 3600 * 9 / 10);
    let mut out = Outcome { changed: false, failed: false };
    let _ = tokio::fs::create_dir_all(lists_dir()).await;

    for list in cfg.lists.iter().filter(|l| l.enabled) {
        let path = cache_path(&list.name);
        if let Ok(md) = tokio::fs::metadata(&path).await {
            if md.modified().ok().and_then(|t| t.elapsed().ok()).map_or(false, |age| age < max_age) {
                continue; // fresh enough
            }
        }
        let urls: Vec<&str> = std::iter::once(list.url.as_str()).chain(list.mirrors.iter().map(String::as_str)).collect();
        match download(client, &urls).await {
            Ok(text) => {
                let tmp = path.with_extension("tmp");
                if tokio::fs::write(&tmp, &text).await.is_ok() && tokio::fs::rename(&tmp, &path).await.is_ok() {
                    info!(list = %list.name, bytes = text.len(), "updated blocklist");
                    out.changed = true;
                } else {
                    warn!(list = %list.name, "could not write cache file");
                    out.failed = true;
                }
            }
            Err(e) => {
                warn!(list = %list.name, error = %e, "download failed (keeping cached copy)");
                out.failed = true;
            }
        }
    }
    out
}

async fn download(client: &reqwest::Client, urls: &[&str]) -> Result<String> {
    let mut last = None;
    for u in urls {
        match fetch(client, u).await {
            Ok(t) => return Ok(t),
            Err(e) => { warn!(url = %u, error = %e, "fetch failed"); last = Some(e); }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no URLs configured")))
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<String> {
    let text = client.get(url).send().await?.error_for_status()?.text().await?;
    // Never replace a good cache with an HTML error page or an empty file.
    if rules::parse_list(&text).next().is_none() {
        bail!("response contained no usable rules");
    }
    Ok(text)
}
