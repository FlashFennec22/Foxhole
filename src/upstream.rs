use crate::config::UpstreamConfig;
use anyhow::{anyhow, bail, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};
use tracing::{debug, info, warn};

/// How long a DoH server that just failed is skipped before being tried again.
const DOWN_FOR_MS: u64 = 30_000;

struct Server {
    url: String,
    /// Milliseconds since `Upstream::start` until which this server is considered down.
    down_until: AtomicU64,
}

/// Forwards raw DNS packets upstream: DoH servers in order (skipping ones that recently
/// failed), then plain UDP as a last resort.
pub struct Upstream {
    client: reqwest::Client,
    servers: Vec<Server>,
    fallback: Vec<SocketAddr>,
    timeout: Duration,
    start: Instant,
}

impl Upstream {
    pub fn new(cfg: &UpstreamConfig) -> Result<Self> {
        let mut b = reqwest::Client::builder()
            .pool_idle_timeout(Duration::from_secs(60))
            .user_agent(concat!("foxhole/", env!("CARGO_PKG_VERSION")));
        for s in &cfg.doh {
            if !s.ips.is_empty() {
                // Pin each DoH hostname: our own resolver must never be needed to reach upstream.
                let addrs: Vec<SocketAddr> = s.ips.iter().map(|ip| SocketAddr::new(*ip, 443)).collect();
                b = b.resolve_to_addrs(&s.host, &addrs);
            }
        }
        Ok(Self {
            client: b.build()?,
            servers: cfg.doh.iter().map(|s| Server { url: s.url.clone(), down_until: AtomicU64::new(0) }).collect(),
            fallback: cfg.fallback.clone(),
            timeout: Duration::from_millis(cfg.timeout_ms.max(200)),
            start: Instant::now(),
        })
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub async fn resolve(&self, packet: &[u8]) -> Result<Vec<u8>> {
        for s in &self.servers {
            if s.down_until.load(Relaxed) > self.now_ms() {
                continue; // recently failed: don't make every query wait on it again
            }
            match self.doh(&s.url, packet).await {
                Ok(r) => {
                    // Back in service after being marked down?
                    if s.down_until.swap(0, Relaxed) != 0 {
                        info!(server = %s.url, "DoH server recovered");
                    }
                    return Ok(r);
                }
                Err(e) => {
                    let now = self.now_ms();
                    let prev = s.down_until.swap(now + DOWN_FOR_MS, Relaxed);
                    if prev <= now {
                        warn!(server = %s.url, error = %e, "DoH server failed; skipping it for 30s");
                    }
                }
            }
        }
        debug!("no DoH server available, using plain UDP fallback");
        self.udp(packet).await
    }

    async fn doh(&self, url: &str, packet: &[u8]) -> Result<Vec<u8>> {
        let resp = self
            .client
            .post(url)
            .timeout(self.timeout)
            .header(CONTENT_TYPE, "application/dns-message")
            .header(ACCEPT, "application/dns-message")
            .body(packet.to_vec())
            .send()
            .await?
            .error_for_status()?;
        let bytes = resp.bytes().await?;
        if bytes.len() < 12 {
            bail!("short DoH response");
        }
        Ok(bytes.to_vec())
    }

    async fn udp(&self, packet: &[u8]) -> Result<Vec<u8>> {
        for server in &self.fallback {
            let attempt = async {
                let sock = UdpSocket::bind("0.0.0.0:0").await?;
                sock.send_to(packet, server).await?;
                let mut buf = vec![0u8; 4096];
                let (n, _) = timeout(self.timeout, sock.recv_from(&mut buf)).await??;
                buf.truncate(n);
                Ok::<_, anyhow::Error>(buf)
            };
            if let Ok(r) = attempt.await {
                return Ok(r);
            }
        }
        Err(anyhow!("all upstreams failed"))
    }
}
