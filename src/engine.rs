use crate::{config::{data_dir, Config}, dns::{self, State}, lists, sysdns, upstream::Upstream};
use anyhow::{Context, Result};
use std::{net::{Ipv4Addr, Ipv6Addr}, sync::{atomic::Ordering::Relaxed, Arc}, time::Duration};
use tokio::{net::{TcpListener, UdpSocket}, sync::Notify};
use tracing::{info, warn};

/// Runs the resolver until `shutdown` is notified. If `manage_dns`, points Windows at us
/// while running and restores the original settings on exit.
pub async fn run(cfg: Config, shutdown: Arc<Notify>, manage_dns: bool) -> Result<()> {
    let upstream = Upstream::new(&cfg.upstream)?;

    // Start protecting immediately from the cached lists; fresh downloads swap in later.
    let c = cfg.clone();
    let matcher = tokio::task::spawn_blocking(move || lists::build_matcher(&c)).await?;
    info!(rules = matcher.len(), "loaded cached blocklists");
    let state = Arc::new(State::new(matcher, upstream));

    // Bind first: if port 53 is taken we fail *before* touching the system's DNS settings.
    let v4 = Ipv4Addr::LOCALHOST;
    let udp = UdpSocket::bind((v4, 53)).await
        .context("cannot listen on 127.0.0.1:53/UDP (another DNS service, ICS or Docker may be using port 53)")?;
    let tcp = TcpListener::bind((v4, 53)).await.context("cannot listen on 127.0.0.1:53/TCP")?;
    tokio::spawn(dns::serve_udp(udp, state.clone()));
    tokio::spawn(dns::serve_tcp(tcp, state.clone()));

    let mut ipv6 = false;
    match (UdpSocket::bind((Ipv6Addr::LOCALHOST, 53)).await, TcpListener::bind((Ipv6Addr::LOCALHOST, 53)).await) {
        (Ok(u), Ok(t)) => {
            tokio::spawn(dns::serve_udp(u, state.clone()));
            tokio::spawn(dns::serve_tcp(t, state.clone()));
            ipv6 = true;
        }
        _ => warn!("could not listen on [::1]:53; IPv6 DNS server entry will not be set"),
    }
    info!(ipv6, "DNS listener ready on loopback port 53");

    tokio::spawn(updater(cfg.clone(), state.clone()));
    tokio::spawn(stats_writer(state.clone()));

    // Make sure all active adapters point at us: immediately, whenever Windows reports an
    // interface/address change (Wi-Fi switch, VPN, new adapter, DHCP), and every few minutes as a
    // safety net in case something rewrites the settings without a network change.
    let watcher = if manage_dns {
        sysdns::Watcher::new().map_err(|e| warn!(error = %e, "cannot watch network changes; polling only")).ok()
    } else {
        None
    };
    let mut tick = tokio::time::interval(Duration::from_secs(if watcher.is_some() { 300 } else { 60 }));
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {}
            _ = async { match &watcher { Some(w) => w.changed().await, None => std::future::pending().await } } => {
                // Changes arrive in bursts (link up, DHCP, IPv6 autoconfiguration): let them settle,
                // without delaying a shutdown that arrives meanwhile.
                tokio::select! {
                    _ = shutdown.notified() => break,
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                }
            }
        }
        if manage_dns {
            match tokio::task::spawn_blocking(move || sysdns::apply(ipv6)).await {
                Ok(Err(e)) => warn!(error = %e, "failed to apply system DNS settings"),
                Err(e) => warn!(error = %e, "DNS task panicked"),
                _ => {}
            }
        }
    }
    drop(watcher);

    info!(total = state.total.load(Relaxed), blocked = state.blocked.load(Relaxed), "shutting down");
    if manage_dns {
        if let Ok(Err(e)) = tokio::task::spawn_blocking(sysdns::restore).await {
            warn!(error = %e, "failed to restore DNS settings; run `foxhole off`");
        }
    }
    Ok(())
}

async fn updater(cfg: Config, state: Arc<State>) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(120)).build() {
        Ok(c) => c,
        Err(e) => { warn!(error = %e, "cannot build HTTP client; list updates disabled"); return; }
    };
    let interval = Duration::from_secs(cfg.update_interval_hours.max(1) * 3600);
    loop {
        let outcome = lists::refresh(&cfg, &client).await;
        if outcome.changed {
            let c = cfg.clone();
            if let Ok(m) = tokio::task::spawn_blocking(move || lists::build_matcher(&c)).await {
                info!(rules = m.len(), "blocklist reloaded");
                state.set_matcher(m);
            }
        }
        // Retry sooner after a failure (e.g. no network at boot).
        tokio::time::sleep(if outcome.failed { Duration::from_secs(600) } else { interval }).await;
    }
}

/// Publishes counters for the tray app (read-only for normal users) every 10 seconds.
async fn stats_writer(state: Arc<State>) {
    let path = data_dir().join("stats.json");
    let tmp = path.with_extension("tmp");
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        let json = format!(
            r#"{{"total":{},"blocked":{},"rules":{}}}"#,
            state.total.load(Relaxed),
            state.blocked.load(Relaxed),
            state.rule_count()
        );
        if tokio::fs::write(&tmp, json).await.is_ok() {
            let _ = tokio::fs::rename(&tmp, &path).await;
        }
    }
}
