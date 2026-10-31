mod config;
mod dns;
mod engine;
mod lists;
mod rules;
mod sysdns;
mod upstream;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod trayctl;
#[cfg(windows)]
mod winctl;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{data_dir, Config};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Parser)]
#[command(name = "foxhole", version, about = "One-click DNS ad blocker (AdGuard-style lists; Hagezi Pro++ by default)")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Internal: set on the copy started through UAC, so it never tries to elevate again.
    #[arg(long, hide = true, global = true)]
    elevated: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Turn protection on (and restart it, to apply config changes). This is also what double-clicking does.
    On {
        #[arg(long, hide = true)]
        pause: bool,
        #[arg(long, hide = true)]
        no_tray: bool,
    },
    /// Turn protection off and restore the original DNS settings
    Off,
    /// Show whether protection is running
    Status,
    /// Open the uninstaller (restores your DNS settings and removes Foxhole)
    Uninstall,
    /// Run in the foreground for debugging (Ctrl+C to stop)
    Run {
        /// Don't touch Windows' DNS settings; just listen on 127.0.0.1:53
        #[arg(long)]
        no_system_dns: bool,
    },
    /// Internal: entry point used by the Windows Service Control Manager
    #[command(hide = true)]
    Service,
    /// Internal (installer): register the service for this exe and start it
    #[command(hide = true)]
    InstallService,
    /// Internal (installer): stop the service and tray icons before an upgrade replaces the files
    #[command(hide = true)]
    PrepareUpgrade,
    /// Internal (uninstaller): restore DNS and remove the service
    #[command(hide = true)]
    UninstallService,
}

fn init_logging(to_file: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if to_file {
        let _ = std::fs::create_dir_all(data_dir());
        let path = data_dir().join("foxhole.log");
        // crude rotation: start fresh once the log passes 5 MB
        if std::fs::metadata(&path).map(|m| m.len() > 5_000_000).unwrap_or(false) {
            let _ = std::fs::remove_file(&path);
        }
        if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(Mutex::new(f)).init();
            return;
        }
    }
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Run { no_system_dns }) => run_foreground(!no_system_dns),
        other => windows_cmd(other.unwrap_or(Cmd::On { pause: true, no_tray: false }), cli.elevated),
    }
}

fn run_foreground(manage_dns: bool) -> Result<()> {
    init_logging(false);
    let cfg = Config::load_or_create()?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        let shutdown = Arc::new(Notify::new());
        let s2 = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            s2.notify_one();
        });
        engine::run(cfg, shutdown, manage_dns, || {}).await
    })
}

#[cfg(not(windows))]
fn windows_cmd(_: Cmd, _: bool) -> Result<()> {
    anyhow::bail!("this command is only available on Windows (use `run --no-system-dns` to test elsewhere)")
}

#[cfg(windows)]
fn windows_cmd(cmd: Cmd, elevated: bool) -> Result<()> {
    use winctl::Status;

    // If we aren't elevated, hands the job to an elevated copy of ourselves and returns its exit code.
    let elevate = |args: &[&str]| -> Result<Option<u32>> {
        if winctl::is_admin() {
            return Ok(None);
        }
        if elevated {
            anyhow::bail!("this needs administrator rights, but the elevated copy didn't get them");
        }
        winctl::relaunch_elevated(args).map(Some)
    };
    fn pause() {
        println!("\nPress Enter to close...");
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }

    match cmd {
        Cmd::On { pause: p, no_tray } => {
            // The elevated copy skips the tray; we launch it afterwards un-elevated, as the user.
            let mut args = vec!["on", "--no-tray"];
            if p { args.push("--pause"); }
            if let Some(code) = elevate(&args)? {
                if code == 0 { winctl::launch_tray(); }
                std::process::exit(code as i32);
            }
            let r = winctl::turn_on();
            match &r {
                Ok(()) => println!("\nFoxhole is ON. Ads and trackers are now blocked system-wide."),
                Err(e) => println!("\nCould not start Foxhole: {e:#}"),
            }
            if r.is_ok() && !no_tray { winctl::launch_tray(); }
            if p { pause(); }
            // The error was already shown above; just report it through the exit code.
            if r.is_err() { std::process::exit(1); }
            Ok(())
        }
        Cmd::Off => {
            if let Some(code) = elevate(&["off"])? { std::process::exit(code as i32); }
            init_logging(false);
            winctl::turn_off()?;
            println!("Foxhole is OFF. Your original DNS settings were restored.");
            Ok(())
        }
        Cmd::Uninstall => winctl::run_uninstaller(),
        Cmd::Status => {
            println!("{}", match winctl::status() {
                Status::Running => "ON (service running)",
                Status::Stopped => "OFF (service stopped)",
                Status::NotInstalled => "not installed",
                Status::Other => "starting/stopping",
            });
            Ok(())
        }
        Cmd::Service => {
            init_logging(true);
            service::dispatch().map_err(Into::into)
        }
        // Run by the (already elevated) installer with no console; details go to foxhole.log.
        Cmd::InstallService | Cmd::PrepareUpgrade | Cmd::UninstallService => {
            init_logging(true);
            if !winctl::is_admin() {
                anyhow::bail!("this command is for the installer and needs administrator rights");
            }
            let r = match cmd {
                Cmd::InstallService => winctl::install_service(),
                Cmd::PrepareUpgrade => winctl::prepare_upgrade(),
                _ => winctl::uninstall_service(),
            };
            if let Err(e) = &r {
                tracing::error!(error = %format!("{e:#}"), "installer step failed");
            }
            r
        }
        Cmd::Run { .. } => unreachable!(),
    }
}
