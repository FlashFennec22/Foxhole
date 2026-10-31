//! Install / start / stop / uninstall the Windows service by driving `sc.exe`,
//! plus UAC self-elevation.

use crate::{config::{data_dir, Config}, service::SERVICE_NAME, sysdns};
use anyhow::{bail, Context, Result};
use std::{os::windows::process::CommandExt, path::{Path, PathBuf}, process::Command, time::{Duration, Instant}};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const TRAY_EXE: &str = "foxhole-tray.exe";
const UNINSTALL_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Foxhole";

/// Service ACL: SYSTEM + Administrators keep full control; interactive users may query,
/// START and STOP the service (so the tray can toggle without UAC) but NOT change its config.
const SERVICE_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

pub fn is_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

/// Re-launch this exe through UAC with the given args and wait for it to finish.
pub fn relaunch_elevated(args: &[&str]) -> Result<()> {
    println!("Requesting administrator permission...");
    let exe = std::env::current_exe()?.display().to_string().replace('\'', "''");
    let arglist = if args.is_empty() {
        String::new()
    } else {
        format!(" -ArgumentList {}", args.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(","))
    };
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &format!("Start-Process -FilePath '{exe}' -Verb RunAs -Wait{arglist}")])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .context("failed to request administrator rights")?;
    if !status.success() {
        bail!("administrator permission was not granted");
    }
    Ok(())
}

fn sc(args: &[&str]) -> Result<(bool, String)> {
    let out = Command::new("sc.exe").args(args).creation_flags(CREATE_NO_WINDOW).output().context("running sc.exe")?;
    Ok((out.status.success(), String::from_utf8_lossy(&out.stdout).to_string()))
}

fn exists() -> bool {
    sc(&["query", SERVICE_NAME]).map(|(ok, _)| ok).unwrap_or(false)
}

#[derive(Debug, PartialEq)]
pub enum Status { NotInstalled, Running, Stopped, Other }

pub fn status() -> Status {
    match sc(&["query", SERVICE_NAME]) {
        Ok((true, out)) if out.contains("RUNNING") => Status::Running,
        Ok((true, out)) if out.contains("STOPPED") => Status::Stopped,
        Ok((true, _)) => Status::Other,
        _ => Status::NotInstalled,
    }
}

fn wait_for(target: Status, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if status() == target { return true; }
        std::thread::sleep(Duration::from_millis(300));
    }
    status() == target
}

fn stop() {
    if exists() && status() != Status::Stopped {
        let _ = sc(&["stop", SERVICE_NAME]);
        wait_for(Status::Stopped, 15);
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.display().to_string().eq_ignore_ascii_case(&b.display().to_string())
}

fn kill_tray() {
    let _ = Command::new("taskkill").args(["/IM", TRAY_EXE, "/F"]).creation_flags(CREATE_NO_WINDOW).output();
}

/// Start the tray app (best effort). Call from a NON-elevated process so it runs as the user.
pub fn launch_tray() {
    let p = install_dir().join(TRAY_EXE);
    if p.exists() {
        let _ = Command::new(p).spawn();
    }
}


/// Adds the entry shown in Settings -> Apps -> Installed apps.
fn register_uninstall(exe: &Path) {
    let exe_s = exe.display().to_string();
    let dir_s = install_dir().display().to_string();
    let uninstall_cmd = format!("\"{exe_s}\" uninstall --pause");
    let values: [(&str, &str, &str); 8] = [
        ("DisplayName", "REG_SZ", "Foxhole DNS Ad Blocker"),
        ("DisplayVersion", "REG_SZ", env!("CARGO_PKG_VERSION")),
        ("Publisher", "REG_SZ", "Foxhole"),
        ("InstallLocation", "REG_SZ", dir_s.as_str()),
        ("DisplayIcon", "REG_SZ", exe_s.as_str()),
        ("UninstallString", "REG_SZ", uninstall_cmd.as_str()),
        ("NoModify", "REG_DWORD", "1"),
        ("NoRepair", "REG_DWORD", "1"),
    ];
    for (name, kind, value) in values {
        let _ = Command::new("reg")
            .args(["add", UNINSTALL_KEY, "/v", name, "/t", kind, "/d", value, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

fn reg_delete(key: &str, value: Option<&str>) {
    let mut cmd = Command::new("reg");
    cmd.args(["delete", key]);
    match value {
        Some(v) => { cmd.args(["/v", v]); }
        None => { cmd.arg("/va"); }
    }
    let _ = cmd.arg("/f").creation_flags(CREATE_NO_WINDOW).output();
}

fn install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files")).join("Foxhole")
}

/// Copy the exe to Program Files and (re)register the service with auto-start + auto-restart.
fn install() -> Result<()> {
    let dir = install_dir();
    let target = dir.join("foxhole.exe");
    let current = std::env::current_exe()?;
    stop();
    kill_tray(); // its exe can't be overwritten while running
    if !same_path(&current, &target) {
        std::fs::create_dir_all(&dir)?;
        std::fs::copy(&current, &target).with_context(|| format!("copying to {}", target.display()))?;
    }
    if let Some(src_dir) = current.parent() {
        let (src, dst) = (src_dir.join(TRAY_EXE), dir.join(TRAY_EXE));
        if src.exists() && !same_path(&src, &dst) {
            std::fs::copy(&src, &dst).with_context(|| format!("copying to {}", dst.display()))?;
        }
    }
    let bin = format!("\"{}\" service", target.display());
    let (ok, out) = if exists() {
        sc(&["config", SERVICE_NAME, "binPath=", &bin, "start=", "auto"])?
    } else {
        sc(&["create", SERVICE_NAME, "binPath=", &bin, "start=", "auto", "DisplayName=", "Foxhole DNS Ad Blocker"])?
    };
    if !ok { bail!("sc.exe failed: {}", out.trim()); }
    match sc(&["sdset", SERVICE_NAME, SERVICE_SDDL]) {
        Ok((true, _)) => {}
        _ => println!("Warning: could not set service permissions; the tray icon may need admin rights to toggle."),
    }
    let _ = sc(&["description", SERVICE_NAME, "Local DNS resolver that blocks ads and trackers."]);
    // If the process ever dies, restart it quickly so DNS never stays pointed at a dead resolver.
    let _ = sc(&["failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/2000/restart/5000/restart/30000"]);
    register_uninstall(&target);
    Ok(())
}

pub fn turn_on() -> Result<()> {
    Config::load_or_create()?; // validates / creates config before we start
    println!("Installing service...");
    install()?;
    println!("Starting...");
    let (_, out) = sc(&["start", SERVICE_NAME])?;
    if !wait_for(Status::Running, 10) {
        bail!("service did not start. See %ProgramData%\\Foxhole\\foxhole.log\n{}", out.trim());
    }
    Ok(())
}

pub fn turn_off() -> Result<()> {
    if exists() {
        let _ = sc(&["config", SERVICE_NAME, "start=", "demand"]); // stay off across reboots
        stop();
    }
    sysdns::restore()?; // idempotent safety net in case the service died uncleanly
    Ok(())
}

/// Full removal: stop, restore DNS, delete the service and registry entries.
/// `purge` also deletes settings, cached lists and logs in %ProgramData%\Foxhole.
/// Program Files is removed afterwards by `remove_install_dir()`, once this process is done.
pub fn uninstall(purge: bool) -> Result<()> {
    println!("Stopping protection and restoring your DNS settings...");
    turn_off()?;

    println!("Removing service...");
    kill_tray();
    reg_delete(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", Some("Foxhole"));
    if exists() {
        let _ = sc(&["delete", SERVICE_NAME]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    reg_delete(UNINSTALL_KEY, None);

    if purge {
        println!("Deleting settings, cached lists and logs...");
        let _ = std::fs::remove_dir_all(data_dir());
    }
    Ok(())
}

/// Deletes C:\Program Files\Foxhole shortly after this process exits (a running exe can't delete itself).
pub fn remove_install_dir() {
    let dir = install_dir();
    // Safety: never run a recursive delete on anything that isn't our own folder.
    if dir.file_name().map_or(true, |n| !n.eq_ignore_ascii_case("Foxhole")) {
        return;
    }
    let _ = Command::new("cmd.exe")
        .raw_arg(format!("/C ping -n 4 127.0.0.1 >nul & rmdir /S /Q \"{}\"", dir.display()))
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}
