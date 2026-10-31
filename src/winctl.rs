//! Install / start / stop / uninstall the Windows service through the Service Control Manager API,
//! plus UAC self-elevation.

use crate::{config::{data_dir, Config}, service::SERVICE_NAME, sysdns, trayctl};
use anyhow::{bail, Context, Result};
use std::{
    ffi::OsString,
    io,
    mem::size_of,
    os::windows::{ffi::OsStrExt, io::{AsRawHandle, FromRawHandle, OwnedHandle}, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    ptr,
    time::{Duration, Instant},
};
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, ERROR_CANCELLED, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    },
    System::{
        Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS},
        Services::{ChangeServiceConfigW, SetServiceObjectSecurity, SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_NO_CHANGE},
        Threading::{
            GetExitCodeProcess, ResetEvent, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE, INFINITE,
            SYNCHRONIZATION_SYNCHRONIZE,
        },
    },
    UI::{
        Shell::{IsUserAnAdmin, ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};
use winreg::{enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}, RegKey};

const DISPLAY_NAME: &str = "Foxhole DNS Ad Blocker";
const TRAY_EXE: &str = "foxhole-tray.exe";
const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Foxhole";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Service ACL: SYSTEM + Administrators keep full control; interactive users may query,
/// START and STOP the service (so the tray can toggle without UAC) but NOT change its config.
const SERVICE_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

/// ShellExecuteEx, i.e. start a program the way Explorer would. Unlike `std::process::Command`, this
/// doesn't let the child inherit our handles, so a caller reading our output through a pipe isn't
/// kept waiting by a long-running child such as the tray icon.
fn shell_execute(verb: &str, file: &Path, params: &str) -> io::Result<Option<OwnedHandle>> {
    let file: Vec<u16> = file.as_os_str().encode_wide().chain(Some(0)).collect();
    let params = trayctl::wide(params);
    let verb = trayctl::wide(verb);
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((!info.hProcess.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(info.hProcess) }))
}

/// Re-launches this exe through UAC with the given args, waits for it and returns its exit code.
pub fn relaunch_elevated(args: &[&str]) -> Result<u32> {
    println!("Requesting administrator permission...");
    // `--elevated` lets the copy detect that elevation didn't actually happen, instead of looping.
    let params = args.iter().copied().chain(["--elevated"]).collect::<Vec<_>>().join(" "); // space-free literals
    let process = match shell_execute("runas", &std::env::current_exe()?, &params) {
        Ok(Some(p)) => p,
        Ok(None) => bail!("could not start Foxhole as administrator"),
        Err(e) if e.raw_os_error() == Some(ERROR_CANCELLED as i32) => bail!("administrator permission was not granted"),
        Err(e) => return Err(e).context("could not start Foxhole as administrator"),
    };
    let mut code = 1;
    unsafe {
        WaitForSingleObject(process.as_raw_handle(), INFINITE);
        GetExitCodeProcess(process.as_raw_handle(), &mut code);
    }
    Ok(code)
}

fn open(access: ServiceAccess) -> Option<Service> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    mgr.open_service(SERVICE_NAME, access).ok()
}

#[derive(Debug, PartialEq)]
pub enum Status { NotInstalled, Running, Stopped, Other }

pub fn status() -> Status {
    let Some(svc) = open(ServiceAccess::QUERY_STATUS) else { return Status::NotInstalled };
    match svc.query_status().map(|s| s.current_state) {
        Ok(ServiceState::Running) => Status::Running,
        Ok(ServiceState::Stopped) => Status::Stopped,
        Ok(_) => Status::Other,
        Err(_) => Status::NotInstalled,
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

/// Waits (up to `secs`) for a start or stop in progress to finish, and returns the outcome.
fn wait_settled(secs: u64) -> Status {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let s = status();
        if s != Status::Other || Instant::now() >= deadline {
            return s;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Stops the service if it is running. Returns false if it is still running afterwards.
fn stop() -> bool {
    if let Some(svc) = open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS) {
        if wait_settled(15) != Status::Stopped {
            let _ = svc.stop();
            return wait_for(Status::Stopped, 15);
        }
    }
    true
}

/// Switches between automatic start (protection on at boot) and manual start (stays off).
fn set_auto_start(svc: &Service, auto: bool) -> Result<()> {
    let start = if auto { SERVICE_AUTO_START } else { SERVICE_DEMAND_START };
    let ok = unsafe {
        ChangeServiceConfigW(
            svc.raw_handle() as _, SERVICE_NO_CHANGE, start, SERVICE_NO_CHANGE,
            ptr::null(), ptr::null(), ptr::null_mut(), ptr::null(), ptr::null(), ptr::null(), ptr::null(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error()).context("changing the service start type");
    }
    Ok(())
}

fn set_security(svc: &Service, sddl: &str) -> io::Result<()> {
    let sddl = trayctl::wide(sddl);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let ok = unsafe { SetServiceObjectSecurity(svc.raw_handle() as _, DACL_SECURITY_INFORMATION, sd) };
    let err = io::Error::last_os_error();
    unsafe { LocalFree(sd) };
    if ok == 0 { Err(err) } else { Ok(()) }
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.display().to_string().eq_ignore_ascii_case(&b.display().to_string())
}

fn tray_running() -> bool {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return false;
    }
    let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut found = false;
    let mut more = unsafe { Process32FirstW(snap, &mut e) } != 0;
    while more && !found {
        let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
        found = String::from_utf16_lossy(&e.szExeFile[..len]).eq_ignore_ascii_case(TRAY_EXE);
        more = unsafe { Process32NextW(snap, &mut e) } != 0;
    }
    unsafe { CloseHandle(snap) };
    found
}

/// Asks every running tray icon (any user, any session) to exit, and waits up to 5 s for them.
/// Returns false if one is still running (e.g. an old version that doesn't listen for the signal).
pub fn close_trays() -> bool {
    if !tray_running() {
        return true;
    }
    let ev = match trayctl::exit_event(EVENT_MODIFY_STATE | SYNCHRONIZATION_SYNCHRONIZE) {
        Ok(ev) => ev,
        Err(e) => { tracing::warn!(error = %e, "cannot signal the tray icon"); return false; }
    };
    unsafe { SetEvent(ev.as_raw_handle()) };
    let deadline = Instant::now() + Duration::from_secs(5);
    while tray_running() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    // Reset so a tray started later (e.g. right after an upgrade) doesn't exit immediately.
    unsafe { ResetEvent(ev.as_raw_handle()) };
    !tray_running()
}

/// Start the tray app (best effort). Call from a NON-elevated process so it runs as the user.
pub fn launch_tray() {
    let p = install_dir().join(TRAY_EXE);
    if p.exists() {
        let _ = shell_execute("open", &p, "");
    }
}

/// Adds the entry shown in Settings -> Apps -> Installed apps.
fn register_uninstall(exe: &Path) -> io::Result<()> {
    let (key, _) = RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(UNINSTALL_KEY)?;
    let exe_s = exe.display().to_string();
    key.set_value("DisplayName", &DISPLAY_NAME)?;
    key.set_value("DisplayVersion", &env!("CARGO_PKG_VERSION"))?;
    key.set_value("Publisher", &"Foxhole")?;
    key.set_value("InstallLocation", &install_dir().display().to_string())?;
    key.set_value("DisplayIcon", &exe_s)?;
    key.set_value("UninstallString", &format!("\"{exe_s}\" uninstall --pause"))?;
    key.set_value("NoModify", &1u32)?;
    key.set_value("NoRepair", &1u32)?;
    Ok(())
}

fn install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files")).join("Foxhole")
}

/// Copy the exe to Program Files and (re)register the service with auto-start + auto-restart.
fn install() -> Result<()> {
    let dir = install_dir();
    let target = dir.join("foxhole.exe");
    let current = std::env::current_exe()?;
    if !stop() {
        bail!("the Foxhole service didn't stop; try again in a moment");
    }
    let trays_closed = close_trays(); // a running exe can't be overwritten
    if !same_path(&current, &target) {
        std::fs::create_dir_all(&dir)?;
        std::fs::copy(&current, &target).with_context(|| format!("copying to {}", target.display()))?;
    }
    if let Some(src_dir) = current.parent() {
        let (src, dst) = (src_dir.join(TRAY_EXE), dir.join(TRAY_EXE));
        if src.exists() && !same_path(&src, &dst) {
            if let Err(e) = std::fs::copy(&src, &dst) {
                if trays_closed { return Err(e).with_context(|| format!("copying to {}", dst.display())); }
                println!("Note: the tray icon is still running, so it wasn't updated. Quit it and run this again to update it.");
            }
        }
    }

    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: target.clone(),
        launch_arguments: vec!["service".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    // ALL_ACCESS because setting the service's DACL needs WRITE_DAC, which ServiceAccess doesn't name.
    let access = ServiceAccess::ALL_ACCESS;
    let svc = match open(access) {
        Some(svc) => {
            svc.change_config(&info).context("updating the service")?;
            svc
        }
        None => ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
            .and_then(|m| m.create_service(&info, access))
            .context("creating the service")?,
    };
    if let Err(e) = set_security(&svc, SERVICE_SDDL) {
        println!("Warning: could not set service permissions ({e}); the tray icon may need admin rights to toggle.");
    }
    let _ = svc.set_description("Local DNS resolver that blocks ads and trackers.");
    // If the process ever dies, restart it quickly so DNS never stays pointed at a dead resolver.
    let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
    let _ = svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(2), restart(5), restart(30)]),
    });
    if let Err(e) = register_uninstall(&target) {
        println!("Warning: could not register in Installed apps: {e}");
    }
    Ok(())
}

pub fn turn_on() -> Result<()> {
    Config::load_or_create()?; // validates / creates config before we start
    println!("Installing service...");
    install()?;
    println!("Starting...");
    let started = open(ServiceAccess::START).context("service not found after install")?.start::<OsString>(&[]);
    // The service reports RUNNING only once it is listening on port 53, and stops if it can't.
    if wait_settled(30) != Status::Running {
        let why = started.err().map(|e| format!("\n{e}")).unwrap_or_default();
        bail!("service did not start. See %ProgramData%\\Foxhole\\foxhole.log{why}");
    }
    Ok(())
}

/// Best effort: even if one step fails, the others (above all restoring DNS) still run.
pub fn turn_off() -> Result<()> {
    let mut result = Ok(());
    if let Some(svc) = open(ServiceAccess::CHANGE_CONFIG) {
        result = set_auto_start(&svc, false); // stay off across reboots
        if !stop() {
            result = result.and(Err(anyhow::anyhow!("the Foxhole service didn't stop")));
        }
    }
    let restored = sysdns::restore(); // idempotent safety net in case the service died uncleanly
    result.and(restored)
}

/// Full removal: stop, restore DNS, delete the service and registry entries.
/// `purge` also deletes settings, cached lists and logs in %ProgramData%\Foxhole.
/// Program Files is removed afterwards by `remove_install_dir()`, once this process is done.
pub fn uninstall(purge: bool) -> Result<()> {
    // Close the tray icons first, so none can restart the service while it is being removed.
    close_trays();
    println!("Stopping protection and restoring your DNS settings...");
    if let Err(e) = turn_off() {
        println!("Warning: {e:#}");
    }

    println!("Removing service...");
    if let Ok(run) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, winreg::enums::KEY_SET_VALUE) {
        let _ = run.delete_value("Foxhole");
    }
    if let Some(svc) = open(ServiceAccess::DELETE) {
        let _ = svc.delete();
        drop(svc); // the service disappears once the last handle is closed
        let deadline = Instant::now() + Duration::from_secs(5);
        while status() != Status::NotInstalled && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    let _ = RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey_all(UNINSTALL_KEY);

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
