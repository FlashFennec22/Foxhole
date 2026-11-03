//! Foxhole tray icon: shows protection status and toggles the Windows service.
//! Runs as the normal (unelevated) user. The installer grants users start/stop rights on the service.
//!
//! GUI subsystem: no console window when launched at login.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("foxhole-tray is only available on Windows");
}

#[cfg(windows)]
#[path = "../trayctl.rs"]
mod trayctl;

#[cfg(windows)]
#[path = "../update.rs"]
mod update;

#[cfg(windows)]
fn main() {
    app::run();
}

#[cfg(windows)]
mod app {
    use crate::{
        trayctl,
        update::{self, Release, Version},
    };
    use serde::Deserialize;
    use std::{
        ffi::OsString,
        fs::OpenOptions,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        path::PathBuf,
        process::Command,
        ptr,
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tao::{
        event::Event,
        event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    };
    use tray_icon::{
        menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
        Icon, TrayIconBuilder,
    };
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    use windows_sys::Win32::{
        System::Threading::{WaitForSingleObject, INFINITE, SYNCHRONIZATION_SYNCHRONIZE},
        UI::WindowsAndMessaging::{
            MessageBoxW, IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND,
            MB_TOPMOST, MB_YESNO, MESSAGEBOX_STYLE,
        },
    };
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    const SERVICE_NAME: &str = "Foxhole";
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    /// Per-user tray settings (the update checker's).
    const SETTINGS_KEY: &str = r"Software\Foxhole";
    const UPDATE_CHECK_EVERY_SECS: u64 = 24 * 60 * 60;

    #[derive(Clone, Copy, PartialEq)]
    enum SvcState {
        NotInstalled,
        Running,
        Stopped,
        Transition,
    }

    #[derive(Deserialize, Clone, PartialEq)]
    struct Stats {
        total: u64,
        blocked: u64,
        rules: u64,
    }

    #[derive(Clone, PartialEq)]
    struct Snapshot {
        state: SvcState,
        stats: Option<Stats>,
    }

    enum UserEvent {
        Menu(MenuEvent),
        Status(Snapshot),
        Error(String),
        /// A newer release is out.
        UpdateAvailable(Release),
        /// Downloading/starting an update began (true) or ended without the installer closing us (false).
        UpdateBusy(bool),
        /// The installer asked every tray icon to exit.
        Quit,
    }

    // ---------- service / data helpers ----------

    fn data_dir() -> PathBuf {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Foxhole")
    }

    fn local_dir() -> PathBuf {
        let d = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("Foxhole");
        let _ = std::fs::create_dir_all(&d);
        d
    }

    fn svc_state() -> SvcState {
        let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
            return SvcState::NotInstalled;
        };
        let Ok(svc) = mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
            return SvcState::NotInstalled;
        };
        match svc.query_status().map(|s| s.current_state) {
            Ok(ServiceState::Running) => SvcState::Running,
            Ok(ServiceState::Stopped) => SvcState::Stopped,
            Ok(_) => SvcState::Transition,
            Err(_) => SvcState::NotInstalled,
        }
    }

    fn read_stats() -> Option<Stats> {
        let text = std::fs::read_to_string(data_dir().join("stats.json")).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn snapshot() -> Snapshot {
        let state = svc_state();
        let stats = if state == SvcState::Running { read_stats() } else { None };
        Snapshot { state, stats }
    }

    fn control(start: bool) -> Result<(), windows_service::Error> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(
            SERVICE_NAME,
            ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )?;
        if start {
            svc.start::<OsString>(&[])?;
        } else {
            svc.stop()?;
        }
        Ok(())
    }

    /// Start/stop on a worker thread (stopping can take a few seconds), then publish the new state.
    fn spawn_action(proxy: EventLoopProxy<UserEvent>, start: bool) {
        thread::spawn(move || {
            if let Err(e) = control(start) {
                let _ = proxy.send_event(UserEvent::Error(e.to_string()));
            }
            // wait briefly for the SCM to settle, then refresh
            for _ in 0..30 {
                thread::sleep(Duration::from_millis(400));
                if svc_state() != SvcState::Transition {
                    break;
                }
            }
            let _ = proxy.send_event(UserEvent::Status(snapshot()));
        });
    }

    // ---------- autostart (HKCU Run key) ----------

    fn autostart_enabled() -> bool {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(RUN_KEY)
            .and_then(|k| k.get_value::<String, _>("Foxhole"))
            .is_ok()
    }

    fn set_autostart(on: bool) {
        let Ok((key, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN_KEY) else { return };
        if on {
            let Ok(exe) = std::env::current_exe() else { return };
            let _ = key.set_value("Foxhole", &format!("\"{}\"", exe.display()));
        } else {
            let _ = key.delete_value("Foxhole");
        }
    }

    // ---------- update checks (settings in HKCU\Software\Foxhole) ----------

    fn settings() -> Option<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER).create_subkey(SETTINGS_KEY).ok().map(|(k, _)| k)
    }

    fn auto_update_enabled() -> bool {
        settings().and_then(|k| k.get_value::<u32, _>("CheckForUpdates").ok()).map_or(true, |v| v != 0)
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }

    fn update_check_due() -> bool {
        let last = settings().and_then(|k| k.get_value::<u64, _>("LastUpdateCheck").ok()).unwrap_or(0);
        let now = now_secs();
        now < last || now - last >= UPDATE_CHECK_EVERY_SECS // `now < last`: the clock was set back
    }

    /// The last version the user was asked about without asking for it; each version pops up once.
    fn prompted_version() -> Option<String> {
        settings()?.get_value::<String, _>("LastPromptedVersion").ok()
    }

    fn set_setting(name: &str, value: &impl winreg::types::ToRegValue) {
        if let Some(k) = settings() {
            let _ = k.set_value(name, value);
        }
    }

    /// One update check or install at a time (an automatic prompt can be open while the menu is clicked).
    static UPDATE_BUSY: AtomicBool = AtomicBool::new(false);

    struct UpdateGuard;

    impl UpdateGuard {
        fn take() -> Option<Self> {
            (!UPDATE_BUSY.swap(true, Ordering::AcqRel)).then_some(UpdateGuard)
        }
    }

    impl Drop for UpdateGuard {
        fn drop(&mut self) {
            UPDATE_BUSY.store(false, Ordering::Release);
        }
    }

    /// Blocks until dismissed, so call it from a worker thread, never the event loop.
    fn message_box(text: &str, style: MESSAGEBOX_STYLE) -> i32 {
        let text = trayctl::wide(text);
        let title = trayctl::wide("Foxhole");
        unsafe { MessageBoxW(ptr::null_mut(), text.as_ptr(), title.as_ptr(), style | MB_SETFOREGROUND | MB_TOPMOST) }
    }

    /// Worker thread. `manual`: the user asked, so always answer, even "up to date" or an error.
    fn check_for_updates(proxy: &EventLoopProxy<UserEvent>, manual: bool) {
        let current = Version::current();
        let release = match update::latest() {
            Ok(r) => r,
            Err(e) => {
                if manual {
                    message_box(&format!("Couldn't check for updates.\n\n{e:#}"), MB_OK | MB_ICONWARNING);
                }
                return; // an automatic check retries within the hour
            }
        };
        set_setting("LastUpdateCheck", &now_secs());
        if release.version <= current {
            if manual {
                message_box(&format!("Foxhole is up to date (version {current})."), MB_OK | MB_ICONINFORMATION);
            }
            return;
        }
        let _ = proxy.send_event(UserEvent::UpdateAvailable(release.clone()));
        // Pop up once per version on our own; after that the menu item is the reminder.
        let seen = release.version.to_string();
        if manual || prompted_version().as_deref() != Some(seen.as_str()) {
            set_setting("LastPromptedVersion", &seen);
            if ask_to_install(&release) {
                install(proxy, &release);
            }
        }
    }

    fn ask_to_install(release: &Release) -> bool {
        let notes = if release.notes.is_empty() { String::new() } else { format!("What's new:\n{}\n\n", release.notes) };
        let action = if release.installer.is_some() {
            "Download and install it now? Windows will ask for permission to make changes."
        } else {
            "Open the download page?"
        };
        let text = format!("Foxhole {} is available. You have {}.\n\n{notes}{action}", release.version, Version::current());
        message_box(&text, MB_YESNO | MB_ICONQUESTION) == IDYES
    }

    /// Worker thread. Downloads, verifies and starts the installer, which then closes this tray.
    fn install(proxy: &EventLoopProxy<UserEvent>, release: &Release) {
        if release.installer.is_none() {
            // No installer exe with a published checksum on this release: let the user get it.
            if let Err(e) = update::open_page(&release.page) {
                message_box(&format!("Couldn't open the download page.\n\n{e:#}"), MB_OK | MB_ICONWARNING);
            }
            return;
        }
        let _ = proxy.send_event(UserEvent::UpdateBusy(true));
        // `run` returns false if the UAC prompt was declined; nothing to report then.
        if let Err(e) = update::download(release, &local_dir().join("updates")).and_then(|i| i.run()) {
            message_box(&format!("Couldn't install the update.\n\n{e:#}"), MB_OK | MB_ICONWARNING);
        }
        let _ = proxy.send_event(UserEvent::UpdateBusy(false));
    }

    // ---------- UI helpers ----------

    fn fmt_num(n: u64) -> String {
        let s = n.to_string();
        let mut out = String::new();
        for (i, c) in s.chars().enumerate() {
            if i > 0 && (s.len() - i) % 3 == 0 {
                out.push(',');
            }
            out.push(c);
        }
        out
    }

    // Fox head, drawn at runtime (no asset files). Shapes are in a unit square, y pointing down,
    // and symmetric about x = 0.5; the eye is given for the left side and mirrored.
    const FOX_HEAD: &[(f32, f32)] = &[
        (0.05, 0.02), (0.36, 0.28), (0.64, 0.28), (0.95, 0.02), // ear tips and the top of the head
        (0.91, 0.44), (1.00, 0.62), (0.60, 0.88), (0.50, 0.98), // right cheek, snout
        (0.40, 0.88), (0.00, 0.62), (0.09, 0.44), // left cheek
    ];
    /// Light cheeks and chin.
    const FOX_MUZZLE: &[(f32, f32)] = &[(0.00, 0.62), (0.30, 0.63), (0.50, 0.74), (0.70, 0.63), (1.00, 0.62), (0.50, 0.98)];
    /// The tip of the snout keeps the head colour, inside the muzzle.
    const FOX_NOSE: &[(f32, f32)] = &[(0.40, 0.86), (0.60, 0.86), (0.50, 0.98)];
    /// Cut out (transparent), so the eyes work on light and dark taskbars alike.
    const FOX_EYE: &[(f32, f32)] = &[(0.22, 0.45), (0.43, 0.52), (0.35, 0.58)];
    /// A sleepy, closed eye: a thin downward curve.
    const FOX_EYE_SHUT: &[(f32, f32)] = &[(0.22, 0.50), (0.33, 0.55), (0.43, 0.50), (0.43, 0.555), (0.33, 0.605), (0.22, 0.555)];

    /// Even-odd point-in-polygon test.
    fn inside(poly: &[(f32, f32)], x: f32, y: f32) -> bool {
        let mut hit = false;
        let mut j = poly.len() - 1;
        for i in 0..poly.len() {
            let ((xi, yi), (xj, yj)) = (poly[i], poly[j]);
            if (yi > y) != (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi {
                hit = !hit;
            }
            j = i;
        }
        hit
    }

    /// `n`×`n` RGBA pixels (straight alpha), 4×4 samples per pixel for smooth edges.
    fn fox_rgba(n: u32, rgb: [u8; 3], muzzle: [u8; 3], eyes_open: bool) -> Vec<u8> {
        const SS: u32 = 4;
        let eye = if eyes_open { FOX_EYE } else { FOX_EYE_SHUT };
        let mut px = Vec::with_capacity((n * n * 4) as usize);
        for py in 0..n {
            for pxl in 0..n {
                let (mut sum, mut hits) = ([0u32; 3], 0u32);
                for sy in 0..SS {
                    for sx in 0..SS {
                        let x = (pxl as f32 + (sx as f32 + 0.5) / SS as f32) / n as f32;
                        let y = (py as f32 + (sy as f32 + 0.5) / SS as f32) / n as f32;
                        if !inside(FOX_HEAD, x, y) || inside(eye, x, y) || inside(eye, 1.0 - x, y) {
                            continue;
                        }
                        let light = inside(FOX_MUZZLE, x, y) && !inside(FOX_NOSE, x, y);
                        let c = if light { muzzle } else { rgb };
                        for k in 0..3 {
                            sum[k] += c[k] as u32;
                        }
                        hits += 1;
                    }
                }
                let a = (hits * 255 / (SS * SS)) as u8;
                let c = |k: usize| if hits == 0 { 0 } else { (sum[k] / hits) as u8 };
                px.extend_from_slice(&[c(0), c(1), c(2), a]);
            }
        }
        px
    }

    /// `rgb` mixed `t` of the way to white.
    fn tint(rgb: [u8; 3], t: f32) -> [u8; 3] {
        rgb.map(|c| (c as f32 + (255.0 - c as f32) * t) as u8)
    }

    /// The fox in `rgb` with a lighter muzzle. `on`: eyes open; otherwise shut, so the state
    /// shows by more than colour alone (green and red are easy to confuse).
    fn make_icon(rgb: [u8; 3], on: bool) -> Icon {
        const N: u32 = 32;
        Icon::from_rgba(fox_rgba(N, rgb, tint(rgb, 0.6), on), N, N).expect("valid icon buffer")
    }

    /// Writes raw RGBA previews of every state at common tray sizes, for checking changes to the
    /// shapes: `cargo test --bin foxhole-tray -- --ignored icon_preview`
    #[test]
    #[ignore]
    fn icon_preview() {
        let dir = std::env::temp_dir().join("foxhole-icon-preview");
        std::fs::create_dir_all(&dir).unwrap();
        let states = [("on", [46, 160, 67], true), ("off", [128, 128, 128], false), ("working", [230, 160, 30], false), ("missing", [200, 60, 60], false)];
        for (name, rgb, on) in states {
            for n in [16, 20, 24, 32, 128] {
                std::fs::write(dir.join(format!("{name}-{n}.rgba")), fox_rgba(n, rgb, tint(rgb, 0.6), on)).unwrap();
            }
        }
    }

    pub fn run() {
        // Single instance: hold an exclusive lock file for the life of the process.
        let Ok(_lock) = OpenOptions::new()
            .write(true)
            .create(true)
            .share_mode(0)
            .open(local_dir().join("tray.lock"))
        else {
            return;
        };

        // First launch ever: start with Windows by default (user can untick it in the menu).
        let marker = local_dir().join("tray-initialized");
        if !marker.exists() {
            set_autostart(true);
            let _ = std::fs::write(&marker, b"1");
        }

        let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        let proxy = event_loop.create_proxy();
        {
            let p = proxy.clone();
            MenuEvent::set_event_handler(Some(move |e| {
                let _ = p.send_event(UserEvent::Menu(e));
            }));
        }

        let status_item = MenuItem::new("Checking…", false, None);
        let rules_item = MenuItem::new("", false, None);
        let toggle_item = MenuItem::new("Please wait…", false, None);
        let folder_item = MenuItem::new("Open data folder", true, None);
        let autostart_item = CheckMenuItem::new("Start with Windows", true, autostart_enabled(), None);
        let update_item = MenuItem::new("Check for updates", true, None);
        let auto_update_item = CheckMenuItem::new("Check for updates automatically", true, auto_update_enabled(), None);
        let quit_item = MenuItem::new("Quit tray icon", true, None);

        let menu = Menu::new();
        menu.append_items(&[
            &status_item,
            &rules_item,
            &PredefinedMenuItem::separator(),
            &toggle_item,
            &folder_item,
            &autostart_item,
            &PredefinedMenuItem::separator(),
            &update_item,
            &auto_update_item,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ])
        .expect("building menu");

        let toggle_id = toggle_item.id().clone();
        let folder_id = folder_item.id().clone();
        let autostart_id = autostart_item.id().clone();
        let update_id = update_item.id().clone();
        let auto_update_id = auto_update_item.id().clone();
        let quit_id = quit_item.id().clone();

        // Drawn once up front; cloning an Icon shares the same handle.
        let icon_on = make_icon([46, 160, 67], true);
        let icon_off = make_icon([128, 128, 128], false);
        let icon_working = make_icon([230, 160, 30], false);
        let icon_missing = make_icon([200, 60, 60], false);

        let mut tray = Some(TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Foxhole")
            .with_icon(icon_off.clone())
            .build()
            .expect("creating tray icon"));

        // Exit when the installer/uninstaller asks (it needs to replace or delete this exe).
        match trayctl::exit_event(SYNCHRONIZATION_SYNCHRONIZE) {
            Ok(ev) => {
                let p = proxy.clone();
                thread::spawn(move || {
                    unsafe { WaitForSingleObject(ev.as_raw_handle(), INFINITE) };
                    let _ = p.send_event(UserEvent::Quit);
                });
            }
            Err(e) => eprintln!("cannot listen for the exit signal: {e}"),
        }

        // Poll the service every 3 s; only notify the UI when something changed.
        {
            let p = proxy.clone();
            thread::spawn(move || {
                let mut last: Option<Snapshot> = None;
                loop {
                    let snap = snapshot();
                    if last.as_ref() != Some(&snap) {
                        let _ = p.send_event(UserEvent::Status(snap.clone()));
                        last = Some(snap);
                    }
                    thread::sleep(Duration::from_secs(3));
                }
            });
        }

        // Check for updates once a day; look hourly whether one is due (and to retry after failures).
        {
            let p = proxy.clone();
            thread::spawn(move || {
                // Give the network a minute after sign-in before the first check.
                thread::sleep(Duration::from_secs(60));
                loop {
                    if auto_update_enabled() && update_check_due() {
                        if let Some(_busy) = UpdateGuard::take() {
                            check_for_updates(&p, false);
                        }
                    }
                    thread::sleep(Duration::from_secs(60 * 60));
                }
            });
        }

        let mut current = SvcState::Transition;
        // The state whose icon is showing; the stats change every few seconds, the icon rarely.
        let mut shown: Option<SvcState> = None;
        let mut available: Option<Release> = None;
        let update_text = |available: &Option<Release>| match available {
            Some(r) => format!("Install Foxhole {}…", r.version),
            None => "Check for updates".to_string(),
        };

        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            let Event::UserEvent(ev) = event else { return };
            // Dropping the TrayIcon removes it from the notification area right away.
            let Some(icon) = tray.as_ref() else { return };

            match ev {
                UserEvent::Status(snap) => {
                    current = snap.state;
                    let tray_icon = icon;
                    let (img, tip, status, toggle, enabled) = match snap.state {
                        SvcState::Running => {
                            let text = match &snap.stats {
                                Some(s) if s.total > 0 => format!(
                                    "Protection on — blocked {} of {} queries ({}%)",
                                    fmt_num(s.blocked),
                                    fmt_num(s.total),
                                    s.blocked * 100 / s.total
                                ),
                                _ => "Protection on".to_string(),
                            };
                            (&icon_on, "Foxhole — protection on", text, "Turn protection off", true)
                        }
                        SvcState::Stopped => (
                            &icon_off,
                            "Foxhole — protection off",
                            "Protection off".to_string(),
                            "Turn protection on",
                            true,
                        ),
                        SvcState::Transition => (
                            &icon_working,
                            "Foxhole — working…",
                            "Working…".to_string(),
                            "Please wait…",
                            false,
                        ),
                        SvcState::NotInstalled => (
                            &icon_missing,
                            "Foxhole — not installed",
                            "Not installed — run the Foxhole installer".to_string(),
                            "Turn protection on",
                            false,
                        ),
                    };
                    if shown != Some(snap.state) {
                        let _ = tray_icon.set_icon(Some(img.clone()));
                        shown = Some(snap.state);
                    }
                    let _ = tray_icon.set_tooltip(Some(tip));
                    status_item.set_text(status);
                    rules_item.set_text(match &snap.stats {
                        Some(s) => format!("{} rules loaded", fmt_num(s.rules)),
                        None => String::new(),
                    });
                    toggle_item.set_text(toggle);
                    toggle_item.set_enabled(enabled);
                }
                UserEvent::Quit => {
                    tray = None;
                    *control_flow = ControlFlow::Exit;
                }
                UserEvent::Error(msg) => {
                    status_item.set_text(format!("Couldn't change protection: {msg}"));
                }
                UserEvent::UpdateAvailable(release) => {
                    available = Some(release);
                    if update_item.is_enabled() {
                        update_item.set_text(update_text(&available));
                    }
                }
                UserEvent::UpdateBusy(busy) => {
                    update_item.set_enabled(!busy);
                    update_item.set_text(if busy { "Downloading update…".to_string() } else { update_text(&available) });
                }
                UserEvent::Menu(me) => {
                    if me.id == toggle_id {
                        let start = match current {
                            SvcState::Stopped => true,
                            SvcState::Running => false,
                            _ => return,
                        };
                        toggle_item.set_enabled(false);
                        status_item.set_text("Working…");
                        spawn_action(proxy.clone(), start);
                    } else if me.id == folder_id {
                        let _ = Command::new("explorer").arg(data_dir()).spawn();
                    } else if me.id == autostart_id {
                        set_autostart(autostart_item.is_checked());
                    } else if me.id == update_id {
                        // Clicking "Install Foxhole x.y.z…" is the user's yes; otherwise check now.
                        let p = proxy.clone();
                        let release = available.clone();
                        thread::spawn(move || {
                            let Some(_busy) = UpdateGuard::take() else { return };
                            match release {
                                Some(r) => install(&p, &r),
                                None => check_for_updates(&p, true),
                            }
                        });
                    } else if me.id == auto_update_id {
                        set_setting("CheckForUpdates", &(auto_update_item.is_checked() as u32));
                    } else if me.id == quit_id {
                        tray = None;
                        *control_flow = ControlFlow::Exit;
                    }
                }
            }
        });
    }
}
