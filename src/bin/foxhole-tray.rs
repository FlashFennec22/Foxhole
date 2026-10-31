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
fn main() {
    app::run();
}

#[cfg(windows)]
mod app {
    use serde::Deserialize;
    use std::{
        ffi::OsString,
        fs::OpenOptions,
        os::windows::{fs::OpenOptionsExt, process::CommandExt},
        path::PathBuf,
        process::Command,
        thread,
        time::Duration,
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

    const SERVICE_NAME: &str = "Foxhole";
    const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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

    // ---------- autostart (HKCU Run key via reg.exe) ----------

    fn autostart_enabled() -> bool {
        Command::new("reg")
            .args(["query", RUN_KEY, "/v", "Foxhole"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn set_autostart(on: bool) {
        let mut cmd = Command::new("reg");
        if on {
            let Ok(exe) = std::env::current_exe() else { return };
            cmd.args(["add", RUN_KEY, "/v", "Foxhole", "/t", "REG_SZ", "/d"])
                .arg(format!("\"{}\"", exe.display()))
                .arg("/f");
        } else {
            cmd.args(["delete", RUN_KEY, "/v", "Foxhole", "/f"]);
        }
        let _ = cmd.creation_flags(CREATE_NO_WINDOW).output();
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

    /// Flat disc icon generated at runtime (no asset files). `dot` adds a white centre.
    fn make_icon(rgb: [u8; 3], dot: bool) -> Icon {
        const N: u32 = 32;
        let c = (N as f32 - 1.0) / 2.0;
        let mut px = Vec::with_capacity((N * N * 4) as usize);
        for y in 0..N {
            for x in 0..N {
                let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
                let a = ((15.5 - d).clamp(0.0, 1.0) * 255.0) as u8;
                let (r, g, b) = if dot && d < 5.5 { (255, 255, 255) } else { (rgb[0], rgb[1], rgb[2]) };
                px.extend_from_slice(&[r, g, b, a]);
            }
        }
        Icon::from_rgba(px, N, N).expect("valid icon buffer")
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
            &quit_item,
        ])
        .expect("building menu");

        let toggle_id = toggle_item.id().clone();
        let folder_id = folder_item.id().clone();
        let autostart_id = autostart_item.id().clone();
        let quit_id = quit_item.id().clone();

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Foxhole")
            .with_icon(make_icon([128, 128, 128], false))
            .build()
            .expect("creating tray icon");

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

        let mut current = SvcState::Transition;

        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            let Event::UserEvent(ev) = event else { return };

            match ev {
                UserEvent::Status(snap) => {
                    current = snap.state;
                    let (icon, tip, status, toggle, enabled) = match snap.state {
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
                            (make_icon([46, 160, 67], true), "Foxhole — protection on", text, "Turn protection off", true)
                        }
                        SvcState::Stopped => (
                            make_icon([128, 128, 128], false),
                            "Foxhole — protection off",
                            "Protection off".to_string(),
                            "Turn protection on",
                            true,
                        ),
                        SvcState::Transition => (
                            make_icon([230, 160, 30], false),
                            "Foxhole — working…",
                            "Working…".to_string(),
                            "Please wait…",
                            false,
                        ),
                        SvcState::NotInstalled => (
                            make_icon([200, 60, 60], false),
                            "Foxhole — not installed",
                            "Not installed — run foxhole.exe".to_string(),
                            "Turn protection on",
                            false,
                        ),
                    };
                    let _ = tray.set_icon(Some(icon));
                    let _ = tray.set_tooltip(Some(tip));
                    status_item.set_text(status);
                    rules_item.set_text(match &snap.stats {
                        Some(s) => format!("{} rules loaded", fmt_num(s.rules)),
                        None => String::new(),
                    });
                    toggle_item.set_text(toggle);
                    toggle_item.set_enabled(enabled);
                }
                UserEvent::Error(msg) => {
                    status_item.set_text(format!("Couldn't change protection: {msg}"));
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
                    } else if me.id == quit_id {
                        *control_flow = ControlFlow::Exit;
                    }
                }
            }
        });
    }
}
