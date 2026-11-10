//! Windows Service entry point (`foxhole.exe service`, launched by the Service Control Manager).
//!
//! A start that fails (bad config, port 53 taken, ...) is retried a few times, further apart each
//! time. Between attempts the service reports PAUSED: unlike START_PENDING, Windows still delivers a
//! stop request in that state, so `foxhole off` and the tray can call the retries off. Once the
//! attempts are used up it leaves a note for the tray icon, which tells the user, and stops.

use crate::{config::{data_dir, Config}, engine, sysdns};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

pub const SERVICE_NAME: &str = "Foxhole";

/// How long to wait before each further attempt to start, in seconds. One entry per retry, so the
/// service gives up after `len() + 1` attempts, a little under four minutes after the first.
const RETRY_DELAYS_SECS: [u64; 4] = [10, 30, 60, 120];

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "service exited with error");
    }
}

fn status(handle: &ServiceStatusHandle, state: ServiceState, code: u32) {
    let accept = if matches!(state, ServiceState::Running | ServiceState::Paused) {
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
    } else {
        ServiceControlAccept::empty()
    };
    // Loading the cached blocklists can take a moment on slow disks.
    let wait_hint = if state == ServiceState::StartPending { Duration::from_secs(30) } else { Duration::default() };
    let _ = handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    });
}

/// The engine only returns an error when it could not start (bad config, port 53 taken, ...). The
/// adapters may still point at us from a run that never got to restore them (power loss, crash),
/// and Windows doesn't restart a service that reports its own failure, so without this the machine
/// would be left with a resolver that isn't there.
fn fail_open() {
    match sysdns::restore() {
        Ok(()) => tracing::warn!("protection is off; Windows is not using Foxhole for DNS"),
        Err(e) => tracing::error!(error = %format!("{e:#}"), "could not restore DNS settings; run `foxhole off`"),
    }
}

/// Read by the tray icon (the file name is repeated in src/bin/foxhole-tray.rs), which shows it to
/// the user once. Normal users can read the data folder but not write to it.
fn start_failure_path() -> PathBuf {
    data_dir().join("start-failed.json")
}

fn write_start_failure(attempts: usize, error: &anyhow::Error) {
    let json = serde_json::json!({
        // Identifies this failure, so each tray icon shows it only once.
        "at": SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        "attempts": attempts,
        "error": format!("{error:#}"),
    });
    let path = start_failure_path();
    let tmp = path.with_extension("tmp");
    if let Err(e) = std::fs::write(&tmp, json.to_string()).and_then(|()| std::fs::rename(&tmp, &path)) {
        tracing::warn!(error = %e, "could not leave a note for the tray icon");
    }
}

/// The note is out of date once protection starts, or is turned off on purpose.
pub fn clear_start_failure() {
    let _ = std::fs::remove_file(start_failure_path());
}

/// One attempt to start. Returns Ok once the engine has run and been shut down again.
fn run_once(handle: &ServiceStatusHandle, shutdown: &Arc<Notify>) -> anyhow::Result<()> {
    let cfg = Config::load_or_create()?;
    // A runtime per attempt: dropping it closes whatever a failed attempt had already bound (say
    // the UDP socket, when TCP was the one that failed), which would otherwise block the next one.
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(engine::run(cfg, shutdown.clone(), true, || {
        clear_start_failure();
        status(handle, ServiceState::Running, 0);
    }))
}

/// Runs the engine, trying again after a failed start. The error is that of the last attempt.
fn run_with_retries(handle: &ServiceStatusHandle, shutdown: &Arc<Notify>) -> anyhow::Result<()> {
    let waiter = tokio::runtime::Builder::new_current_thread().enable_time().build()?;
    let mut delays = RETRY_DELAYS_SECS.iter();
    loop {
        let error = match run_once(handle, shutdown) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        tracing::error!(error = %format!("{error:#}"), "engine failed");
        // Before reporting anything, so whoever is waiting on the start sees working DNS afterwards.
        fail_open();
        let Some(&secs) = delays.next() else { return Err(error) };

        // Stays PAUSED through the following attempts, until one works or the last one fails.
        status(handle, ServiceState::Paused, 0);
        tracing::warn!(secs, "will try to start again");
        let stop_requested = waiter.block_on(async {
            tokio::select! {
                _ = shutdown.notified() => true,
                _ = tokio::time::sleep(Duration::from_secs(secs)) => false,
            }
        });
        if stop_requested {
            tracing::info!("stopped while waiting to try again");
            return Ok(());
        }
    }
}

fn run_service() -> anyhow::Result<()> {
    let shutdown = Arc::new(Notify::new());
    let sd = shutdown.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            sd.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    // Report RUNNING only once port 53 is bound, so `foxhole on` and the installer can tell
    // whether protection really started (e.g. not when another DNS server holds the port).
    status(&handle, ServiceState::StartPending, 0);

    let result = run_with_retries(&handle, &shutdown);
    if let Err(e) = &result {
        let attempts = RETRY_DELAYS_SECS.len() + 1;
        tracing::error!(attempts, "giving up; protection stays off until it is turned on again or Windows restarts");
        write_start_failure(attempts, e);
    }
    status(&handle, ServiceState::Stopped, if result.is_ok() { 0 } else { 1 });
    result
}
