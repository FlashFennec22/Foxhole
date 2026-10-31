//! Windows Service entry point (`foxhole.exe service`, launched by the Service Control Manager).

use crate::{config::Config, engine};
use std::{ffi::OsString, sync::Arc, time::Duration};
use tokio::sync::Notify;
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

pub const SERVICE_NAME: &str = "Foxhole";

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
    let accept = if state == ServiceState::Running {
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
    } else {
        ServiceControlAccept::empty()
    };
    let _ = handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
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

    status(&handle, ServiceState::Running, 0);

    let result = (|| -> anyhow::Result<()> {
        let cfg = Config::load_or_create()?;
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        rt.block_on(engine::run(cfg, shutdown, true))
    })();

    if let Err(e) = &result {
        tracing::error!(error = %e, "engine failed");
    }
    status(&handle, ServiceState::Stopped, if result.is_ok() { 0 } else { 1 });
    result
}
