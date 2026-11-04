//! `VigilSvc`: the Windows service host and orchestrator.
//!
//! `vigil-svc --console` runs the same loop in the foreground (no admin needed) for development
//! and for the unelevated "try it" mode; without arguments the Service Control Manager starts it.
#![forbid(unsafe_code)]

#[cfg(not(windows))]
fn main() {
    eprintln!("VigilSvc runs on Windows only.");
    std::process::exit(2);
}

#[cfg(windows)]
mod win {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::time::Duration;

    use vigil_svc::{host, observer};
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const NAME: &str = "VigilSvc";

    fn init_logging() {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
    }

    /// Run observer and pipe server until either ends or `stop` resolves.
    async fn run(stop: impl Future<Output = ()>) -> anyhow::Result<()> {
        let (shared, pack) = host::build_state()?;
        shared.attach_control(Arc::new(vigil_svc::winctl::WinControl::default()));
        shared.attach_ai(Arc::new(vigil_svc::ai::LiveBackend::new(Arc::new(
            vigil_svc::winctl::DpapiVault,
        ))));
        match vigil_svc::winfilter::WfpEngine::open() {
            Ok(e) => shared.attach_engine(Some(Arc::new(e))),
            Err(e) => {
                tracing::warn!(error = %e, "filter engine unavailable; running without enforcement");
                shared.attach_engine(None);
            }
        }
        tokio::spawn(Arc::clone(&shared).pump_drops());
        tokio::spawn(Arc::clone(&shared).maintain());
        shared.audit(
            "service",
            vigil_core::audit::AuditKind::ServiceStart,
            None,
            &serde_json::json!({}),
        );
        let obs = tokio::spawn(observer::run(Arc::clone(&shared), pack));
        let pipe = tokio::spawn(host::serve_pipe(shared));
        tokio::select! {
            () = stop => Ok(()),
            r = obs => r?,
            r = pipe => r?,
        }
    }

    pub fn console() -> anyhow::Result<()> {
        init_logging();
        tokio::runtime::Runtime::new()?.block_on(run(async {
            let _ = tokio::signal::ctrl_c().await;
        }))
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = service() {
            tracing::error!(error = %e, "service failed");
        }
    }

    fn status(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }

    fn service() -> anyhow::Result<()> {
        init_logging();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let tx = std::sync::Mutex::new(Some(tx));
        let handle = service_control_handler::register(NAME, move |c| match c {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(t) = tx.lock().ok().and_then(|mut g| g.take()) {
                    let _ = t.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
        ))?;
        let result = tokio::runtime::Runtime::new()?.block_on(run(async {
            let _ = rx.await;
        }));
        let code = u32::from(result.is_err());
        handle.set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            code,
        ))?;
        result
    }

    pub fn dispatch() -> anyhow::Result<()> {
        service_dispatcher::start(NAME, ffi_service_main)?;
        Ok(())
    }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    if std::env::args().any(|a| a == "--console") {
        win::console()
    } else {
        win::dispatch()
    }
}
