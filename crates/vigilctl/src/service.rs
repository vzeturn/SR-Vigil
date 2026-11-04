//! `vigilctl service ...`: register and control `VigilSvc` with the Service Control Manager.
//! These commands need an elevated shell; everything else in Vigil works without.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::Context as _;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const NAME: &str = "VigilSvc";
const ELEVATION_HINT: &str = "this needs an elevated (administrator) shell";

fn manager(access: ServiceManagerAccess) -> anyhow::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).context(ELEVATION_HINT)
}

/// `vigil-svc.exe` next to this executable.
fn service_binary() -> anyhow::Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?.with_file_name("vigil-svc.exe");
    anyhow::ensure!(
        exe.is_file(),
        "{} not found next to vigilctl",
        exe.display()
    );
    Ok(exe)
}

pub fn install() -> anyhow::Result<()> {
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "Vigil endpoint protection".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary()?,
        launch_arguments: Vec::<OsString>::new(),
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let svc = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .context("create service (is it already installed?)")?;
    svc.set_description(
        "Classifies processes and network connections as safe, unknown or malicious.",
    )?;
    // Restart after 1 s, 5 s, then 30 s; forget failures after a day.
    let restart = |secs| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(secs),
    };
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(1), restart(5), restart(30)]),
    })?;
    svc.start::<&str>(&[])?;
    println!("{NAME} installed and started");
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let svc = manager(ServiceManagerAccess::CONNECT)?
        .open_service(
            NAME,
            ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )
        .context("open service (is it installed?)")?;
    let _ = svc.stop();
    svc.delete()?;
    println!("{NAME} removed (data in %ProgramData%\\Vigil is kept)");
    Ok(())
}

pub fn start() -> anyhow::Result<()> {
    manager(ServiceManagerAccess::CONNECT)?
        .open_service(NAME, ServiceAccess::START)
        .context("open service (is it installed?)")?
        .start::<&str>(&[])?;
    println!("{NAME} started");
    Ok(())
}

pub fn stop() -> anyhow::Result<()> {
    manager(ServiceManagerAccess::CONNECT)?
        .open_service(NAME, ServiceAccess::STOP)
        .context("open service (is it installed?)")?
        .stop()?;
    println!("{NAME} stopping");
    Ok(())
}
