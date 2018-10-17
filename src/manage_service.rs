use std::ffi::{OsStr, OsString};
use std::path::Path;

use windows_service::service::{
    Service, ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
    ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use std::thread;
use std::time::Duration;

use {ErrorKind, Result, ResultExt};

// TODO: Should take path as arg? Return service?
pub fn install_service<T, U, V>(name: T, display_name: U, path: V) -> Result<()>
where
    T: AsRef<OsStr>,
    U: AsRef<OsStr>,
    V: AsRef<Path>,
{
    let manager_access = ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .chain_err(|| ErrorKind::FailMessage("Connect to service manager"))?;

    let service_info = ServiceInfo {
        name: name.as_ref().to_os_string(),
        display_name: display_name.as_ref().to_os_string(),
        service_type: ServiceType::OwnProcess,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: path.as_ref().to_path_buf(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: Some(OsString::from("NT AUTHORITY\\Local Service")),
        account_password: None,
    };

    service_manager
        .create_service(service_info, ServiceAccess::empty())
        .chain_err(|| ErrorKind::FailMessage("Create service"))?;

    Ok(())
}

pub fn open_service<T: AsRef<OsStr>>(name: T, access: ServiceAccess) -> Result<Service> {
    let manager_access = ServiceManagerAccess::empty();
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .chain_err(|| ErrorKind::FailMessage("Connect to service manager"))?;

    service_manager
        .open_service(name, access)
        .chain_err(|| ErrorKind::FailMessage("Open service"))
}

pub fn stop_and_uninstall_service<T: AsRef<OsStr>>(name: T) -> Result<()> {
    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = open_service(name, service_access)?;

    let service_status = service
        .query_status()
        .chain_err(|| ErrorKind::FailMessage("Query status"))?;
    if service_status.current_state != ServiceState::Stopped {
        service
            .stop()
            .chain_err(|| ErrorKind::FailMessage("Stop service"))?;

        // Wait for service to stop
        // TODO: loop
        thread::sleep(Duration::from_secs(1));
    }

    service
        .delete()
        .chain_err(|| ErrorKind::FailMessage("Delete service"))
}

pub fn start_service<T: AsRef<OsStr>>(name: T) -> Result<()> {
    let service_access = ServiceAccess::START;
    let service = open_service(name, service_access)?;

    service
        .start()
        .chain_err(|| ErrorKind::FailMessage("Start service"))?;

    Ok(())
}

pub fn stop_service<T: AsRef<OsStr>>(name: T) -> Result<()> {
    let service_access = ServiceAccess::STOP;
    let service = open_service(name, service_access)?;

    service
        .stop()
        .chain_err(|| ErrorKind::FailMessage("Stop service"))?;

    Ok(())
}
