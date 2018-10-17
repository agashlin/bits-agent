#![recursion_limit = "1024"]
#![windows_subsystem = "console"]

// TODO:
// - Setting completion callbacks?
// - Enumerate expected command failures, give them distinct result codes
// - a lot of these should probably return the full HRESULT on error
// - we can use the describe stuff from IBackgroundCopyError::GetErrorDescription etc?

extern crate byteorder;

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate windows_service;

extern crate widestring;
extern crate winapi;

use std::io;

use winapi::shared::minwindef::DWORD;
use winapi::um::winnt::HRESULT;

error_chain! {
    errors { FailMessage(msg: &'static str) {
                 display("{} failed", msg)
             }

             OSError(function_name: &'static str, err: io::Error) {
                 display("{} failed: {}", function_name, err)
             }

             OSErrorRC(function_name: &'static str, rc: DWORD) {
                 display("{} failed: rc {:#x}", function_name, rc)
             }

             OSErrorHRESULT(function_name: &'static str, rc: HRESULT) {
                 display("{} failed: HRESULT {:#x}", function_name, rc)
             }

             ServiceErrorNoSuchJob {
                 display("job with given GUID does not exist")
             }

             ServiceErrorPermission {
                 display("permission denied")
             }

             ServiceErrorBadCommand {
                 display("bad commat format")
             }

             InvalidCommandLine

             FailureFromService(rc: u8) {
                 description("service returned failure")
                 display("service returned failure: rc {}", rc)
             }
    }
}

macro_rules! os_error {
    ($string:expr) => {
        Err(ErrorKind::OSError($string, ::std::io::Error::last_os_error()).into())
    };
}

#[macro_use]
mod util;
mod client;
mod command;
mod grant_access;
mod manage_service;
mod service;

use std::env;

use grant_access::grant_service_access;
use manage_service::*;

const SERVICE_NAME: &str = "mozbitsagent";
const DISPLAY_NAME: &str = "Mozilla Updater BITS Agent";
const PIPE_NAME: &str = "\\\\.\\pipe\\mozbitsagentcontrol";

fn main() {
    if let Err(ref e) = run() {
        use error_chain::ChainedError;
        eprintln!("{}", e.display_chain());
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<String>>();
    if args.len() < 1 {
        return Err(ErrorKind::InvalidCommandLine.into());
    }

    // TODO: simplify command line interface, should attempt to start and, if service doesn't
    // exist, install, service if the pipe doesn't exist
    // stop and uninstall options should still be there
    match args[0].as_str() {
        "install" => {
            if args.len() != 1 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            let service_binary_path =
                ::std::env::current_exe().chain_err(|| ErrorKind::FailMessage("Get exe path"))?;
            install_service(SERVICE_NAME, DISPLAY_NAME, service_binary_path)
                .chain_err(|| ErrorKind::FailMessage("Install service"))?;
            grant_service_access(SERVICE_NAME)
                .chain_err(|| ErrorKind::FailMessage("Set permissions"))?;
        }
        "uninstall" => {
            if args.len() != 1 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            stop_and_uninstall_service(SERVICE_NAME)
                .chain_err(|| ErrorKind::FailMessage("Uninstall"))?;
        }
        "start" => {
            if args.len() != 1 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            start_service(SERVICE_NAME)?;
        }
        "stop" => {
            if args.len() != 1 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            stop_service(SERVICE_NAME)?;
        }
        "service" => {
            if args.len() != 1 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            service::run()?;
        }
        "create-bits" => {
            if args.len() != 1 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            client::bits_create()?;
        }
        "cancel-bits" => {
            if args.len() != 2 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            client::bits_cancel(&args[1])?;
        }
        "add-file" => {
            if args.len() != 4 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            client::bits_add_file(&args[1], &args[2], &args[3])?;
        }
        "resume" => {
            if args.len() != 2 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            client::bits_resume(&args[1])?;
        }
        "suspend" => {
            if args.len() != 2 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            client::bits_suspend(&args[1])?;
        }
        "complete" => {
            if args.len() != 2 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            client::bits_complete(&args[1])?;
        }
        "status" => {
            if args.len() != 2 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            client::bits_get_status(&args[1])?;
        }
        "status-me" => {
            if args.len() != 2 {
                return Err(ErrorKind::InvalidCommandLine.into());
            }
            client::bits_get_status_me(&args[1])?;
        }
        _ => {
            return Err(ErrorKind::InvalidCommandLine.into());
        }
    };
    Ok(())
}
