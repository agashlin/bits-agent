pub mod bits;

use std::ffi::OsString;

use windows_service::service::{ServiceControlAccept, ServiceState, ServiceStatus};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use widestring::WideCString;

use command::*;
use grant_access::users_access;
use util::HHolder;
use {ErrorKind, Result, ResultExt, PIPE_NAME, SERVICE_NAME};

pub fn run() -> Result<()> {
    // Register generated `ffi_service_main` with the system and start the service, blocking
    // this thread until the service is stopped.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .chain_err(|| ErrorKind::FailMessage("Start service dispatcher"))
}

// Generate the windows service boilerplate.
define_windows_service!(ffi_service_main, service_main);

pub fn service_main(_arguments: Vec<OsString>) {
    if let Err(_e) = run_service() {
        // TODO: handle error
    }
}

fn service_status(
    controls_accepted: ServiceControlAccept,
    current_state: ServiceState,
) -> ServiceStatus {
    use std::time::Duration;
    use windows_service::service::{ServiceExitCode, ServiceType};
    ServiceStatus {
        service_type: ServiceType::OwnProcess,
        current_state,
        controls_accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
    }
}

// TODO: assert expected GUID sizeof

fn run_service() -> Result<()> {
    use command::{OperationCode, ResponseCode};
    use std::mem::{size_of, uninitialized};
    use std::ptr::null_mut;
    use util::NamedPipeConnectionHolder;
    use winapi::shared::minwindef::{DWORD, FALSE, LPCVOID, LPVOID};
    use winapi::shared::winerror::{ERROR_MORE_DATA, SUCCEEDED};
    use winapi::um::combaseapi::CoInitializeEx;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::fileapi::{FlushFileBuffers, ReadFile, WriteFile};
    use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
    use winapi::um::namedpipeapi::{CallNamedPipeW, ConnectNamedPipe, CreateNamedPipeW};
    use winapi::um::objbase::COINIT_APARTMENTTHREADED;
    use winapi::um::winbase::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
    };
    use winapi::um::winnt::{PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR};
    use windows_service::service::ServiceControl;

    // TODO: submit to winapi along with other NMP?
    const NMPWAIT_WAIT_FOREVER: DWORD = 0xffffffff;

    //
    let rc = unsafe { CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED) };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("CoInitializeEx", rc).into());
    }

    // Create named pipe
    // TODO: should this be done before entering the service here, pass the handle?
    let mut sd = users_access()?;
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: &mut sd as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR,
        bInheritHandle: FALSE,
    };

    const BUFSIZE: usize = 512;
    let pipe_name = WideCString::from_str(PIPE_NAME)
        .unwrap()
        .into_boxed_wide_c_str();
    let control_pipe = HHolder(unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
            1,                // nMaxInstances
            BUFSIZE as DWORD, // nOutBufferSize
            BUFSIZE as DWORD, // nInBufferSize
            0,                // nDefaultTimeOut (50ms default)
            &mut sa as *mut SECURITY_ATTRIBUTES,
        )
    });
    if !control_pipe.valid() {
        // TODO: we need better handling here in general for failure cases, retry?
        return os_error!("CreateNamedPipeW");
    }

    // TODO: Probably want this in another fn
    // Define system service event handler that will be receiving service events.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

            // Handle stop
            ServiceControl::Stop => {
                // TODO: how to get this working when we dn't have status_handle yet?
                /*status_handle.set_service_status(
                    service_status(ServiceControlAccept::none(), ServiceStatus::StopPending))
                    .chain_err(ErrorKind::FailMessage("Set service status stop pending"))?;*/

                let mut in_buffer = [OperationCode::ServiceStop];
                let mut out_buffer = [];
                let mut bytes_read: DWORD = 0;
                let pipe_name = WideCString::from_str(PIPE_NAME)
                    .unwrap()
                    .into_boxed_wide_c_str();
                let rc = unsafe {
                    CallNamedPipeW(
                        pipe_name.as_ptr(),
                        in_buffer.as_mut_ptr() as LPVOID,
                        in_buffer.len() as DWORD,
                        out_buffer.as_mut_ptr() as LPVOID,
                        out_buffer.len() as DWORD,
                        &mut bytes_read,
                        NMPWAIT_WAIT_FOREVER, // TODO
                    )
                };
                if rc == 0 {
                    // TODO: log, still return NoError? Service thread may be wedged?
                }
                ServiceControlHandlerResult::NoError
            }

            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler.
    // The returned status handle should be used to report service status changes to the system.
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .chain_err(|| ErrorKind::FailMessage("Register service control handler"))?;

    // Tell the system that the service is running.
    status_handle
        .set_service_status(service_status(
            ServiceControlAccept::STOP,
            ServiceState::Running,
        ))
        .chain_err(|| ErrorKind::FailMessage("Set service status running"))?;

    // TODO: probably want this in another fn
    loop {
        let rc = unsafe { ConnectNamedPipe(*control_pipe, null_mut()) };
        if rc == 0 {
            // TODO: log and resume?
            return os_error!("ConnectNamedPipe");
        }
        let _ch = NamedPipeConnectionHolder(*control_pipe);

        // just read opcode
        let mut opcode: u8;
        let mut bytes_read: DWORD = 0;
        let rc = unsafe {
            opcode = uninitialized();
            ReadFile(
                *control_pipe,
                &mut opcode as *mut u8 as LPVOID,
                1 as DWORD,
                &mut bytes_read,
                null_mut(),
            )
        };
        let last_error = unsafe { GetLastError() };
        let more_data = rc == 0 && (last_error == ERROR_MORE_DATA);
        if rc == 0 && !more_data {
            return os_error!("ReadFile of pipe for opcode");
        }

        if bytes_read != 1 {
            // TODO: log and resume?
            continue;
        }

        let response = if opcode == OperationCode::ServiceStop as u8 {
            if more_data {
                vec![ResponseCode::BadCommand as u8]
            } else {
                break;
            }
        } else {
            match process_command(opcode, more_data, &control_pipe) {
                Ok(r) => r,
                Err(e) => match e.kind() {
                    ErrorKind::ServiceErrorBadCommand => vec![ResponseCode::BadCommand as u8],
                    _ => return Err(e),
                },
            }
        };

        let mut bytes_written = 0;
        let rc = unsafe {
            WriteFile(
                *control_pipe,
                response.as_ptr() as LPCVOID,
                response.len() as DWORD,
                &mut bytes_written,
                null_mut(),
            )
        };
        if rc == 0 || bytes_written as usize != response.len() {
            // TODO: log?
            continue;
        }

        let rc = unsafe { FlushFileBuffers(*control_pipe) };
        if rc == 0 {
            // TODO: log?
            continue;
        }
    } // loop end

    status_handle
        .set_service_status(service_status(
            ServiceControlAccept::empty(),
            ServiceState::Stopped,
        ))
        .chain_err(|| ErrorKind::FailMessage("Set service status stopped"))?;

    Ok(())
}

fn process_command(opcode: u8, more_data: bool, control_pipe: &HHolder) -> Result<Vec<u8>> {
    use byteorder::{NativeEndian, ReadBytesExt};
    use command;
    use std::io::Cursor;
    use std::mem::size_of;
    use winapi::shared::guiddef::GUID;

    match opcode {
        x if x == OperationCode::BitsCreate as u8 => {
            if more_data {
                Err(ErrorKind::ServiceErrorBadCommand.into())
            } else {
                Ok(bits_create("JOE'S"))
            }
        }
        x if x == OperationCode::BitsCancel as u8 => {
            if !more_data {
                Err(ErrorKind::ServiceErrorBadCommand.into())
            } else {
                Ok(bits_cancel(&read_data(
                    control_pipe,
                    command::BITS_CANCEL_CMD_LEN,
                    false,
                )?))
            }
        }
        x if x == OperationCode::BitsAddFile as u8 => {
            // need to do a bit more work here as the length is variable
            if !more_data {
                return Err(ErrorKind::ServiceErrorBadCommand.into());
            }

            let cmd = read_data(control_pipe, command::BITS_ADD_FILE_CMD_MIN_LEN, true)?;

            let guid = &cmd[0..size_of::<GUID>()];
            let mut reader = Cursor::new(&cmd[size_of::<GUID>()..]);
            let remote_url_length = reader.read_u16::<NativeEndian>().unwrap() as usize;
            let local_file_name_length = reader.read_u16::<NativeEndian>().unwrap() as usize;

            if remote_url_length == 0
                || remote_url_length / 2 * 2 != remote_url_length
                || local_file_name_length == 0
                || local_file_name_length / 2 * 2 != local_file_name_length
            {
                return Err(ErrorKind::ServiceErrorBadCommand.into());
            }

            let remote_url = read_data::<u16>(control_pipe, remote_url_length / 2, true)?;
            let local_file_name =
                read_data::<u16>(control_pipe, local_file_name_length / 2, false)?;

            Ok(bits_add_file(&guid, &remote_url, &local_file_name))
        }
        x if x == OperationCode::BitsResume as u8 => {
            // TODO: reduce redundancy here and with the next few?
            if !more_data {
                Err(ErrorKind::ServiceErrorBadCommand.into())
            } else {
                Ok(bits_resume(&read_data(
                    control_pipe,
                    command::BITS_RESUME_CMD_LEN,
                    false,
                )?))
            }
        }
        x if x == OperationCode::BitsSuspend as u8 => {
            if !more_data {
                Err(ErrorKind::ServiceErrorBadCommand.into())
            } else {
                Ok(bits_suspend(&read_data(
                    control_pipe,
                    command::BITS_SUSPEND_CMD_LEN,
                    false,
                )?))
            }
        }
        x if x == OperationCode::BitsGetStatus as u8 => {
            if !more_data {
                Err(ErrorKind::ServiceErrorBadCommand.into())
            } else {
                Ok(bits_get_status(&read_data(
                    control_pipe,
                    command::BITS_GET_STATUS_CMD_LEN,
                    false,
                )?))
            }
        }
        x if x == OperationCode::BitsComplete as u8 => {
            if !more_data {
                Err(ErrorKind::ServiceErrorBadCommand.into())
            } else {
                Ok(bits_complete(&read_data(
                    control_pipe,
                    command::BITS_COMPLETE_CMD_LEN,
                    false,
                )?))
            }
        }
        _ => Err(ErrorKind::ServiceErrorBadCommand.into()),
    }
}

fn read_data<T: Sized + Copy>(
    control_pipe: &HHolder,
    count_to_read: usize,
    expect_more: bool,
) -> Result<Vec<T>> {
    use std::mem::{size_of, uninitialized};
    use std::ptr::null_mut;
    use winapi::shared::minwindef::{DWORD, LPVOID};
    use winapi::shared::winerror::ERROR_MORE_DATA;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::fileapi::ReadFile;

    let mut buffer: Vec<T> = Vec::new();
    unsafe {
        buffer.resize(count_to_read, uninitialized());
    };

    let mut bytes_read = 0;
    let bytes_to_read = count_to_read * size_of::<T>();
    let rc = unsafe {
        ReadFile(
            **control_pipe,
            buffer.as_mut_slice().as_mut_ptr() as LPVOID,
            bytes_to_read as DWORD,
            &mut bytes_read,
            null_mut(),
        )
    };
    let last_error = unsafe { GetLastError() };
    let more_data = rc == 0 && (last_error == ERROR_MORE_DATA);
    if rc == 0 && !more_data {
        return os_error!("ReadFile of pipe");
    }

    if more_data != expect_more {
        return Err(ErrorKind::ServiceErrorBadCommand.into());
    }

    Ok(buffer)
}

// TODO: a lot of redundancy below should be able to be factored out
// everything that has a GUID at the beginning, in particular, should be unified both here and in
// bits.rs (and probably above in the pipe reading as well)
// And the conversion of error types should be unified, with some unique service error types
// being chained in bits.rs and then translated up a level into the response

// TODO: failure modes
// - permission?
fn bits_create(name: &str) -> Vec<u8> {
    use command::ResponseCode;

    let name = WideCString::from_str(name).unwrap();
    // TODO: log errors, specific errors
    let guid = match bits::create_job(name) {
        Ok((guid, _job)) => guid,
        Err(_) => return vec![ResponseCode::Failure as u8],
    };

    let mut response = vec![ResponseCode::Success as u8];
    serialize_guid(&mut response, &guid);
    response
}

// TODO: failure modes
// - job doesn't exist
// - permission
fn bits_cancel(cmd: &[u8]) -> Vec<u8> {
    use command::{ResponseCode, BITS_CANCEL_CMD_LEN};
    use std::mem::size_of;
    use winapi::shared::guiddef::GUID;

    if cmd.len() != BITS_CANCEL_CMD_LEN {
        return vec![ResponseCode::BadCommand as u8];
    }

    // TODO: log errors, specific errors
    match bits::cancel_job(&deserialize_guid(&cmd[0..size_of::<GUID>()]).unwrap()) {
        Ok(_) => vec![ResponseCode::Success as u8],
        Err(_) => vec![ResponseCode::Failure as u8],
    }
}

// TODO: failure modes
// - directory permission
// - invalidarg
fn bits_add_file(guid: &[u8], remote_url: &[u16], local_file_name: &[u16]) -> Vec<u8> {
    use command::ResponseCode;
    use std::mem::size_of;
    use winapi::shared::guiddef::GUID;

    if guid.len() != size_of::<GUID>() {
        return vec![ResponseCode::BadCommand as u8];
    }

    let guid = &deserialize_guid(&guid[0..size_of::<GUID>()]).unwrap();

    let remote_url = match unsafe { WideCString::from_ptr(remote_url.as_ptr(), remote_url.len()) } {
        Err(_) => return vec![ResponseCode::BadCommand as u8],
        Ok(s) => s,
    };
    let local_file_name =
        match unsafe { WideCString::from_ptr(local_file_name.as_ptr(), local_file_name.len()) } {
            Err(_) => return vec![ResponseCode::BadCommand as u8],
            Ok(s) => s,
        };

    // TODO: log errors, more specific errors
    match bits::add_file(guid, &remote_url, &local_file_name) {
        Ok(_) => vec![ResponseCode::Success as u8],
        Err(_) => vec![ResponseCode::Failure as u8],
    }
}

fn bits_resume(cmd: &[u8]) -> Vec<u8> {
    use command::{ResponseCode, BITS_RESUME_CMD_LEN};
    use std::mem::size_of;
    use winapi::shared::guiddef::GUID;

    if cmd.len() != BITS_RESUME_CMD_LEN {
        return vec![ResponseCode::BadCommand as u8];
    }

    // TODO: log errors, specific errors
    match bits::resume(&deserialize_guid(&cmd[0..size_of::<GUID>()]).unwrap()) {
        Ok(_) => vec![ResponseCode::Success as u8],
        Err(_) => vec![ResponseCode::Failure as u8],
    }
}

fn bits_suspend(cmd: &[u8]) -> Vec<u8> {
    use command::{ResponseCode, BITS_SUSPEND_CMD_LEN};
    use std::mem::size_of;
    use winapi::shared::guiddef::GUID;

    if cmd.len() != BITS_SUSPEND_CMD_LEN {
        return vec![ResponseCode::BadCommand as u8];
    }

    // TODO: log errors, specific errors
    match bits::suspend(&deserialize_guid(&cmd[0..size_of::<GUID>()]).unwrap()) {
        Ok(_) => vec![ResponseCode::Success as u8],
        Err(_) => vec![ResponseCode::Failure as u8],
    }
}

fn bits_get_status(cmd: &[u8]) -> Vec<u8> {
    use byteorder::{NativeEndian, WriteBytesExt};
    use command::{ResponseCode, BITS_GET_STATUS_CMD_LEN};
    use std::mem::size_of;
    use winapi::shared::guiddef::GUID;

    if cmd.len() != BITS_GET_STATUS_CMD_LEN {
        return vec![ResponseCode::BadCommand as u8];
    }

    // TODO errors
    let status = bits::get_status(&deserialize_guid(&cmd[0..size_of::<GUID>()]).unwrap());
    if let Err(_) = status {
        return vec![ResponseCode::Failure as u8];
    }
    let status = status.unwrap();

    let mut result = Vec::new();
    result.write_u8(ResponseCode::Success as u8).unwrap();

    result.write_u32::<NativeEndian>(status.state).unwrap();
    serialize_bg_job_progress(&mut result, &status.progress);
    result
        .write_u32::<NativeEndian>(status.error_count)
        .unwrap();

    if let Some(error) = status.error {
        result.write_u32::<NativeEndian>(error.context).unwrap();
        result.write_i32::<NativeEndian>(error.error).unwrap();
    } else {
        result.write_u32::<NativeEndian>(0).unwrap();
        result.write_i32::<NativeEndian>(0).unwrap();
    }

    assert!(result.len() == 1 + BITS_GET_STATUS_RES_LEN);

    result
}

// TODO: a lot of the actions are exactly the same code
fn bits_complete(cmd: &[u8]) -> Vec<u8> {
    use command::{ResponseCode, BITS_COMPLETE_CMD_LEN};
    use std::mem::size_of;
    use winapi::shared::guiddef::GUID;

    if cmd.len() != BITS_COMPLETE_CMD_LEN {
        return vec![ResponseCode::BadCommand as u8];
    }

    // TODO: log errors, specific errors
    match bits::complete(&deserialize_guid(&cmd[0..size_of::<GUID>()]).unwrap()) {
        Ok(_) => vec![ResponseCode::Success as u8],
        Err(_) => vec![ResponseCode::Failure as u8],
    }
}
