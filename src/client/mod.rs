use command::*;
use util::CoTaskMemHolder;
use {ErrorKind, Result};

use widestring::WideCString;
use winapi::shared::guiddef::GUID;

pub fn bits_create() -> Result<GUID> {
    use std::mem::size_of;

    let mut in_buffer: [u8; 1] = [OperationCode::BitsCreate as u8];
    let result = call_command(&mut in_buffer, BITS_CREATE_RES_LEN)?;

    let guid = deserialize_guid(&result[0..size_of::<GUID>()]).unwrap();

    print_guid(&guid);
    Ok(guid)
}

fn print_guid(guid: &GUID) {
    println!(
        "\"{}\"",
        unsafe { WideCString::from_ptr_str(*string_from_guid(guid).unwrap() as *const u16) }
            .to_string()
            .unwrap()
    );
}

// TODO: could do with some reduction of redundancy parsing the GUID
pub fn bits_cancel(guid: &str) -> Result<()> {
    let guid = match guid_from_str(guid) {
        None => return Err(ErrorKind::InvalidCommandLine.into()), // TODO: better error
        Some(g) => g,
    };

    let mut in_buffer = vec![OperationCode::BitsCancel as u8];
    serialize_guid(&mut in_buffer, &guid);
    call_command(&mut in_buffer, BITS_CANCEL_RES_LEN)?;
    Ok(())
}

pub fn bits_add_file(guid: &str, remote_url: &str, local_file_name: &str) -> Result<()> {
    use byteorder::{NativeEndian, WriteBytesExt};

    let guid = match guid_from_str(guid) {
        None => return Err(ErrorKind::InvalidCommandLine.into()),
        Some(g) => g,
    };

    let mut in_buffer = vec![OperationCode::BitsAddFile as u8];
    serialize_guid(&mut in_buffer, &guid);

    let mut remote_url_buf = Vec::new();
    serialize_string(&mut remote_url_buf, remote_url)?;
    if remote_url_buf.len() > u16::max_value() as usize {
        return Err(ErrorKind::InvalidCommandLine.into());
    }
    in_buffer
        .write_u16::<NativeEndian>(remote_url_buf.len() as u16)
        .unwrap();

    let mut local_file_name_buf = Vec::new();
    serialize_string(&mut local_file_name_buf, local_file_name)?;
    if local_file_name_buf.len() > u16::max_value() as usize {
        return Err(ErrorKind::InvalidCommandLine.into());
    }
    in_buffer
        .write_u16::<NativeEndian>(local_file_name_buf.len() as u16)
        .unwrap();

    in_buffer.append(&mut remote_url_buf);
    in_buffer.append(&mut local_file_name_buf);

    call_command(&mut in_buffer, BITS_ADD_FILE_RES_LEN)?;
    Ok(())
}

pub fn bits_resume(guid: &str) -> Result<()> {
    bits_guid_only_command(guid, OperationCode::BitsResume)
}

pub fn bits_suspend(guid: &str) -> Result<()> {
    bits_guid_only_command(guid, OperationCode::BitsSuspend)
}

pub fn bits_complete(guid: &str) -> Result<()> {
    bits_guid_only_command(guid, OperationCode::BitsComplete)
}

pub fn bits_get_status(guid: &str) -> Result<()> {
    let guid = match guid_from_str(guid) {
        None => return Err(ErrorKind::InvalidCommandLine.into()),
        Some(g) => g,
    };

    let mut request = vec![OperationCode::BitsGetStatus as u8];
    serialize_guid(&mut request, &guid);
    let result = call_command(&mut request, BITS_GET_STATUS_RES_LEN)?;
    print_status(&result);

    Ok(())
}

pub fn bits_get_status_me(guid: &str) -> Result<()> {
    let guid = match guid_from_str(guid) {
        None => return Err(ErrorKind::InvalidCommandLine.into()),
        Some(g) => g,
    };

    let status = ::service::bits::get_status(&guid)?;
    println!("get status ok");
    Ok(())
}

fn print_status(result: &[u8]) {
    use std::io::Cursor;
    use std::mem::size_of;

    use byteorder::{NativeEndian, ReadBytesExt};
    use winapi::shared::minwindef::ULONG;
    use winapi::um::bits::{
        BG_ERROR_CONTEXT, BG_JOB_PROGRESS, BG_JOB_STATE, BG_JOB_STATE_ERROR,
        BG_JOB_STATE_TRANSIENT_ERROR, BG_SIZE_UNKNOWN,
    };
    use winapi::um::winnt::HRESULT;

    assert!(result.len() == BITS_GET_STATUS_RES_LEN);

    let mut reader = Cursor::new(result);
    let state: BG_JOB_STATE = reader.read_u32::<NativeEndian>().unwrap();
    let pos = reader.position() as usize;
    let progress =
        deserialize_bg_job_progress(&result[pos..pos + size_of::<BG_JOB_PROGRESS>()]).unwrap();
    reader.set_position((pos + size_of::<BG_JOB_PROGRESS>()) as u64);
    let error_count: ULONG = reader.read_u32::<NativeEndian>().unwrap();

    println!("state: {}, errors: {}", state, error_count);
    if progress.BytesTotal != BG_SIZE_UNKNOWN {
        println!(
            "progress: {}/{} bytes, {}/{} files",
            progress.BytesTransferred,
            progress.BytesTotal,
            progress.FilesTransferred,
            progress.FilesTotal
        );
    }

    if state == BG_JOB_STATE_ERROR || state == BG_JOB_STATE_TRANSIENT_ERROR {
        let error_context: BG_ERROR_CONTEXT = reader.read_u32::<NativeEndian>().unwrap();
        let error_hr: HRESULT = reader.read_i32::<NativeEndian>().unwrap();

        println!("error {:#x}, HRESULT {:#x}", error_context, error_hr);
    }
}

fn bits_guid_only_command(guid: &str, opcode: OperationCode) -> Result<()> {
    let guid = match guid_from_str(guid) {
        None => return Err(ErrorKind::InvalidCommandLine.into()),
        Some(g) => g,
    };

    let mut in_buffer = vec![opcode as u8];
    serialize_guid(&mut in_buffer, &guid);
    call_command(&mut in_buffer, 0)?;
    Ok(())
}

// TODO: should only read only the one byte status first; if the command wasn't successful then
// we can make no expectations about the contents of the rest of the message
// TODO: should the result be the win32 error instead?
fn call_command(in_buffer: &mut [u8], expected_response_size: usize) -> Result<Vec<u8>> {
    use widestring::WideCString;
    use winapi::shared::minwindef::{DWORD, LPVOID};
    use winapi::um::namedpipeapi::CallNamedPipeW;
    use PIPE_NAME;

    // TODO: submit to winapi
    // TODO: longer wait? longer default?
    const NMPWAIT_USE_DEFAULT_WAIT: DWORD = 0;

    let mut out_buffer = vec![0; 1 + expected_response_size];
    let mut bytes_read = 0;

    // TODO: handle service not started
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
            NMPWAIT_USE_DEFAULT_WAIT,
        )
    };
    if rc == 0 {
        return os_error!("CallNamedPipeW");
    }

    if bytes_read as usize != 1 + expected_response_size {
        return Err(ErrorKind::FailMessage("Read response from server").into());
    }
    if out_buffer[0] != ResponseCode::Success as u8 {
        return Err(ErrorKind::FailureFromService(out_buffer[0]).into());
    }

    out_buffer.remove(0);
    Ok(out_buffer)
}

// TODO: this should return an error specifying whether the string was bad or some other error
fn guid_from_str(src: &str) -> Option<GUID> {
    use std::mem::uninitialized;
    use std::ptr::null_mut;
    use widestring::WideCString;
    use winapi::shared::winerror::SUCCEEDED;
    use winapi::um::combaseapi::{CLSIDFromString, CoInitializeEx};
    use winapi::um::objbase::COINIT_APARTMENTTHREADED;

    unsafe {
        CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED);
    };

    let src = WideCString::from_str(src).unwrap().into_boxed_wide_c_str();
    let mut guid: GUID;
    let rc = unsafe {
        guid = uninitialized();
        CLSIDFromString(src.as_ptr(), &mut guid)
    };
    if !SUCCEEDED(rc) {
        return None;
    }

    Some(guid)
}

fn string_from_guid(guid: &GUID) -> Option<CoTaskMemHolder> {
    use std::ptr::null_mut;
    use winapi::shared::minwindef::LPVOID;
    use winapi::shared::winerror::SUCCEEDED;
    use winapi::um::combaseapi::{CoInitializeEx, StringFromCLSID};
    use winapi::um::objbase::COINIT_APARTMENTTHREADED;

    let mut string = null_mut();
    let rc = unsafe {
        CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED);

        StringFromCLSID(guid, &mut string)
    };
    if !SUCCEEDED(rc) {
        None
    } else {
        Some(CoTaskMemHolder(string as LPVOID))
    }
}
