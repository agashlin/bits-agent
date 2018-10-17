use std::mem;
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::ULONG;
use winapi::um::bits::{BG_ERROR_CONTEXT, BG_JOB_PROGRESS, BG_JOB_STATE};
use winapi::um::winnt::HRESULT;

use {ErrorKind, Result};

const GUID_SIZE: usize = 16;
const BG_JOB_STATE_SIZE: usize = 4;
const BG_JOB_PROGRESS_SIZE: usize = 24;
const HRESULT_SIZE: usize = 4;
const U16_SIZE: usize = 2;
const ULONG_SIZE: usize = 4;
const BG_ERROR_CONTEXT_SIZE: usize = 4;

// compile time assert field sizes
fn _size_check(
    guid: &GUID,
    bg_job_state: BG_JOB_STATE,
    bg_job_progress: &BG_JOB_PROGRESS,
    hresult: HRESULT,
    usx: u16,
    ulong: ULONG,
    bg_error_context: BG_ERROR_CONTEXT,
) {
    unsafe {
        mem::transmute::<GUID, [u8; GUID_SIZE]>(*guid);
        mem::transmute::<BG_JOB_STATE, [u8; BG_JOB_STATE_SIZE]>(bg_job_state);
        mem::transmute::<BG_JOB_PROGRESS, [u8; BG_JOB_PROGRESS_SIZE]>(*bg_job_progress);
        mem::transmute::<HRESULT, [u8; HRESULT_SIZE]>(hresult);
        mem::transmute::<u16, [u8; U16_SIZE]>(usx);
        mem::transmute::<ULONG, [u8; ULONG_SIZE]>(ulong);
        mem::transmute::<BG_ERROR_CONTEXT, [u8; BG_ERROR_CONTEXT_SIZE]>(bg_error_context);
    };
}

define_deserialize!(deserialize_guid, GUID);
define_serialize!(serialize_guid, GUID);
define_deserialize!(deserialize_bg_job_progress, BG_JOB_PROGRESS);
define_serialize!(serialize_bg_job_progress, BG_JOB_PROGRESS);

/// Convert a string slice into UTF-16, serialize to bytes
pub fn serialize_string(v: &mut Vec<u8>, s: &str) -> Result<()> {
    use std::slice;
    use widestring::WideCString;
    match WideCString::from_str(s) {
        Ok(cs) => {
            v.extend_from_slice(unsafe {
                slice::from_raw_parts(cs.as_ptr() as *const u8, cs.len() * 2)
            });
            Ok(())
        }
        Err(_) => Err(ErrorKind::InvalidCommandLine.into()),
    }
}

#[repr(u8)]
pub enum OperationCode {
    ServiceStop = 1,
    BitsCreate = 2,
    BitsCancel = 3,
    BitsAddFile = 4,
    BitsResume = 5,
    BitsSuspend = 6,
    BitsSetOptions = 7,
    BitsGetStatus = 8,
    BitsComplete = 9,
}

#[repr(u8)]
pub enum ResponseCode {
    Success = 1,
    Failure = 2,
    BadCommand = 3,
    NoSuchJob = 4,
    Permission = 5,
}

//pub const BITS_CREATE_CMD_LEN: usize = 0;
// Response: 0-15: GUID (if response code is Success)
pub const BITS_CREATE_RES_LEN: usize = GUID_SIZE;

// Command: 0-15: GUID
pub const BITS_CANCEL_CMD_LEN: usize = GUID_SIZE;
pub const BITS_CANCEL_RES_LEN: usize = 0;

// Command: 0-15: GUID
//          16-17:      : Remote URL length in bytes, u16 (N)
//          18-19       : Local file name length in bytes, u16 (M)
//          20-(20+N-1) : Remote URL in UTF-16 (no NUL terminator)
//      (20+N)-(20+N+M-1): Local file name in UTF-16 (no NUL terminator)
pub const BITS_ADD_FILE_CMD_MIN_LEN: usize = GUID_SIZE + U16_SIZE * 2;
pub const BITS_ADD_FILE_RES_LEN: usize = 0;

// Command: 0-15: GUID
pub const BITS_RESUME_CMD_LEN: usize = GUID_SIZE;
//pub const BITS_RESUME_RES_LEN: usize = 0;

// Command: 0-15: GUID
pub const BITS_SUSPEND_CMD_LEN: usize = GUID_SIZE;
//pub const BITS_SUSPEND_RES_LEN: usize = 0;

// SET_OPTIONS not yet specified, to be a combination of SetPriority (maybe?), SetNotifyInterface,
// SetNotifyFlags, SetNoProgressTimeout, SetMinimumRetryDelay
// Don't think we'll have a use for SetDescription or SetDisplayName

// Command: 0-15: GUID
pub const BITS_GET_STATUS_CMD_LEN: usize = GUID_SIZE;
// Response:  0- 3: BG_JOB_STATE (u32)
//            4-27: BG_JOB_PROGRESS (struct)
//           28-31: ULONG error count (u32)
//           32-35: BG_ERROR_CONTEXT (u32)    \ 0 if job state not BG_JOB_STATE_ERROR
//           36-39: HRESULT from GetError (i32)/ or BG_JOB_STATE_TRANSIENT_ERROR
pub const BITS_GET_STATUS_RES_LEN: usize =
    BG_JOB_STATE_SIZE + BG_JOB_PROGRESS_SIZE + ULONG_SIZE + BG_ERROR_CONTEXT_SIZE + HRESULT_SIZE;

// Command: 0-15: GUID
pub const BITS_COMPLETE_CMD_LEN: usize = GUID_SIZE;
//pub const BITS_COMPLETE_RES_LEN: usize = 0;
