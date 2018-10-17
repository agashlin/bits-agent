use std::mem;
use std::ptr::null_mut;

use widestring::WideCStr;

use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::ULONG;
use winapi::shared::winerror::SUCCEEDED;
use winapi::um::bits::{BG_ERROR_CONTEXT, BG_JOB_PROGRESS, BG_JOB_STATE};
use winapi::um::winnt::HRESULT;

use util::{BCErrHolder, BCJobHolder, BCMHolder};
use {ErrorKind, Result, ResultExt};

const BACKGROUND_COPY_MANAGER: GUID = GUID {
    Data1: 0x4991d34b,
    Data2: 0x80a1,
    Data3: 0x4291,
    Data4: [0x83, 0xb6, 0x33, 0x28, 0x36, 0x6b, 0x90, 0x97],
};

pub fn create_job<T: AsRef<WideCStr>>(name: T) -> Result<(GUID, BCJobHolder)> {
    // TODO: handle differently error:
    // - job already exists
    use winapi::um::bits::{IBackgroundCopyJob, BG_JOB_TYPE_DOWNLOAD};
    let bcm =
        connect_bcm().chain_err(|| ErrorKind::FailMessage("Connect Background Copy Manager"))?;

    let mut guid;
    let mut pjob: *mut IBackgroundCopyJob = null_mut();
    let rc = unsafe {
        guid = mem::uninitialized();
        (**bcm).CreateJob(
            name.as_ref().as_ptr(),
            BG_JOB_TYPE_DOWNLOAD,
            &mut guid,
            &mut pjob,
        )
    };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("CreateJob", rc).into());
    }

    Ok((guid, BCJobHolder(pjob)))
}

pub fn cancel_job(guid: &GUID) -> Result<()> {
    let job = get_job(guid)?;
    let rc = unsafe { (**job).Cancel() };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("Cancel job", rc).into());
    }

    Ok(())
}

pub fn add_file<T, U>(guid: &GUID, remote_url: &T, local_file: &U) -> Result<()>
where
    T: AsRef<WideCStr>,
    U: AsRef<WideCStr>,
{
    let job = get_job(guid)?;
    let rc = unsafe { (**job).AddFile(remote_url.as_ref().as_ptr(), local_file.as_ref().as_ptr()) };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("AddFile to job", rc).into());
    }

    Ok(())
}

pub fn resume(guid: &GUID) -> Result<()> {
    let job = get_job(guid)?;
    let rc = unsafe { (**job).Resume() };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("Resume job", rc).into());
    }

    Ok(())
}

pub fn suspend(guid: &GUID) -> Result<()> {
    let job = get_job(guid)?;
    let rc = unsafe { (**job).Suspend() };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("Suspend job", rc).into());
    }

    Ok(())
}

pub fn complete(guid: &GUID) -> Result<()> {
    let job = get_job(guid)?;
    let rc = unsafe { (**job).Complete() };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("Complete job", rc).into());
    }

    Ok(())
}

pub struct BCJobError {
    pub context: BG_ERROR_CONTEXT,
    pub error: HRESULT,
}

pub struct BCJobStatus {
    pub state: BG_JOB_STATE,
    pub progress: BG_JOB_PROGRESS,
    pub error_count: ULONG,
    pub error: Option<BCJobError>,
}

pub fn get_status(guid: &GUID) -> Result<BCJobStatus> {
    use winapi::um::bits::{BG_JOB_STATE_ERROR, BG_JOB_STATE_TRANSIENT_ERROR};

    let job = get_job(guid)?;
    let mut state = 0;
    let rc = unsafe { (**job).GetState(&mut state) };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("GetState", rc).into());
    }

    let mut progress;
    let rc = unsafe {
        progress = mem::uninitialized();
        (**job).GetProgress(&mut progress)
    };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("GetProgress", rc).into());
    }

    // TODO: is this working properly? haven't seen it report anything but 0 even with a
    // transient error, but I'm having trouble causing permanent errors...
    let mut error_count = 0;
    let rc = unsafe { (**job).GetErrorCount(&mut error_count) };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("GetErrorCount", rc).into());
    }

    let error;
    if state == BG_JOB_STATE_ERROR || state == BG_JOB_STATE_TRANSIENT_ERROR {
        let error_obj = {
            let mut perror = null_mut();
            let rc = unsafe { (**job).GetError(&mut perror) };
            if !SUCCEEDED(rc) {
                return Err(ErrorKind::OSErrorHRESULT("GetError for job", rc).into());
            }
            BCErrHolder(perror)
        };

        let mut error_context = 0;
        let mut error_hresult = 0;
        let rc = unsafe { (**error_obj).GetError(&mut error_context, &mut error_hresult) };
        if !SUCCEEDED(rc) {
            return Err(ErrorKind::OSErrorHRESULT("GetError for error", rc).into());
        }

        error = Some(BCJobError {
            context: error_context,
            error: error_hresult,
        });
    } else {
        error = None;
    }

    Ok(BCJobStatus {
        state,
        progress,
        error_count,
        error,
    })
}

fn get_job(guid: &GUID) -> Result<BCJobHolder> {
    let bcm =
        connect_bcm().chain_err(|| ErrorKind::FailMessage("Connect Background Copy Manager"))?;

    let mut pjob = null_mut();
    let rc = unsafe { (**bcm).GetJob(guid, &mut pjob) };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("GetJob", rc).into());
    }

    Ok(BCJobHolder(pjob))
}

fn connect_bcm() -> Result<BCMHolder> {
    use winapi::shared::minwindef::LPVOID;
    use winapi::shared::wtypesbase::CLSCTX_LOCAL_SERVER;
    use winapi::um::bits::IBackgroundCopyManager;
    use winapi::um::combaseapi::CoCreateInstance;
    use winapi::Interface;

    let mut pbcm: *mut IBackgroundCopyManager = null_mut();

    let rc = unsafe {
        CoCreateInstance(
            &BACKGROUND_COPY_MANAGER,
            null_mut(), // pUnkOuter
            CLSCTX_LOCAL_SERVER,
            &IBackgroundCopyManager::uuidof() as *const GUID,
            &mut pbcm as *mut *mut IBackgroundCopyManager as *mut LPVOID,
        )
    };
    if !SUCCEEDED(rc) {
        return Err(ErrorKind::OSErrorHRESULT("CoCreateInstance", rc).into());
    }

    Ok(BCMHolder(pbcm))
}
