// Implemented outside of windows-service as it's somewhat special-case
//
// TODO: check a lot of careless stuff in here, I didn't understand absolute vs.
// self-relative Security Descriptors at the time I wrote it. Probably a number
// of double-frees around.

use std::ffi::OsStr;
use std::ptr::{null, null_mut};

use widestring::WideCString;
use winapi::shared::lmcons::{DNLEN, UNLEN};
use winapi::shared::minwindef::{DWORD, FALSE, LPDWORD, TRUE};
use winapi::um::minwinbase::LPTR;
use winapi::um::winnt::{PACL, PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR, WELL_KNOWN_SID_TYPE};

use util::*;
use {ErrorKind, Result};

fn get_last_error() -> DWORD {
    use winapi::um::errhandlingapi::GetLastError;
    unsafe { GetLastError() }
}

/// Grant start and stop access to a service to all local users (TODO check what WinBuiltinUsersSid exactly means).
pub fn grant_service_access<T: AsRef<OsStr>>(service_name: T) -> Result<()> {
    let service_manager = open_service_manager()?;
    let service = open_service(&service_manager, service_name)?;
    let sd = read_service_dacl(&service)?;
    set_user_permissions(&service, &sd.pacl)?;
    Ok(())
}

/// Create security descriptor for read and write access for all local users
pub fn users_access() -> Result<SECURITY_DESCRIPTOR> {
    use winapi::um::winnt::{WinBuiltinUsersSid, GENERIC_READ, GENERIC_WRITE};

    update_acl(
        &null_mut(),
        &mut well_known_account_name(WinBuiltinUsersSid)?,
        GENERIC_READ | GENERIC_WRITE,
    )
}

fn open_service_manager() -> Result<SCHolder> {
    use winapi::um::winsvc::OpenSCManagerW;

    // Open the service manager
    let service_manager = SCHolder(unsafe {
        OpenSCManagerW(
            null(), // local computer
            null(), // active database
            0,      // no special permissions needed
        )
    });

    if service_manager.valid() {
        Ok(service_manager)
    } else {
        os_error!("OpenSCManagerW")
    }
}

fn open_service<T: AsRef<OsStr>>(service_manager: &SCHolder, service_name: T) -> Result<SCHolder> {
    use winapi::um::winnt::{READ_CONTROL, WRITE_DAC};
    use winapi::um::winsvc::OpenServiceW;

    let service_name = WideCString::from_str(service_name).unwrap();
    let service = SCHolder(unsafe {
        OpenServiceW(
            **service_manager,
            service_name.as_ptr(),
            READ_CONTROL | WRITE_DAC,
        )
    });

    if service.valid() {
        Ok(service)
    } else {
        os_error!("OpenServiceW")
    }
}

// These are kept together to avoid pacl from outliving psd
// TODO: find a proper way to do this with lifetimes?
struct SD {
    _psd: LAHolder,
    pacl: PACL,
}

fn read_service_dacl(service: &SCHolder) -> Result<SD> {
    use winapi::shared::minwindef::LPBOOL;
    use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;
    use winapi::um::securitybaseapi::GetSecurityDescriptorDacl;
    use winapi::um::winbase::LocalAlloc;
    use winapi::um::winnt::DACL_SECURITY_INFORMATION;
    use winapi::um::winsvc::QueryServiceObjectSecurity;

    // Find size needed
    let mut bytes_needed: DWORD = 0;
    let rc = unsafe {
        QueryServiceObjectSecurity(
            **service,
            DACL_SECURITY_INFORMATION,
            null_mut(), // lpSecurityDescriptor
            0,          // cbBufSize
            &mut bytes_needed as LPDWORD,
        )
    };
    if rc != 0 || get_last_error() != ERROR_INSUFFICIENT_BUFFER {
        return os_error!("QueryServiceObjectSecurity for size");
    }

    let psd = LAHolder(unsafe { LocalAlloc(LPTR, bytes_needed as usize) });
    if !psd.valid() {
        return os_error!("LocalAlloc for security descriptor");
    }

    let mut temp_bytes_needed: DWORD = 0;
    let rc = unsafe {
        QueryServiceObjectSecurity(
            **service,
            DACL_SECURITY_INFORMATION,
            *psd,         // lpSecurityDescriptor
            bytes_needed, // cbBufSize
            &mut temp_bytes_needed as LPDWORD,
        )
    };
    if rc == 0 {
        return os_error!("QueryServiceObjectSecurity for DACL");
    }

    // NOTE: we don't ever want to free this pointer, it points into psd
    let mut pacl = null_mut();
    let mut dacl_present = FALSE;
    let mut dacl_defaulted = FALSE;
    let rc = unsafe {
        GetSecurityDescriptorDacl(
            *psd,
            &mut dacl_present as LPBOOL,
            &mut pacl,
            &mut dacl_defaulted as LPBOOL,
        )
    };
    if rc == 0 {
        return os_error!("GetSecurityDescriptorDacl");
    }

    Ok(SD { _psd: psd, pacl })
}

fn set_user_permissions(service: &SCHolder, pacl: &PACL) -> Result<()> {
    use winapi::um::winnt::{WinBuiltinUsersSid, DACL_SECURITY_INFORMATION, GENERIC_READ};
    use winapi::um::winsvc::{SetServiceObjectSecurity, SERVICE_START, SERVICE_STOP};

    // Update ACL with permission for Users
    let mut account_name = well_known_account_name(WinBuiltinUsersSid)?;
    let permissions = SERVICE_START | SERVICE_STOP | GENERIC_READ;

    let mut sd = update_acl(&pacl, &mut account_name, permissions)?;

    let rc = unsafe {
        SetServiceObjectSecurity(
            **service,
            DACL_SECURITY_INFORMATION,
            &mut sd as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR,
        )
    };
    if rc == 0 {
        os_error!("SetServiceObjectSecurity")
    } else {
        Ok(())
    }
}

type AccountName = [u16; UNLEN as usize + 1];

fn well_known_account_name(sid_type: WELL_KNOWN_SID_TYPE) -> Result<AccountName> {
    use winapi::shared::minwindef::BOOL;
    use winapi::um::minwinbase::LMEM_FIXED;
    use winapi::um::securitybaseapi::CreateWellKnownSid;
    use winapi::um::winbase::LocalAlloc;
    use winapi::um::winnt::{LPCWSTR, LPWSTR, PSID, PSID_NAME_USE, SECURITY_MAX_SID_SIZE};

    let mut sid_size = SECURITY_MAX_SID_SIZE as DWORD;
    let psid = LAHolder(unsafe { LocalAlloc(LMEM_FIXED, sid_size as usize) });
    if psid.is_null() {
        return os_error!("LocalAlloc for SID");
    }

    let rc = unsafe {
        CreateWellKnownSid(
            sid_type,      // WellKnownSidType
            null_mut(),    // DomainSid
            *psid,         // pSid
            &mut sid_size, // cbSid
        )
    };
    if rc == 0 {
        return os_error!("CreateWellKnownSid");
    }

    let mut account_name = [0; UNLEN as usize + 1];
    let mut account_name_len = account_name.len() as DWORD;
    // We don't use domain name but it is supposedly needed despite being marked
    // _Out_opt_ in MSDN
    let mut domain_name = [0; DNLEN as usize + 1];
    let mut domain_name_len = domain_name.len() as DWORD;
    let mut account_type = 0u32;

    extern "system" {
        pub fn LookupAccountSidW(
            lpSystemName: LPCWSTR,
            lpSid: PSID,
            lpName: LPWSTR,
            cchName: LPDWORD,
            lpReferencedDomainName: LPWSTR,
            cchReferencedDomainName: LPDWORD,
            peUse: PSID_NAME_USE,
        ) -> BOOL;
    }

    let rc = unsafe {
        LookupAccountSidW(
            null(), // lpSystemName, local system
            *psid,
            account_name.as_mut_ptr(),
            &mut account_name_len as LPDWORD,
            domain_name.as_mut_ptr(),
            &mut domain_name_len as LPDWORD,
            &mut account_type as PSID_NAME_USE,
        )
    };
    if rc == 0 {
        return os_error!("LookupAccountSidW");
    }

    Ok(account_name)
}

fn update_acl(
    pacl: &PACL,
    account_name: &mut AccountName,
    permissions: DWORD,
) -> Result<SECURITY_DESCRIPTOR> {
    use winapi::shared::winerror::ERROR_SUCCESS;
    use winapi::um::accctrl::{EXPLICIT_ACCESS_W, NO_INHERITANCE, SET_ACCESS, TRUSTEE_W};
    use winapi::um::aclapi::{BuildExplicitAccessWithNameW, SetEntriesInAclW};
    use winapi::um::securitybaseapi::{InitializeSecurityDescriptor, SetSecurityDescriptorDacl};
    use winapi::um::winnt::SECURITY_DESCRIPTOR_REVISION;

    let mut ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0,
        grfAccessMode: 0,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: 0,
            TrusteeType: 0,
            ptstrName: null_mut(),
        },
    };
    unsafe {
        BuildExplicitAccessWithNameW(
            &mut ea,
            account_name.as_mut_ptr(),
            permissions,
            SET_ACCESS,
            NO_INHERITANCE,
        )
    };

    let mut new_pacl = null_mut();
    let rc = unsafe {
        SetEntriesInAclW(
            1,                          // cCountOfExplicitEntries
            &mut ea,                    // pListOfExplicitEntries
            *pacl,                      // OldAcl
            &mut new_pacl as *mut PACL, // NewAcl
        )
    };
    if rc != ERROR_SUCCESS {
        return os_error!("SetEntriesInAclW");
    }

    let mut sd = SECURITY_DESCRIPTOR {
        Revision: 0,
        Sbz1: 0,
        Control: 0,
        Owner: null_mut(),
        Group: null_mut(),
        Sacl: null_mut(),
        Dacl: null_mut(),
    };
    let rc = unsafe {
        InitializeSecurityDescriptor(
            &mut sd as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR,
            SECURITY_DESCRIPTOR_REVISION,
        )
    };
    if rc == 0 {
        return os_error!("InitializeSecurityDescriptor");
    }

    let rc = unsafe {
        SetSecurityDescriptorDacl(
            &mut sd as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR,
            TRUE, // bDaclPresent
            new_pacl,
            FALSE, // bDaclDefaulted
        )
    };
    if rc == 0 {
        return os_error!("SetSecurityDescriptorDacl");
    }

    Ok(sd)
}
