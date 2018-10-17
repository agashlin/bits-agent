use std::ops::Deref;
use std::ptr::null_mut;

use winapi::shared::minwindef::LPVOID;
use winapi::um::bits::{IBackgroundCopyError, IBackgroundCopyJob, IBackgroundCopyManager};
use winapi::um::combaseapi::CoTaskMemFree;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::DisconnectNamedPipe;
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{HANDLE, PVOID};
use winapi::um::winsvc::{CloseServiceHandle, SC_HANDLE};

// A simple container with Drop and Deref
macro_rules! define_unsafe_holder {
    ($holder_type:ident, $held_type:ty, $drop_fn:expr, $valid:expr, $empty:expr) => {
        pub struct $holder_type(pub $held_type);

        impl $holder_type {
            pub fn valid(&self) -> bool {
                $valid(&self.0)
            }
        }

        impl Drop for $holder_type {
            fn drop(&mut self) {
                if self.valid() {
                    unsafe {
                        $drop_fn(self.0);
                        self.0 = $empty;
                    };
                }
            }
        }

        impl Deref for $holder_type {
            type Target = $held_type;

            fn deref(&self) -> &$held_type {
                &self.0
            }
        }
    };
}

define_unsafe_holder!(
    SCHolder,
    SC_HANDLE,
    CloseServiceHandle,
    |p: &SC_HANDLE| !p.is_null(),
    null_mut()
);
define_unsafe_holder!(
    LAHolder,
    PVOID,
    LocalFree,
    |p: &PVOID| !p.is_null(),
    null_mut()
);
define_unsafe_holder!(
    HHolder,
    HANDLE,
    CloseHandle,
    |p: &HANDLE| *p != INVALID_HANDLE_VALUE,
    INVALID_HANDLE_VALUE
);
define_unsafe_holder!(
    CoTaskMemHolder,
    LPVOID,
    CoTaskMemFree,
    |p: &LPVOID| !p.is_null(),
    null_mut()
);
define_unsafe_holder!(
    NamedPipeConnectionHolder,
    HANDLE,
    DisconnectNamedPipe,
    |_| true,
    null_mut()
);
define_unsafe_holder!(
    BCMHolder,
    *mut IBackgroundCopyManager,
    |p: *mut IBackgroundCopyManager| (*p).Release(),
    |p: &*mut IBackgroundCopyManager| !p.is_null(),
    null_mut()
);
define_unsafe_holder!(
    BCJobHolder,
    *mut IBackgroundCopyJob,
    |p: *mut IBackgroundCopyJob| (*p).Release(),
    |p: &*mut IBackgroundCopyJob| !p.is_null(),
    null_mut()
);
define_unsafe_holder!(
    BCErrHolder,
    *mut IBackgroundCopyError,
    |p: *mut IBackgroundCopyError| (*p).Release(),
    |p: &*mut IBackgroundCopyError| !p.is_null(),
    null_mut()
);

// macros instead of generics due to https://github.com/rust-lang/rust/issues/43408
#[macro_escape]
macro_rules! define_deserialize {
    ($name:ident, $T:ty) => {
        pub fn $name(buf: &[u8]) -> Option<$T> {
            if buf.len() != mem::size_of::<$T>() {
                return None;
            }
            Some(unsafe {
                let mut tmp: [u8; mem::size_of::<$T>()] = mem::uninitialized();
                tmp.copy_from_slice(&buf[0..mem::size_of::<$T>()]);
                mem::transmute::<[u8; mem::size_of::<$T>()], $T>(tmp)
            })
        }
    };
}

#[macro_escape]
macro_rules! define_serialize {
    ($name:ident, $T:ty) => {
        pub fn $name(v: &mut Vec<u8>, obj: &$T) {
            v.extend_from_slice(&unsafe { mem::transmute::<$T, [u8; mem::size_of::<$T>()]>(*obj) });
        }
    };
}
