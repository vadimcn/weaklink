//! Cross-platform functions for loading dynamic libraries and resolving symbols.

#[cfg(any(unix))]
pub use unix::{find_symbol, load_library};
#[cfg(any(windows))]
pub use windows::{find_symbol, load_library};

/// An opaque handle to a loaded dynamic library.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct DylibHandle(pub usize);

/// The address of a resolved symbol.
pub type Address = usize;

/// Unix-specific dynamic-library loading functions and flags.
#[cfg(any(unix, doc))]
pub mod unix {
    use super::{Address, DylibHandle};
    use crate::Error;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub const RTLD_LAZY: c_int = 0x0001;
    pub const RTLD_NOW: c_int = 0x0002;

    #[cfg(target_os = "linux")]
    pub const RTLD_LOCAL: c_int = 0x0000;
    #[cfg(target_os = "macos")]
    pub const RTLD_LOCAL: c_int = 0x0004;

    #[cfg(target_os = "linux")]
    pub const RTLD_GLOBAL: c_int = 0x0100;
    #[cfg(target_os = "macos")]
    pub const RTLD_GLOBAL: c_int = 0x0008;

    #[link(name = "dl")]
    extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> DylibHandle;
        fn dlsym(raw_handle: *const c_void, symbol: *const c_char) -> Address;
        fn dlerror() -> *const c_char;
    }

    /// Loads the dynamic library at `path` using the supplied `dlopen` flags.
    pub fn load_library_with_flags(path: &Path, flags: c_int) -> Result<DylibHandle, Error> {
        let path_buf = CString::new(path.as_os_str().as_bytes()).unwrap();
        unsafe {
            let handle = dlopen(path_buf.as_ptr(), flags);
            if handle.0 == 0 {
                Err(format!("{:?}", CStr::from_ptr(dlerror())).into())
            } else {
                Ok(handle)
            }
        }
    }

    /// Loads the dynamic library at `path` with lazy binding and global symbol visibility.
    pub fn load_library(path: &Path) -> Result<DylibHandle, Error> {
        load_library_with_flags(path, RTLD_LAZY | RTLD_GLOBAL)
    }

    /// Resolves `name` in the dynamic library identified by `handle`.
    pub fn find_symbol(handle: DylibHandle, name: &CStr) -> Result<Address, Error> {
        unsafe {
            let ptr = dlsym(handle.0 as *const c_void, name.as_ptr());
            if ptr == 0 {
                Err(format!("{:?}", CStr::from_ptr(dlerror())).into())
            } else {
                Ok(ptr)
            }
        }
    }
}

/// Windows-specific dynamic-library loading functions and flags.
#[cfg(any(windows, doc))]
pub mod windows {
    use super::{Address, DylibHandle};
    use crate::Error;
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_ushort, c_void};
    #[cfg(windows)]
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    pub const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x00000008;
    pub const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x00000200;
    pub const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x00001000;
    pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x00000100;
    pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x00000800;
    pub const LOAD_LIBRARY_SEARCH_USER_DIRS: u32 = 0x00000400;
    pub const LOAD_LIBRARY_REQUIRE_SIGNED_TARGET: u32 = 0x00000080;
    pub const LOAD_IGNORE_CODE_AUTHZ_LEVEL: u32 = 0x00000010;
    pub const LOAD_LIBRARY_SAFE_CURRENT_DIRS: u32 = 0x00002000;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(filename: *const c_ushort, hfile: DylibHandle, flags: u32) -> DylibHandle;
        fn GetProcAddress(raw_handle: *const c_void, symbol: *const c_char) -> Address;
        fn GetLastError() -> u32;
    }

    /// Loads the dynamic library at `path` using the supplied `LoadLibraryExW` flags.
    pub fn load_library_ex(path: &Path, flags: u32) -> Result<DylibHandle, Error> {
        let mut path_buf = path
            .as_os_str()
            .encode_wide()
            .map(|u| if u == '/' as u16 { '\\' as u16 } else { u }) // Normalize slashes
            .collect::<Vec<_>>();
        path_buf.push(0);
        unsafe {
            let handle = LoadLibraryExW(path_buf.as_ptr(), DylibHandle(0), flags);
            if handle.0 == 0 {
                Err(format!("Could not load {:?} (err=0x{:08X})", path, GetLastError()).into())
            } else {
                Ok(handle)
            }
        }
    }

    /// Loads the dynamic library at `path` with an altered search path.
    pub fn load_library(path: &Path) -> Result<DylibHandle, Error> {
        load_library_ex(path, LOAD_WITH_ALTERED_SEARCH_PATH)
    }

    /// Resolves `name` in the dynamic library identified by `handle`.
    pub fn find_symbol(handle: DylibHandle, name: &CStr) -> Result<Address, Error> {
        unsafe {
            let ptr = GetProcAddress(handle.0 as *const c_void, name.as_ptr());
            if ptr == 0 {
                Err(format!("Could not find {:?} (err=0x{:08X})", name, GetLastError()).into())
            } else {
                Ok(ptr)
            }
        }
    }
}
