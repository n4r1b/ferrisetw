use core::ffi::c_void;
use std::str::Utf8Error;
use windows::core::PSTR;
use windows::Win32::Foundation::{HLOCAL, PSID};
use windows::Win32::Security::Authorization::ConvertSidToStringSidA;

// N.B windows-rs has an incorrect implementation for local free
// https://github.com/microsoft/windows-rs/issues/2488
#[allow(non_snake_case)]
pub unsafe fn LocalFree<P0>(hmem: P0) -> ::windows::core::Result<HLOCAL>
where
    P0: ::windows::core::IntoParam<HLOCAL>,
{
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(hmem : HLOCAL ) -> HLOCAL;
    }
    let res = LocalFree(hmem.into_param().abi());
    ::windows::imp::then(res.0 == 0, || res).ok_or_else(::windows::core::Error::from_win32)
}

/// SDDL native error
#[derive(Debug)]
pub enum SddlNativeError {
    /// Represents an error parsing the SID into a String
    SidParseError(Utf8Error),
    /// Represents an standard IO Error
    IoError(std::io::Error),
}

impl From<Utf8Error> for SddlNativeError {
    fn from(err: Utf8Error) -> Self {
        SddlNativeError::SidParseError(err)
    }
}

impl std::fmt::Display for SddlNativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SidParseError(e) => write!(f, "sid parse error {}", e),
            Self::IoError(e) => write!(f, "i/o error {}", e),
        }
    }
}

pub(crate) type SddlResult<T> = Result<T, SddlNativeError>;

pub fn convert_sid_to_string(sid: *const c_void) -> SddlResult<String> {
    let mut tmp = PSTR::null();
    unsafe {
        let not_really_mut_sid = sid as *mut _; // That's OK to widely change the constness here, because it will be given as an _input_ of ConvertSidToStringSidA and will not be modified
        if !ConvertSidToStringSidA(PSID(not_really_mut_sid), &mut tmp).as_bool() {
            return Err(SddlNativeError::IoError(std::io::Error::last_os_error()));
        }

        let sid_string = std::ffi::CStr::from_ptr(tmp.0 as *mut _)
            .to_str()?
            .to_owned();

        LocalFree(HLOCAL(tmp.0 as isize)).map_err(|e| SddlNativeError::IoError(e.into()))?;

        Ok(sid_string)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_convert_string_to_sid() {
        let sid: Vec<u8> = vec![1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0];
        if let Ok(string_sid) = convert_sid_to_string(sid.as_ptr() as *const c_void) {
            assert_eq!(string_sid, "S-1-5-32-544");
        }
    }
}
