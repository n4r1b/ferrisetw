use crate::traits::*;
use std::str::Utf8Error;
use core::ffi::c_void;
use windows::core::PSTR;
use windows::Win32::Foundation::PSID;
use windows::Win32::System::Memory::LocalFree;
use windows::Win32::Security::Authorization::ConvertSidToStringSidA;

/// SDDL native error
#[derive(Debug)]
pub enum SddlNativeError {
    /// Represents an error parsing the SID into a String
    SidParseError(Utf8Error),
    /// Represents an standard IO Error
    IoError(std::io::Error),
}

impl LastOsError<SddlNativeError> for SddlNativeError {}

impl From<std::io::Error> for SddlNativeError {
    fn from(err: std::io::Error) -> Self {
        SddlNativeError::IoError(err)
    }
}

impl From<Utf8Error> for SddlNativeError {
    fn from(err: Utf8Error) -> Self {
        SddlNativeError::SidParseError(err)
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

        LocalFree(tmp.0 as isize);

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
