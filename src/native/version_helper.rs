//! Native API - Version Helper
//!
//! The `version_helper` module is an abstraction layer over the Version Helper API/Macro which allow
//! us to determine the Windows OS system version
//!
//! At the moment the only option available is to check if the actual System Version is greater than
//! Win8, is the only check we need for the crate to work as expected
use windows::Win32::System::SystemInformation::{OSVERSIONINFOEXA, VER_MAJORVERSION, VER_MINORVERSION, VER_SERVICEPACKMAJOR};
use windows::Win32::System::SystemInformation::{VerifyVersionInfoA, VerSetConditionMask};

use crate::traits::*;

/// Version Helper native error
#[derive(Debug)]
pub enum VersionHelperError {
    /// Represents an standard IO Error
    IoError(std::io::Error),
}

impl LastOsError<VersionHelperError> for VersionHelperError {}

impl From<std::io::Error> for VersionHelperError {
    fn from(err: std::io::Error) -> Self {
        VersionHelperError::IoError(err)
    }
}

pub(crate) type VersionHelperResult<T> = Result<T, VersionHelperError>;

type OsVersionInfo = OSVERSIONINFOEXA;
// Safe cast, we now the value fits in a u8 (VER_GREATER_EQUAL == 3)
const VER_GREATER_OR_EQUAL: u8 = windows::Win32::System::SystemServices::VER_GREATER_EQUAL as u8;

fn verify_system_version(major: u8, minor: u8, sp_major: u16) -> VersionHelperResult<bool> {
    let mut os_version = OsVersionInfo{
        dwOSVersionInfoSize: std::mem::size_of::<OsVersionInfo>() as u32,
        dwMajorVersion: major as u32,
        dwMinorVersion: minor as u32,
        wServicePackMajor: sp_major,
        ..Default::default()
    };

    let mut condition_mask = 0;
    unsafe {
        condition_mask = VerSetConditionMask(
            condition_mask,
            VER_MAJORVERSION,
            VER_GREATER_OR_EQUAL,
        );
        condition_mask = VerSetConditionMask(
            condition_mask,
            VER_MINORVERSION,
            VER_GREATER_OR_EQUAL,
        );
        condition_mask = VerSetConditionMask(
            condition_mask,
            VER_SERVICEPACKMAJOR,
            VER_GREATER_OR_EQUAL,
        );

        Ok(VerifyVersionInfoA(
            &mut os_version,
            VER_MAJORVERSION
                | VER_MINORVERSION
                | VER_SERVICEPACKMAJOR,
            condition_mask,
        ) != false)
    }
}

///
/// # Remarks
///
pub fn is_win8_or_greater() -> bool {
    // Lazy way, let's hardcode this...
    let res = match verify_system_version(6, 2, 0) {
        Ok(res) => res,
        Err(err) => {
            println!("{:?}", err);
            true
        }
    };

    res
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    // Let's assume this test won't be run on a version of Windows older than XP :D
    fn test_verify_system_version() {
        match verify_system_version(5, 1, 0) {
            Ok(res) => assert_eq!(true, res),
            Err(err) => panic!("VersionHelper error: {:?}", err),
        };
    }
}
