fn main() {
    windows::build!(
        Windows::Win32::Etw::*,
        Windows::Win32::SystemServices::{
            PSTR, ERROR_ALREADY_EXISTS, MAX_PATH, ERROR_INSUFFICIENT_BUFFER,
            VER_GREATER_EQUAL, ERROR_CTX_CLOSE_PENDING, ERROR_WMI_INSTANCE_NOT_FOUND
        },
        Windows::Win32::Automation::{
            SysStringLen, BSTR
        },
        Windows::Win32::WindowsProgramming::{
            FILETIME, GetSystemTimeAsFileTime, OSVERSIONINFOEXA,
            VerifyVersionInfoA, VerSetConditionMask
        }
    );
}
