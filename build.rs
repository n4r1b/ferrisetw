fn main() {
    windows_macros::build!(
        Windows::Win32::Etw::*,
        Windows::Win32::Debug::WIN32_ERROR,
        Windows::Win32::SystemServices::{
            PSTR, MAX_PATH, VER_GREATER_EQUAL, LocalFree
        },
        Windows::Win32::Automation::{
            SysStringLen, BSTR
        },
        Windows::Win32::WindowsProgramming::{
            FILETIME, GetSystemTimeAsFileTime, OSVERSIONINFOEXA,
            VerifyVersionInfoA, VerSetConditionMask
        },
        Windows::Win32::Security::{ConvertSidToStringSidA, PSID},
    );
}
