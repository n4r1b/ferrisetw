//! Implements wrappers for various Windows time structures.
use windows::Win32::{
    Foundation::{FILETIME, SYSTEMTIME},
    System::Time::SystemTimeToFileTime,
};

/// Wrapper for [FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct FileTime(pub(crate) FILETIME);

const SECONDS_BETWEEN_1601_AND_1970: i64 = 11_644_473_600;
const NS_IN_SECOND: i64 = 1_000_000_000;
const MS_IN_SECOND: i64 = 1_000;

impl FileTime {
    /// Converts to a unix timestamp with millisecond granularity.
    pub fn as_unix_timestamp(&self) -> i64 {
        self.as_quad() / 10_000 - (SECONDS_BETWEEN_1601_AND_1970 * MS_IN_SECOND)
    }

    /// Converts to a unix timestamp with nanosecond granularity.
    pub fn as_unix_timestamp_nanos(&self) -> i128 {
        self.as_quad() as i128 * 100
            - (SECONDS_BETWEEN_1601_AND_1970 as i128 * NS_IN_SECOND as i128)
    }

    /// Converts to OffsetDateTime
    #[cfg(feature = "time_rs")]
    pub fn as_date_time(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp_nanos(self.as_unix_timestamp_nanos()).unwrap()
    }

    fn as_quad(&self) -> i64 {
        let mut quad = self.0.dwHighDateTime as i64;
        quad <<= 32;
        quad |= self.0.dwHighDateTime as i64;
        quad
    }

    #[cfg(any(feature = "time_rs", feature = "serde"))]
    pub(crate) fn from_quad(quad: i64) -> Self {
        let mut file_time: FileTime = Default::default();
        file_time.0.dwHighDateTime = (quad >> 32) as u32;
        file_time.0.dwLowDateTime = (quad & 0xffffffff) as u32;
        file_time
    }

    pub(crate) fn from_slice(slice: &[u8; std::mem::size_of::<FileTime>()]) -> Self {
        let ptr = slice.as_ptr() as *const FileTime;
        let mut file_time: FileTime = Default::default();
        unsafe {
            file_time.0.dwHighDateTime = (*ptr).0.dwHighDateTime;
            file_time.0.dwLowDateTime = (*ptr).0.dwLowDateTime;
        }
        file_time
    }
}

#[cfg(feature = "time_rs")]
impl From<FileTime> for time::OffsetDateTime {
    fn from(file_time: FileTime) -> Self {
        file_time.as_date_time()
    }
}

#[cfg(feature = "serde")]
impl serde::ser::Serialize for FileTime {
    #[cfg(feature = "time_rs")]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_date_time().serialize(serializer)
    }

    #[cfg(not(feature = "time_rs"))]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_unix_timestamp().serialize(serializer)
    }
}

/// Wrapper for [SYSTEMTIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime)
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct SystemTime(pub(crate) SYSTEMTIME);

impl SystemTime {
    /// Converts to a unix timestamp with millisecond granularity.
    pub fn as_unix_timestamp(&self) -> i64 {
        let file_time: FileTime = Default::default();
        unsafe {
            _ = SystemTimeToFileTime(&self.0 as *const _, &file_time.0 as *const _ as *mut _);
        }
        file_time.as_unix_timestamp()
    }

    /// Converts to a unix timestamp with nanosecond granularity.
    pub fn as_unix_timestamp_nanos(&self) -> i128 {
        let file_time: FileTime = Default::default();
        unsafe {
            _ = SystemTimeToFileTime(&self.0 as *const _, &file_time.0 as *const _ as *mut _);
        }
        file_time.as_unix_timestamp_nanos()
    }

    /// Converts to OffsetDateTime
    #[cfg(feature = "time_rs")]
    pub fn as_date_time(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp_nanos(self.as_unix_timestamp_nanos()).unwrap()
    }

    pub(crate) fn from_slice(slice: &[u8; std::mem::size_of::<SystemTime>()]) -> Self {
        let ptr = slice.as_ptr() as *const SystemTime;
        let mut system_time: SystemTime = Default::default();
        unsafe {
            system_time.0.wYear = (*ptr).0.wYear;
            system_time.0.wMonth = (*ptr).0.wMonth;
            system_time.0.wDayOfWeek = (*ptr).0.wDayOfWeek;
            system_time.0.wDay = (*ptr).0.wDay;
            system_time.0.wHour = (*ptr).0.wHour;
            system_time.0.wMinute = (*ptr).0.wMinute;
            system_time.0.wMilliseconds = (*ptr).0.wMilliseconds;
        }
        system_time
    }
}

#[cfg(feature = "time_rs")]
impl From<SystemTime> for time::OffsetDateTime {
    fn from(file_time: SystemTime) -> Self {
        file_time.as_date_time()
    }
}

#[cfg(feature = "serde")]
impl serde::ser::Serialize for SystemTime {
    #[cfg(feature = "time_rs")]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_date_time().serialize(serializer)
    }

    #[cfg(not(feature = "time_rs"))]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_unix_timestamp().serialize(serializer)
    }
}
