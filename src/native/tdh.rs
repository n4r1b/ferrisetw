//! Native API - Event Tracing tdh header
//!
//! The `tdh` module is an abstraction layer for the Windows tdh library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `tdh` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the the crate level provide a safe API to interact
//! with the crate
use super::etw_types::*;
use crate::traits::*;
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::System::Diagnostics::Etw;

/// Tdh native module errors
#[derive(Debug)]
pub enum TdhNativeError {
    /// Represents an standard IO Error
    IoError(std::io::Error),
}

impl LastOsError<TdhNativeError> for TdhNativeError {}

impl From<std::io::Error> for TdhNativeError {
    fn from(err: std::io::Error) -> Self {
        TdhNativeError::IoError(err)
    }
}

pub(crate) type TdhNativeResult<T> = Result<T, TdhNativeError>;

pub(crate) fn schema_from_tdh(event: EventRecord) -> TdhNativeResult<TraceEventInfoRaw> {
    let mut buffer_size = 0;
    unsafe {
        if Etw::TdhGetEventInformation(&event, &[], std::ptr::null_mut(), &mut buffer_size)
            != ERROR_INSUFFICIENT_BUFFER.0
        {
            return Err(TdhNativeError::IoError(std::io::Error::last_os_error()));
        }

        let mut buffer = TraceEventInfoRaw::alloc(buffer_size);
        if Etw::TdhGetEventInformation(
            &event,
            &[],
            buffer.info_as_ptr() as *mut _,
            &mut buffer_size,
        ) != 0
        {
            return Err(TdhNativeError::IoError(std::io::Error::last_os_error()));
        }

        Ok(buffer)
    }
}

pub(crate) fn property_size(event: EventRecord, name: &str) -> TdhNativeResult<u32> {
    let mut property_size = 0;

    let name = name.into_utf16();
    let desc = Etw::PROPERTY_DATA_DESCRIPTOR {
        ArrayIndex: u32::MAX,
        PropertyName: name.as_ptr() as u64,
        ..Default::default()
    };

    unsafe {
        let status = Etw::TdhGetPropertySize(&event, &[], &[desc], &mut property_size);
        if status != 0 {
            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(
                status as i32,
            )));
        }
    }

    Ok(property_size)
}
