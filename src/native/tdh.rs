//! Native API - Event Tracing tdh header
//!
//! The `tdh` module is an abstraction layer for the Windows tdh library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `tdh` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the the crate level provide a safe API to interact
//! with the crate
use std::alloc::Layout;

use super::etw_types::*;
use crate::native::etw_types::event_record::EventRecord;
use crate::native::tdh_types::Property;
use crate::traits::*;
use widestring::U16CStr;
use windows::core::GUID;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use windows::Win32::System::Diagnostics::Etw::{
    self, TdhEnumerateProviders, EVENT_PROPERTY_INFO, PROVIDER_ENUMERATION_INFO, TRACE_EVENT_INFO,
    TRACE_PROVIDER_INFO,
};

/// Tdh native module errors
#[derive(Debug)]
pub enum TdhNativeError {
    /// Represents an allocation error
    AllocationError,
    /// Represents an standard IO Error
    IoError(std::io::Error),
    /// Represents a not found Error
    NotFound,
}

pub type TdhNativeResult<T> = Result<T, TdhNativeError>;

impl std::fmt::Display for TdhNativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllocationError => write!(f, "allocation error"),
            Self::IoError(e) => write!(f, "i/o error {}", e),
            Self::NotFound => write!(f, "not found error"),
        }
    }
}

/// Read-only wrapper over an [TRACE_EVENT_INFO]
///
/// [TRACE_EVENT_INFO]: https://docs.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info
pub struct TraceEventInfo {
    /// Pointer to an owned TRACE_EVENT_INFO buffer (only mutable for deallocating the data)
    data: *mut u8,
    /// Layout used to allocate the TRACE_EVENT_INFO buffer
    layout: Layout,
}

// Safety: TraceEventInfo contains a pointer to data that is never mutated (except on deallocation), and that itself does not contain pointers
unsafe impl Send for TraceEventInfo {}
// Safety: see above
unsafe impl Sync for TraceEventInfo {}

/// Extract a null-terminated wide-string at a given offset within a buffer.
///
/// The wide-string is converted with loss to a String. If buffer
/// is null or offset is zero, None is returned.
///
/// Safety:
///  * the buffer must entirely contain a null-terminated wide string
///    located at the given offset
unsafe fn extract_utf16_string(buffer: *const u8, offset: usize) -> Option<String> {
    if offset == 0 || buffer.is_null() {
        return None;
    }
    let ptr_str = unsafe {
        // Safety: we trust that offset points to inside the buffer
        buffer.add(offset)
    };
    // This is really a safety net, there is no reason the offset nullifies the base pointer
    if ptr_str.is_null() {
        return None;
    }
    let wide_str = unsafe {
        // Safety:
        //  * we trust the string is null-terminated
        //  * we trust the string entirely fits within the given buffer
        //  * we will not mutate the string
        U16CStr::from_ptr_str(ptr_str as *const u16)
    };
    return Some(wide_str.to_string_lossy());
}

impl TraceEventInfo {
    /// Create a instance of `Self` suitable for the given event
    pub fn build_from_event(event: &EventRecord) -> TdhNativeResult<Self> {
        let mut buffer_size = 0;
        let status = unsafe {
            // Safety:
            //  * the `EVENT_RECORD` was passed by Microsoft and has not been modified: it is thus valid and correctly aligned
            Etw::TdhGetEventInformation(event.as_raw_ptr(), None, None, &mut buffer_size)
        };
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(
                status as i32,
            )));
        }

        if buffer_size == 0 {
            return Err(TdhNativeError::AllocationError);
        }

        let layout = Layout::from_size_align(
            buffer_size as usize,
            std::mem::align_of::<Etw::TRACE_EVENT_INFO>(),
        )
        .map_err(|_| TdhNativeError::AllocationError)?;
        let data = unsafe {
            // Safety: size is not zero
            std::alloc::alloc(layout)
        };
        if data.is_null() {
            return Err(TdhNativeError::AllocationError);
        }

        let status = unsafe {
            // Safety:
            //  * the `EVENT_RECORD` was passed by Microsoft and has not been modified: it is thus valid and correctly aligned
            //  * `data` has been successfully allocated, with the required size and the correct alignment
            Etw::TdhGetEventInformation(
                event.as_raw_ptr(),
                None,
                Some(data.cast::<TRACE_EVENT_INFO>()),
                &mut buffer_size,
            )
        };

        if status != ERROR_SUCCESS.0 {
            unsafe {
                // Safety:
                // * ptr is a block of memory currently allocated via alloc::alloc
                // * layout is the one that was used to allocate that block of memory
                std::alloc::dealloc(data, layout);
            }

            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(
                status as i32,
            )));
        }

        Ok(Self { data, layout })
    }

    fn as_raw(&self) -> &TRACE_EVENT_INFO {
        let p = self.data.cast::<TRACE_EVENT_INFO>();
        unsafe {
            // Safety: the API enforces self.data to point to a valid, allocated TRACE_EVENT_INFO
            p.as_ref().unwrap()
        }
    }

    pub fn provider_guid(&self) -> GUID {
        self.as_raw().ProviderGuid
    }

    pub fn event_id(&self) -> u16 {
        self.as_raw().EventDescriptor.Id
    }

    pub fn event_version(&self) -> u8 {
        self.as_raw().EventDescriptor.Version
    }

    pub fn decoding_source(&self) -> DecodingSource {
        let ds = self.as_raw().DecodingSource;
        DecodingSource::from(ds)
    }

    pub fn provider_name(&self) -> String {
        unsafe {
            // Safety:
            //  * if self.data is null, we'll get None
            //  * otherwise we trust Microsoft for providing consistent and correctly aligned data
            extract_utf16_string(self.data, self.as_raw().ProviderNameOffset as usize)
                .unwrap_or_default()
        }
    }

    pub fn task_name(&self) -> String {
        unsafe {
            // Safety:
            //  * if self.data is null, we'll get None
            //  * otherwise we trust Microsoft for providing consistent and correctly aligned data
            extract_utf16_string(self.data, self.as_raw().TaskNameOffset as usize)
                .unwrap_or_default()
        }
    }

    pub fn opcode_name(&self) -> String {
        unsafe {
            // Safety:
            //  * if self.data is null, we'll get None
            //  * otherwise we trust Microsoft for providing consistent and correctly aligned data
            extract_utf16_string(self.data, self.as_raw().OpcodeNameOffset as usize)
                .unwrap_or_default()
        }
    }

    pub fn properties(&self) -> PropertyIterator {
        PropertyIterator::new(self)
    }
}

impl Drop for TraceEventInfo {
    fn drop(&mut self) {
        unsafe {
            // Safety:
            // * ptr is a block of memory currently allocated via alloc::alloc
            // * layout is the one that was used to allocate that block of memory
            std::alloc::dealloc(self.data, self.layout);
        }
    }
}

pub struct PropertyIterator<'info> {
    next_index: u32,
    count: u32,
    te_info: &'info TraceEventInfo,
}

impl<'info> PropertyIterator<'info> {
    fn new(te_info: &'info TraceEventInfo) -> Self {
        let count = te_info.as_raw().PropertyCount;
        Self {
            next_index: 0,
            count,
            te_info,
        }
    }
}

impl<'info> Iterator for PropertyIterator<'info> {
    type Item = Result<Property, crate::native::tdh_types::PropertyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index == self.count {
            return None;
        }

        let properties_array = &self.te_info.as_raw().EventPropertyInfoArray;
        let properties_array = properties_array as *const EVENT_PROPERTY_INFO;
        let cur_property_ptr = unsafe {
            // Safety:
            //  * index being in the right bounds, this guarantees the resulting pointer lies in the same allocated object
            properties_array.offset(self.next_index as isize) // we assume there will not be more than 2 billion properties for an event
        };
        let curr_prop = unsafe {
            // Safety:
            //  * this pointer has been allocated by a Microsoft API
            match cur_property_ptr.as_ref() {
                None => {
                    // This should not happen, as there is no reason the Microsoft API has put a null pointer at an index below self.count
                    // Ideally, I probably should return an `Err` here. But I prefer keeping a simple return type, and stop the iteration here in case this (normally impossible error) happens
                    return None;
                }
                Some(r) => r,
            }
        };

        let te_info_data = self.te_info.as_raw() as *const TRACE_EVENT_INFO as *const u8;
        // Safety:
        //  * if te_info_data is null, we'll get None
        //  * otherwise we trust Microsoft for providing consistent and correctly aligned data
        let property_name =
            unsafe { extract_utf16_string(te_info_data, curr_prop.NameOffset as usize)? };

        self.next_index += 1;
        Some(Property::new(property_name, curr_prop))
    }
}

pub fn property_size(event: &EventRecord, name: &str) -> TdhNativeResult<u32> {
    let mut property_size = 0;

    let name = name.into_utf16();
    let desc = Etw::PROPERTY_DATA_DESCRIPTOR {
        ArrayIndex: u32::MAX,
        PropertyName: name.as_ptr() as u64,
        ..Default::default()
    };

    unsafe {
        let status = Etw::TdhGetPropertySize(event.as_raw_ptr(), None, &[desc], &mut property_size);
        if status != 0 {
            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(
                status as i32,
            )));
        }
    }

    Ok(property_size)
}

/// Read-only wrapper over an [PROVIDER_ENUMERATION_INFO]
///
/// [PROVIDER_ENUMERATION_INFO]: https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-provider_enumeration_info
struct ProviderEnumerationInfo {
    /// Pointer to an owned PROVIDER_ENUMERATION_INFO buffer (only mutable for deallocating the data)
    data: *mut u8,
    /// Layout used to allocate the PROVIDER_ENUMERATION_INFO buffer
    layout: Layout,
}

impl ProviderEnumerationInfo {
    /// Create a instance of `Self` suitable for the given event
    pub fn build_full_enumeration() -> TdhNativeResult<Self> {
        let mut buffer_size = 0;
        let status = unsafe {
            // Safety: buffer_size is valid, and zero on input, so no data
            // will be written in the buffer, that can therefore be null
            TdhEnumerateProviders(None, &mut buffer_size)
        };
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(
                status as i32,
            )));
        }

        if buffer_size == 0 {
            return Err(TdhNativeError::AllocationError);
        }

        let layout = Layout::from_size_align(
            buffer_size as usize,
            std::mem::align_of::<PROVIDER_ENUMERATION_INFO>(),
        )
        .map_err(|_| TdhNativeError::AllocationError)?;
        let data = unsafe {
            // Safety: size is not zero
            std::alloc::alloc(layout)
        };
        if data.is_null() {
            return Err(TdhNativeError::AllocationError);
        }

        let status = unsafe {
            // Safety:
            //  * `data` has been successfully allocated, with the required size and the correct alignment
            TdhEnumerateProviders(
                Some(data.cast::<PROVIDER_ENUMERATION_INFO>()),
                &mut buffer_size,
            )
        };

        if status != ERROR_SUCCESS.0 {
            unsafe {
                // Safety:
                // * ptr is a block of memory currently allocated via alloc::alloc
                // * layout is the one that was used to allocate that block of memory
                std::alloc::dealloc(data, layout);
            }

            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(
                status as i32,
            )));
        }

        Ok(Self { data, layout })
    }

    fn as_raw(&self) -> &PROVIDER_ENUMERATION_INFO {
        let p = self.data.cast::<PROVIDER_ENUMERATION_INFO>();
        unsafe {
            // Safety: the API enforces self.data to point to a valid, allocated PROVIDER_ENUMERATION_INFO
            p.as_ref().unwrap()
        }
    }

    pub fn raw_providers(&self) -> &[TRACE_PROVIDER_INFO] {
        let raw = self.as_raw();
        if raw.NumberOfProviders == 0 {
            return &[];
        }

        // Safety:
        //  * we trust Microsoft for providing consistent data
        //  * the underlying buffer will not be mutated
        unsafe {
            core::slice::from_raw_parts(
                raw.TraceProviderInfoArray.as_ptr(),
                raw.NumberOfProviders as usize,
            )
        }
    }

    pub fn provider_name(&self, provider: &TRACE_PROVIDER_INFO) -> String {
        unsafe {
            // Safety:
            //  * if self.data is null, we'll get None
            //  * otherwise we trust Microsoft for providing consistent and correctly aligned data
            extract_utf16_string(self.data, provider.ProviderNameOffset as usize)
                .unwrap_or_default()
        }
    }
}

impl Drop for ProviderEnumerationInfo {
    fn drop(&mut self) {
        unsafe {
            // Safety:
            // * ptr is a block of memory currently allocated via alloc::alloc
            // * layout is the one that was used to allocate that block of memory
            std::alloc::dealloc(self.data, self.layout);
        }
    }
}

// https://github.com/microsoft/krabsetw/blob/f18605233f75e6ab207244a4b58f7d834835a25a/krabs/krabs/provider.hpp#L575
pub(crate) fn get_provider_guid(name: &str) -> TdhNativeResult<GUID> {
    let providers_info = ProviderEnumerationInfo::build_full_enumeration()?;

    let raw_providers = providers_info.raw_providers();

    for raw_provider in raw_providers {
        let provider_name = providers_info.provider_name(raw_provider);
        if provider_name == name {
            return Ok(raw_provider.ProviderGuid);
        }
    }

    Err(TdhNativeError::NotFound)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    pub fn test_get_provider() {
        let guid =
            get_provider_guid("Microsoft-Windows-Kernel-Process").expect("Error Getting GUID");

        assert_eq!(
            GUID::from_u128(0x22FB2CD6_0E7B_422B_A0C7_2FAD1FD0E716),
            guid
        );
    }

    #[test]
    pub fn test_provider_not_found() {
        let err = get_provider_guid("Not-A-Real-Provider");

        assert!(matches!(err, Err(TdhNativeError::NotFound)));
    }
}
