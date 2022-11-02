//! Native API - Event Tracing tdh header
//!
//! The `tdh` module is an abstraction layer for the Windows tdh library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `tdh` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the the crate level provide a safe API to interact
//! with the crate
use std::alloc::Layout;

use super::etw_types::*;
use crate::traits::*;
use crate::native::tdh_types::Property;
use windows::Win32::System::Diagnostics::Etw::{self, TRACE_EVENT_INFO, EVENT_PROPERTY_INFO};
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::core::GUID;
use widestring::U16CStr;

/// Tdh native module errors
#[derive(Debug)]
pub enum TdhNativeError {
    /// Represents an allocation error
    AllocationError,
    /// Represents an standard IO Error
    IoError(std::io::Error),
}

pub(crate) type TdhNativeResult<T> = Result<T, TdhNativeError>;

impl LastOsError<TdhNativeError> for TdhNativeError {}

impl From<std::io::Error> for TdhNativeError {
    fn from(err: std::io::Error) -> Self {
        TdhNativeError::IoError(err)
    }
}


/// Read-only wrapper over an [TRACE_EVENT_INFO]
///
/// [TRACE_EVENT_INFO]: https://docs.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info
pub struct TraceEventInfo{
    /// Pointer to a valid TRACE_EVENT_INFO buffer
    data: *const u8,
    /// Pointer to the same buffer, but mutable (used only when deallocating the data)
    mut_data_for_dealloc: *mut u8,
    /// Layout used to allocate the TRACE_EVENT_INFO buffer
    layout: Layout,
}

// Safety: TraceEventInfo contains a pointer to data that is never mutated (except on deallocation), and that itself does not contain pointers
unsafe impl Send for TraceEventInfo {}
// Safety: see above
unsafe impl Sync for TraceEventInfo {}

macro_rules! extract_utf16_string {
    ($self: ident, $member_name: ident) => {
        let provider_name_offset = $self.as_raw().$member_name;
        let provider_name_ptr = unsafe {
            // Safety: we trust Microsoft for providing correctly aligned data
            $self.data.offset(provider_name_offset as isize)
        };
        if provider_name_offset == 0 || provider_name_ptr.is_null() {
            return String::new();
        }
        let provider_name = unsafe {
            // Safety:
            //  * we trust Microsoft for providing correctly aligned data
            //  * we will copy into a String before the buffer gets invalid
            U16CStr::from_ptr_str(provider_name_ptr as *const u16)
        };
        return provider_name.to_string_lossy();
    }
}

impl TraceEventInfo {
    /// Create a instance of `Self` suitable for the given event
    pub fn build_from_event(event: &EventRecord) -> TdhNativeResult<Self> {
        let mut buffer_size = 0;
        let status = unsafe {
            // Safety:
            //  * the `EVENT_RECORD` was passed by Microsoft and has not been modified: it is thus valid and correctly aligned
            Etw::TdhGetEventInformation(
                event.as_raw_ptr(),
                &[],
                std::ptr::null_mut(),
                &mut buffer_size,
            )
        };
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(status as i32)));
        }

        if buffer_size == 0 {
            return Err(TdhNativeError::AllocationError);
        }

        let layout = Layout::from_size_align(buffer_size as usize, std::mem::align_of::<Etw::TRACE_EVENT_INFO>())
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
                &[],
                data.cast::<TRACE_EVENT_INFO>(),
                &mut buffer_size,
            )
        };

        if status != 0 {
            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(status as i32)));
        }

        Ok(Self { data, mut_data_for_dealloc: data, layout })

    }

    fn as_raw(&self) -> &TRACE_EVENT_INFO {
        let p = self.data.cast::<TRACE_EVENT_INFO>();
        unsafe {
            // Safety: the API enforces self.data to point to a valid, allocated TRACE_EVENT_INFO
            p.as_ref().unwrap()
        }
    }

    pub(crate) fn provider_guid(&self) -> GUID {
        self.as_raw().ProviderGuid
    }

    pub(crate) fn event_id(&self) -> u16 {
        self.as_raw().EventDescriptor.Id
    }

    pub(crate) fn event_version(&self) -> u8 {
        self.as_raw().EventDescriptor.Version
    }

    pub(crate) fn decoding_source(&self) -> DecodingSource {
        let ds = self.as_raw().DecodingSource;
        DecodingSource::from(ds)
    }

    pub(crate) fn provider_name(&self) -> String {
        extract_utf16_string!(self, ProviderNameOffset);
    }

    pub(crate) fn task_name(&self) -> String {
        extract_utf16_string!(self, TaskNameOffset);
    }

    pub(crate) fn opcode_name(&self) -> String {
        extract_utf16_string!(self, OpcodeNameOffset);
    }

    pub(crate) fn properties<'info>(&'info self) -> PropertyIterator<'info> {
        PropertyIterator::new(self)
    }
}

impl Drop for TraceEventInfo {
    fn drop(&mut self) {
        unsafe {
            // Safety:
            // * ptr is a block of memory currently allocated via alloc::alloc
            // * layout is th one that was used to allocate that block of memory
            std::alloc::dealloc(self.mut_data_for_dealloc, self.layout);
        }
    }
}

pub(crate) struct PropertyIterator<'info> {
    next_index: u32,
    count: u32,
    te_info: &'info TraceEventInfo,
}

impl<'info> PropertyIterator<'info> {
    fn new(te_info: &'info TraceEventInfo) -> Self {
        let count = te_info.as_raw().PropertyCount;
        Self { next_index: 0, count, te_info }
    }
}

impl<'info> Iterator for PropertyIterator<'info> {
    type Item = Property;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index == self.count {
            return None;
        }

        let properties_array = &self.te_info.as_raw().EventPropertyInfoArray;
        let properties_array = properties_array as *const EVENT_PROPERTY_INFO;
        let cur_property_ptr = unsafe {
            // Safety:
            //  * index being in the right bounds, this guarantees the resulting pointer lies in the same allocated object
            properties_array.offset(self.next_index as isize)   // we assume there will not be more than 2 billion properties for an event
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
        let property_name_offset = curr_prop.NameOffset;
        let property_name_ptr = unsafe {
            // Safety: offset comes from a Microsoft API
            te_info_data.offset(property_name_offset as isize)
        };
        if property_name_ptr.is_null() {
            // This is really a safety net, there is no reason the offset nullifies the base pointer
            // This is not supposed to happen, so a simple `None` (instead of a proper `Err`) will do
            return None;
        }

        let property_name = unsafe {
            // Safety:
            //  * we trust Microsoft for providing correctly aligned data
            //  * we will copy into a String before the buffer gets invalid
            U16CStr::from_ptr_str(property_name_ptr as *const u16)
        };
        let property_name = property_name.to_string_lossy();

        self.next_index += 1;
        Some(Property::new(property_name, curr_prop))
    }
}

pub(crate) fn property_size(event: &EventRecord, name: &str) -> TdhNativeResult<u32> {
    let mut property_size = 0;

    let name = name.into_utf16();
    let desc = Etw::PROPERTY_DATA_DESCRIPTOR{
        ArrayIndex: u32::MAX,
        PropertyName: name.as_ptr() as u64,
        ..Default::default()
    };

    unsafe {
        let status = Etw::TdhGetPropertySize(
            event.as_raw_ptr(),
            &[],
            &[desc],
            &mut property_size,
        );
        if status != 0 {
            return Err(TdhNativeError::IoError(std::io::Error::from_raw_os_error(
                status as i32,
            )));
        }
    }

    Ok(property_size)
}
