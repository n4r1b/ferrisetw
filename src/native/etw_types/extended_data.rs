//! A module to handle Extended Data from ETW traces

use std::{ffi::CStr, mem};
use windows::core::GUID;
use windows::Win32::Security::SID;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID, EVENT_EXTENDED_ITEM_TS_ID,
};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXTENDED_DATA_ITEM, EVENT_HEADER_EXT_TYPE_EVENT_KEY,
    EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL, EVENT_HEADER_EXT_TYPE_INSTANCE_INFO,
    EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID,
    EVENT_HEADER_EXT_TYPE_SID, EVENT_HEADER_EXT_TYPE_STACK_TRACE32,
    EVENT_HEADER_EXT_TYPE_STACK_TRACE64, EVENT_HEADER_EXT_TYPE_TS_ID,
};

// These types are returned by our public API. Let's use their re-exported versions
use crate::native::{
    EVENT_EXTENDED_ITEM_INSTANCE, EVENT_EXTENDED_ITEM_STACK_TRACE32,
    EVENT_EXTENDED_ITEM_STACK_TRACE64,
};

/// A wrapper over [`windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXTENDED_DATA_ITEM`]
#[repr(transparent)]
pub struct EventHeaderExtendedDataItem(EVENT_HEADER_EXTENDED_DATA_ITEM);

/// A safe representation of an ExtendedDataItem
///
/// See <https://docs.microsoft.com/en-us/windows/win32/api/relogger/ns-relogger-event_header_extended_data_item>
#[derive(Debug)]
pub enum ExtendedDataItem {
    /// Unexpected, invalid or not implemented yet
    Unsupported,
    /// Related activity identifier
    RelatedActivityId(GUID),
    /// Security identifier (SID) of the user that logged the event
    Sid(SID),
    /// Terminal session identifier
    TsId(u32),
    InstanceInfo(EVENT_EXTENDED_ITEM_INSTANCE),
    /// Call stack (if the event is captured on a 32-bit computer)
    StackTrace32(EVENT_EXTENDED_ITEM_STACK_TRACE32),
    /// Call stack (if the event is captured on a 64-bit computer)
    StackTrace64(EVENT_EXTENDED_ITEM_STACK_TRACE64),
    /// TraceLogging event metadata information
    TraceLogging(String),
    // /// Provider traits data
    // /// (for example traits set through EventSetInformation(EventProviderSetTraits) or specified through EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA)
    // ProvTraits,
    /// Unique event identifier
    EventKey(u64),
    /// Unique process identifier (unique across the boot session)
    ProcessStartKey(u64),
}

impl EventHeaderExtendedDataItem {
    /// Returns the `ExtType` of this extended data.
    ///
    /// See <https://docs.microsoft.com/en-us/windows/win32/api/relogger/ns-relogger-event_header_extended_data_item> for possible values
    pub fn data_type(&self) -> u16 {
        self.0.ExtType
    }

    pub fn is_tlg(&self) -> bool {
        self.0.ExtType as u32 == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
    }

    /// Returns this extended data as a variant of a Rust enum.
    // TODO: revisit this function
    pub fn to_extended_data_item(&self) -> ExtendedDataItem {
        let data_ptr = self.0.DataPtr as *const std::ffi::c_void;
        if data_ptr.is_null() {
            return ExtendedDataItem::Unsupported;
        }

        match self.0.ExtType as u32 {
            EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID;
                ExtendedDataItem::RelatedActivityId(unsafe { *data_ptr }.RelatedActivityId)
            }

            EVENT_HEADER_EXT_TYPE_SID => {
                let data_ptr = data_ptr as *const SID;
                ExtendedDataItem::Sid(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_TS_ID => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_TS_ID;
                ExtendedDataItem::TsId(unsafe { *data_ptr }.SessionId)
            }

            EVENT_HEADER_EXT_TYPE_INSTANCE_INFO => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_INSTANCE;
                ExtendedDataItem::InstanceInfo(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_STACK_TRACE32 => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_STACK_TRACE32;
                ExtendedDataItem::StackTrace32(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_STACK_TRACE64 => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_STACK_TRACE64;
                ExtendedDataItem::StackTrace64(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY => {
                let data_ptr = data_ptr as *const u64;
                ExtendedDataItem::ProcessStartKey(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_EVENT_KEY => {
                let data_ptr = data_ptr as *const u64;
                ExtendedDataItem::EventKey(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL => {
                ExtendedDataItem::TraceLogging(unsafe { self.get_event_name().unwrap_or_default() })
            }

            _ => ExtendedDataItem::Unsupported,
        }
    }

    ///
    /// This function will parse the `_tlgEventMetadata_t` to retrieve the EventName
    ///
    /// For more info see `_tlgEventMetadata_t` in `TraceLoggingProvider.h` (Windows SDK)
    ///
    /// ```cpp
    /// struct _tlgEventMetadata_t
    /// {
    ///     UINT8 Type; // = _TlgBlobEvent4
    ///     UCHAR Channel;
    ///     UCHAR Level;
    ///     UCHAR Opcode;
    ///     ULONGLONG Keyword;
    ///     UINT16 RemainingSize; // = sizeof(RemainingSize + Tags + EventName + Fields)
    ///     UINT8 Tags[]; // 1 or more bytes. Read until you hit a byte with high bit unset.
    ///     char EventName[sizeof("eventName")]; // UTF-8 nul-terminated event name
    ///     for each field {
    ///         char FieldName[sizeof("fieldName")];
    ///         UINT8 InType;
    ///         UINT8 OutType;
    ///         UINT8 Tags[];
    ///         UINT16 ValueCount;
    ///         UINT16 TypeInfoSize;
    ///         char TypeInfo[TypeInfoSize];
    ///     }
    /// }
    /// ```
    ///
    ///  We are only interested on `EventName` so we will only consider the first three members.
    ///
    /// # Safety
    ///
    /// As per the MS header 'This structure may change in future revisions of this header.'  
    /// **Keep an eye on it!**
    ///
    // TODO: Make this function more robust
    unsafe fn get_event_name(&self) -> Option<String> {
        const TAGS_SIZE: usize = 1;
        debug_assert!(self.is_tlg());

        let mut data_ptr = self.0.DataPtr as *const u8;
        if data_ptr.is_null() {
            return None;
        }

        let size = data_ptr.read_unaligned() as u16;
        data_ptr = data_ptr.add(mem::size_of::<u16>());

        let mut n = 0;
        while n < size {
            // Read until you hit a byte with high bit unset.
            let tag = data_ptr.read_unaligned();
            data_ptr = data_ptr.add(TAGS_SIZE);

            if tag & 0b1000_0000 == 0 {
                break;
            }

            n += 1;
        }

        // If debug let's assert here since this is a case we want to investigate
        debug_assert!(n != size);
        if n == size {
            return None;
        }

        Some(String::from(
            CStr::from_ptr(data_ptr as *const _).to_string_lossy(),
        ))
    }
}
