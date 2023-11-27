//! A module to handle Extended Data from ETW traces

use windows::core::GUID;
use windows::Win32::Security::SID;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID, EVENT_EXTENDED_ITEM_TS_ID,
};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXTENDED_DATA_ITEM, EVENT_HEADER_EXT_TYPE_EVENT_KEY,
    EVENT_HEADER_EXT_TYPE_INSTANCE_INFO, EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY,
    EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID, EVENT_HEADER_EXT_TYPE_SID,
    EVENT_HEADER_EXT_TYPE_STACK_TRACE32, EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
    EVENT_HEADER_EXT_TYPE_TS_ID,
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
    /// Unexpected or invalid (or not implemented yet in Ferrisetw) extended data type
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
    // TODO: implement them, but the documentation does not clearly define what they are supposed to contain
    // /// TraceLogging event metadata information
    // SchemaTl,
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

    /// Returns this extended data as a variant of a Rust enum.
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

            _ => ExtendedDataItem::Unsupported,
        }
    }
}
