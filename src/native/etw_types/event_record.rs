//! Safe wrappers over the EVENT_RECORD type

use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

use crate::native::etw_types::extended_data::EventHeaderExtendedDataItem;
use crate::native::ExtendedDataItem;

use super::EVENT_HEADER_FLAG_32_BIT_HEADER;

/// A read-only wrapper over an [EVENT_RECORD](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)
#[repr(transparent)]
pub struct EventRecord(pub(crate) EVENT_RECORD);

impl EventRecord {
    /// Create a `&self` from a Windows pointer.
    ///
    /// # Safety
    ///
    /// 1. Once an instance of `Self` is created, one should make sure the pointed data does not get modified (or dealloc'ed).
    /// 2. The returned lifetime is arbitray. To restrict the use of the returned reference (and to ensure the first safety guarantee), simply pass it to a sub-function whose signature has no explicit lifetime.
    ///    Thus, the sub-function will not be able to leak this reference.
    pub(crate) unsafe fn from_ptr<'a>(p: *const EVENT_RECORD) -> Option<&'a Self> {
        let s = p as *const Self;
        s.as_ref()
    }

    /// Get the wrapped `EVENT_RECORD` (usually to feed Windows API functions)
    ///
    /// # Safety
    ///
    /// Obviously, the returned pointer is only valid as long `self` is valid and not modified.
    pub(crate) fn as_raw_ptr(&self) -> *const EVENT_RECORD {
        &self.0 as *const EVENT_RECORD
    }

    /// The `UserContext` field from the wrapped `EVENT_RECORD`
    ///
    /// In this crate, it is always populated to point to a valid [`CallbackData`](crate::trace::CallbackData)
    pub(crate) fn user_context(&self) -> *const std::ffi::c_void {
        self.0.UserContext as *const _
    }

    /// The `ProviderId` field from the wrapped `EVENT_RECORD`
    pub fn provider_id(&self) -> GUID {
        self.0.EventHeader.ProviderId
    }

    /// The `Id` field from the wrapped `EVENT_RECORD`
    pub fn event_id(&self) -> u16 {
        self.0.EventHeader.EventDescriptor.Id
    }

    /// The `Opcode` field from the wrapped `EVENT_RECORD`
    pub fn opcode(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Opcode
    }

    /// The `Version` field from the wrapped `EVENT_RECORD`
    pub fn version(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Version
    }

    /// The `Level` field from the wrapped `EVENT_RECORD`
    pub fn level(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Level
    }

    /// The `Keyword` field from the wrapped `EVENT_RECORD`
    pub fn keyword(&self) -> u64 {
        self.0.EventHeader.EventDescriptor.Keyword
    }

    /// The `Flags` field from the wrapped `EVENT_RECORD`
    pub fn event_flags(&self) -> u16 {
        self.0.EventHeader.Flags
    }

    /// The `ProcessId` field from the wrapped `EVENT_RECORD`
    pub fn process_id(&self) -> u32 {
        self.0.EventHeader.ProcessId
    }

    /// The `ThreadId` field from the wrapped `EVENT_RECORD`
    pub fn thread_id(&self) -> u32 {
        self.0.EventHeader.ThreadId
    }

    /// The `ActivityId` field from the wrapped `EVENT_RECORD`
    pub fn activity_id(&self) -> GUID {
        self.0.EventHeader.ActivityId
    }

    /// The `TimeStamp` field from the wrapped `EVENT_RECORD`
    ///
    /// As per [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header):
    /// > Contains the time that the event occurred.<br/>
    /// > The resolution is system time unless the `ProcessTraceMode member` of `EVENT_TRACE_LOGFILE`
    /// > contains the `PROCESS_TRACE_MODE_RAW_TIMESTAMP` flag, in which case the resolution depends
    /// > on the value of the `Wnode.ClientContext` member of `EVENT_TRACE_PROPERTIES` at the time
    /// > the controller created the session.
    ///
    /// Note: the `time_rs` Cargo feature enables to convert this into strongly-typed values
    pub fn raw_timestamp(&self) -> i64 {
        self.0.EventHeader.TimeStamp
    }

    /// The `TimeStamp` field from the wrapped `EVENT_RECORD`, as a strongly-typed `time::OffsetDateTime`
    #[cfg(feature = "time_rs")]
    pub fn timestamp(&self) -> time::OffsetDateTime {
        crate::native::time::FileTime::from_quad(self.0.EventHeader.TimeStamp).into()
    }

    pub(crate) fn user_buffer(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.0.UserData as *mut _, self.0.UserDataLength.into())
        }
    }

    pub(crate) fn pointer_size(&self) -> usize {
        if self.event_flags() & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
            4
        } else {
            8
        }
    }

    /// Returns the `ExtendedData` from the ETW Event
    ///
    /// Their availability is mostly determined by the flags passed to [`Provider::trace_flags`](crate::provider::Provider::trace_flags)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// use windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID;
    ///
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let activity_id = record
    ///         .extended_data()
    ///         .iter()
    ///         .find(|edata| edata.data_type() as u32 == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID)
    ///         .map(|edata| edata.to_extended_data_item());
    /// };
    /// ```
    pub fn extended_data(&self) -> &[EventHeaderExtendedDataItem] {
        let n_extended_data = self.0.ExtendedDataCount;
        let p_ed_array = self.0.ExtendedData;
        if n_extended_data == 0 || p_ed_array.is_null() {
            return &[];
        }

        // Safety: * we're building a slice from an array pointer size given by Windows
        //         * the pointed data is not supposed to be mutated during the lifetime of `Self`
        unsafe {
            std::slice::from_raw_parts(
                p_ed_array as *const EventHeaderExtendedDataItem,
                n_extended_data as usize,
            )
        }
    }

    /// Returns the `eventName` for manifest-free events
    pub fn event_name(&self) -> String {
        if self.event_id() != 0 {
            return String::new();
        }

        if let Some(ExtendedDataItem::TraceLogging(name)) = self
            .extended_data()
            .iter()
            .find(|ext_data| ext_data.is_tlg())
            .map(|ext_data| ext_data.to_extended_data_item())
        {
            name
        } else {
            String::new()
        }
    }
}
