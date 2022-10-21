//! Safe wrappers over the EVENT_RECORD type

use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;
use windows::core::GUID;

use crate::native::etw_types::EventHeaderExtendedDataItem;

/// A read-only wrapper over an [EVENT_RECORD](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)
#[repr(transparent)]
pub struct EventRecord(EVENT_RECORD);

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
    pub fn as_raw_ptr(&self) -> *const EVENT_RECORD {
        &self.0 as *const EVENT_RECORD
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
    pub fn timestamp(&self) -> i64 {
        self.0.EventHeader.TimeStamp
    }

    pub(crate) fn user_buffer(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.0.UserData as *mut _,
                self.0.UserDataLength.into(),
            )
        }
    }

    /// Returns the ExtendedData from the ETW Event
    ///
    /// Their availability is mostly determined by the flags passed to [`Provider::trace_flags`](crate::provider::Provider::trace_flags)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::native::etw_types::EventRecord;
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
                n_extended_data as usize)
        }
    }
}
