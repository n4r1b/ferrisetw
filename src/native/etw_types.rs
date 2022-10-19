//! Basic ETW types
//!
//! The `etw_types` module provides an abstraction over the basic ETW types needed to control and
//! parse a trace session. Most of the types in this module are wrappers over the windows bindings
//! using the newtype pattern to extend their implementations
//!
//! In most cases a user of the crate won't have to deal with this and can directly obtain the data
//! needed by using the functions exposed by the modules at the crate level
use crate::provider::event_filter::EventFilterDescriptor;
use crate::provider::TraceFlags;
use crate::trace::{CallbackData, TraceProperties, TraceTrait};
use std::ffi::c_void;
use std::fmt::Formatter;
use std::marker::PhantomData;
use std::sync::Arc;

use windows::core::GUID;
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Etw;
use windows::Win32::System::Diagnostics::Etw::EVENT_FILTER_DESCRIPTOR;
use widestring::{U16CStr, U16CString};

mod event_record;
pub use event_record::EventRecord;

mod extended_data;
pub use extended_data::{ExtendedDataItem, EventHeaderExtendedDataItem};

pub const TRACE_NAME_MAX_CHARS: usize = 200; // Microsoft documentation says the limit is 1024, but do not trust us. Experience shows that traces with names longer than ~240 character silently fail.

/// This enum is <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ne-evntrace-trace_query_info_class>
///
/// Re-defining it here, because all these values are not defined in windows-rs (yet?)
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
#[repr(i32)]
pub enum TraceInformation {
    TraceGuidQueryList,
    TraceGuidQueryInfo,
    TraceGuidQueryProcess,
    TraceStackTracingInfo,
    TraceSystemTraceEnableFlagsInfo,
    TraceSampledProfileIntervalInfo,
    TraceProfileSourceConfigInfo,
    TraceProfileSourceListInfo,
    TracePmcEventListInfo,
    TracePmcCounterListInfo,
    TraceSetDisallowList,
    TraceVersionInfo,
    TraceGroupQueryList,
    TraceGroupQueryInfo,
    TraceDisallowListQuery,
    TraceInfoReserved15,
    TracePeriodicCaptureStateListInfo,
    TracePeriodicCaptureStateInfo,
    TraceProviderBinaryTracking,
    TraceMaxLoggersQuery,
    TraceLbrConfigurationInfo,
    TraceLbrEventListInfo,
    /// Query the maximum PMC counters that can be specified simultaneously.
    /// May be queried without an active ETW session.
    ///
    /// Output: u32
    TraceMaxPmcCounterQuery,
    TraceStreamCount,
    TraceStackCachingInfo,
    TracePmcCounterOwners,
    TraceUnifiedStackCachingInfo,
    TracePmcSessionInformation,
    MaxTraceSetInfoClass,
}

#[allow(dead_code)]
pub(crate) enum ControlValues {
    Query = 0,
    Stop = 1,
    Update = 2,
}

#[allow(dead_code)]
enum LoggingMode {
    None,
    Sequential,
    Circular,
    Append,
    NewFile,
    NonStoppable,
    Secure,
    RealTime,
    Buffering,
    SystemLogger,
    DelayOpenFile,
    PrivateLogger,
    NoPerProcBuffering,
}

impl From<LoggingMode> for u32 {
    fn from(val: LoggingMode) -> Self {
        match val {
            // Not all but pretty much...
            LoggingMode::None => Etw::EVENT_TRACE_FILE_MODE_NONE,
            LoggingMode::Sequential => Etw::EVENT_TRACE_FILE_MODE_SEQUENTIAL,
            LoggingMode::Circular => Etw::EVENT_TRACE_FILE_MODE_CIRCULAR,
            LoggingMode::Append => Etw::EVENT_TRACE_FILE_MODE_APPEND,
            LoggingMode::NewFile => Etw::EVENT_TRACE_FILE_MODE_NEWFILE,
            LoggingMode::NonStoppable => Etw::EVENT_TRACE_NONSTOPPABLE_MODE,
            LoggingMode::Secure => Etw::EVENT_TRACE_SECURE_MODE,
            LoggingMode::RealTime => Etw::EVENT_TRACE_REAL_TIME_MODE,
            LoggingMode::DelayOpenFile => Etw::EVENT_TRACE_DELAY_OPEN_FILE_MODE,
            LoggingMode::Buffering => Etw::EVENT_TRACE_BUFFERING_MODE,
            LoggingMode::PrivateLogger => Etw::EVENT_TRACE_PRIVATE_LOGGER_MODE,
            LoggingMode::SystemLogger => Etw::EVENT_TRACE_SYSTEM_LOGGER_MODE,
            LoggingMode::NoPerProcBuffering => Etw::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
        }
    }
}

#[allow(dead_code)]
enum ProcessTraceMode {
    RealTime,
    EventRecord,
    RawTimestamp,
}

impl From<ProcessTraceMode> for u32 {
    fn from(val: ProcessTraceMode) -> Self {
        match val {
            ProcessTraceMode::RealTime => Etw::PROCESS_TRACE_MODE_EVENT_RECORD,
            ProcessTraceMode::EventRecord => Etw::PROCESS_TRACE_MODE_REAL_TIME,
            ProcessTraceMode::RawTimestamp => Etw::PROCESS_TRACE_MODE_RAW_TIMESTAMP,
        }
    }
}


/// Wrapper over an [EVENT_TRACE_PROPERTIES](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties), and its allocated companion members
///
/// The [EventTraceProperties] struct contains the information about a tracing session, this struct
/// also needs two buffers right after it to hold the log file name and the session name. This struct
/// provides the full definition of the properties plus the the allocation for both names
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventTraceProperties {
    etw_trace_properties: Etw::EVENT_TRACE_PROPERTIES,
    wide_trace_name: [u16; TRACE_NAME_MAX_CHARS+1],    // The +1 leaves space for the final null widechar.
    wide_log_file_name: [u16; TRACE_NAME_MAX_CHARS+1], // The +1 leaves space for the final null widechar. Not used currently, but this may be useful when resolving https://github.com/n4r1b/ferrisetw/issues/7
}


impl std::fmt::Debug for EventTraceProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = U16CString::from_vec_truncate(self.wide_trace_name).to_string_lossy();
        f.debug_struct("EventTraceProperties")
            .field("name", &name)
            .finish()
    }
}

impl EventTraceProperties {
    /// Create a new instance
    ///
    /// # Notes
    /// `trace_name` is limited to 200 characters.
    pub(crate) fn new<T>(
        trace_name: &U16CStr,
        trace_properties: &TraceProperties,
        enable_flags: Etw::EVENT_TRACE_FLAG,
    ) -> Self
    where
        T: TraceTrait
    {
        let mut etw_trace_properties = Etw::EVENT_TRACE_PROPERTIES::default();

        etw_trace_properties.Wnode.BufferSize = std::mem::size_of::<EventTraceProperties>() as u32;
        etw_trace_properties.Wnode.Guid = T::trace_guid();
        etw_trace_properties.Wnode.Flags = Etw::WNODE_FLAG_TRACED_GUID;
        etw_trace_properties.Wnode.ClientContext = 1; // QPC clock resolution
        etw_trace_properties.BufferSize = trace_properties.buffer_size;
        etw_trace_properties.MinimumBuffers = trace_properties.min_buffer;
        etw_trace_properties.MaximumBuffers = trace_properties.max_buffer;
        etw_trace_properties.FlushTimer = trace_properties.flush_timer;

        if trace_properties.log_file_mode != 0 {
            etw_trace_properties.LogFileMode = trace_properties.log_file_mode;
        } else {
            etw_trace_properties.LogFileMode =
                u32::from(LoggingMode::RealTime) | u32::from(LoggingMode::NoPerProcBuffering);
        }

        etw_trace_properties.LogFileMode |= T::augmented_file_mode();
        etw_trace_properties.EnableFlags = enable_flags;

        // etw_trace_properties.LogFileNameOffset must be 0, but this will change when https://github.com/n4r1b/ferrisetw/issues/7 is resolved
        // > If you do not want to log events to a log file (for example, if you specify EVENT_TRACE_REAL_TIME_MODE only), set LogFileNameOffset to 0.
        // (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
        etw_trace_properties.LoggerNameOffset = offset_of!(EventTraceProperties, wide_log_file_name) as u32;

        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties#remarks
        // > You do not copy the session name to the offset. The StartTrace function copies the name for you.
        //
        // Let's do it anyway, even though that's not required
        let mut s = Self {
            etw_trace_properties,
            wide_trace_name: [0u16; TRACE_NAME_MAX_CHARS+1],
            wide_log_file_name: [0u16; TRACE_NAME_MAX_CHARS+1],
        };
        let name_len = trace_name.len().min(TRACE_NAME_MAX_CHARS);
        s.wide_trace_name[..name_len].copy_from_slice(&trace_name.as_slice()[..name_len]);

        s
    }

    /// Gets a pointer to the wrapped [Etw::EVENT_TRACE_PROPERTIES]
    ///
    /// # Safety
    ///
    /// The API enforces this points to an allocated, valid `EVENT_TRACE_PROPERTIES` instance.
    /// As evey other mutable raw pointer, you should not use it in case someone else is keeping a reference to this object.
    ///
    /// Note that `OpenTraceA` **will** modify its content on output.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut Etw::EVENT_TRACE_PROPERTIES {
        &mut self.etw_trace_properties as *mut Etw::EVENT_TRACE_PROPERTIES
    }

    pub fn trace_name_array(&self) -> &[u16] {
        &self.wide_trace_name
    }
}

/// Newtype wrapper over an [EVENT_TRACE_LOGFILEW]
///
/// Its lifetime is tied a to [`CallbackData`] because it contains raw pointers to it.
///
/// [EVENT_TRACE_LOGFILEW]: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Etw/struct.EVENT_TRACE_LOGFILEW.html
#[repr(C)]
#[derive(Clone)]
pub struct EventTraceLogfile<'callbackdata> {
    native: Etw::EVENT_TRACE_LOGFILEW,
    wide_logger_name: U16CString,
    lifetime: PhantomData<&'callbackdata CallbackData>,
}

impl<'callbackdata> EventTraceLogfile<'callbackdata> {
    /// Create a new instance
    pub fn create(callback_data: &'callbackdata Box<Arc<CallbackData>>, mut wide_logger_name: U16CString, callback: unsafe extern "system" fn(*mut Etw::EVENT_RECORD)) -> Self {
        let mut native = Etw::EVENT_TRACE_LOGFILEW::default();

        native.LoggerName = PWSTR(wide_logger_name.as_mut_ptr());
        native.Anonymous1.ProcessTraceMode =
            u32::from(ProcessTraceMode::RealTime) | u32::from(ProcessTraceMode::EventRecord);

        native.Anonymous2.EventRecordCallback = Some(callback);

        let not_really_mut_ptr = callback_data.as_ref() as *const Arc<CallbackData> as *const c_void as *mut c_void; // That's kind-of fine because the user context is _not supposed_ to be changed by Windows APIs
        native.Context = not_really_mut_ptr;

        Self {
            native,
            wide_logger_name,
            lifetime: PhantomData,
        }
    }

    /// Retrieve the windows-rs compatible pointer to the contained `EVENT_TRACE_LOGFILEA`
    ///
    /// # Safety
    ///
    /// This pointer is valid as long as [`Self`] is alive (and not modified elsewhere)<br/>
    /// Note that `OpenTraceW` **will** modify its content on output, and thus you should make sure to be the only user of this instance.
    pub(crate) unsafe fn as_mut_ptr(&mut self) -> *mut Etw::EVENT_TRACE_LOGFILEW {
        &mut self.native as *mut Etw::EVENT_TRACE_LOGFILEW
    }
}

/// Newtype wrapper over an [ENABLE_TRACE_PARAMETERS]
///
/// [ENABLE_TRACE_PARAMETERS]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.ENABLE_TRACE_PARAMETERS.html
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EnableTraceParameters<'filters>{
    native: Etw::ENABLE_TRACE_PARAMETERS,
    lifetime: PhantomData<&'filters EventFilterDescriptor>,
}

impl<'filters> EnableTraceParameters<'filters> {
    pub fn create(guid: GUID, trace_flags: TraceFlags, filters: &'filters [EventFilterDescriptor]) -> Self {
        let mut params = EnableTraceParameters::default();
        params.native.ControlFlags = 0;
        params.native.Version = Etw::ENABLE_TRACE_PARAMETERS_VERSION_2;
        params.native.SourceId = guid;
        params.native.EnableProperty = trace_flags.bits();


        let mut win_filter_descriptors: Vec<EVENT_FILTER_DESCRIPTOR> = filters
            .iter()
            .map(|efd| efd.as_event_filter_descriptor())
            .collect();
        params.native.FilterDescCount = win_filter_descriptors.len() as u32; // (let's assume we won't try to fit more than 4 billion filters)
        if filters.is_empty() {
            params.native.EnableFilterDesc = std::ptr::null_mut();
        } else {
            params.native.EnableFilterDesc = win_filter_descriptors.as_mut_ptr();
        }

        params
    }

    /// Returns an unsafe pointer over the wrapped `ENABLE_TRACE_PARAMETERS`
    ///
    /// # Safety
    ///
    /// This pointer is valid as long `self` is valid (and not mutated)
    pub fn as_ptr(&self) -> *const Etw::ENABLE_TRACE_PARAMETERS {
        &self.native as *const _
    }
}

/// Wrapper over the [DECODING_SOURCE] type
///
/// [DECODING_SOURCE]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.DECODING_SOURCE.html
#[derive(Debug)]
pub enum DecodingSource {
    DecodingSourceXMLFile,
    DecodingSourceWbem,
    DecodingSourceWPP,
    DecodingSourceTlg,
    DecodingSourceMax,
}

impl From<Etw::DECODING_SOURCE> for DecodingSource {
    fn from(val: Etw::DECODING_SOURCE) -> Self {
        match val {
            Etw::DecodingSourceXMLFile => DecodingSource::DecodingSourceXMLFile,
            Etw::DecodingSourceWbem => DecodingSource::DecodingSourceWbem,
            Etw::DecodingSourceWPP => DecodingSource::DecodingSourceWPP,
            Etw::DecodingSourceTlg => DecodingSource::DecodingSourceTlg,
            _ => DecodingSource::DecodingSourceMax,
        }
    }
}

// Safe cast (EVENT_HEADER_FLAG_32_BIT_HEADER = 32)
#[doc(hidden)]
pub const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = Etw::EVENT_HEADER_FLAG_32_BIT_HEADER as u16;
