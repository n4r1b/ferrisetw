//! Basic ETW types
//!
//! The `etw_types` module provides an abstraction over the basic ETW types needed to control and
//! parse a trace session. Most of the types in this module are wrappers over the windows bindings
//! using the newtype pattern to extend their implementations
//!
//! In most cases a user of the crate won't have to deal with this and can directly obtain the data
//! needed by using the functions exposed by the modules at the crate level
use crate::provider::event_filter::EventFilterDescriptor;
use crate::provider::{Provider, TraceFlags};
use crate::trace::{TraceData, TraceProperties, TraceTrait};
use std::ffi::c_void;
use std::fmt::Formatter;
use std::marker::PhantomData;
use windows::core::GUID;
use windows::core::PSTR;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Diagnostics::Etw;
use windows::Win32::System::Diagnostics::Etw::EVENT_FILTER_DESCRIPTOR;

mod event_record;
pub use event_record::EventRecord;

mod extended_data;
pub use extended_data::{ExtendedDataItem, EventHeaderExtendedDataItem};

// typedef ULONG64 TRACEHANDLE, *PTRACEHANDLE;
pub(crate) type TraceHandle = u64;
pub(crate) type EvenTraceControl = Etw::EVENT_TRACE_CONTROL;

pub const INVALID_TRACE_HANDLE: TraceHandle = u64::MAX;

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

/// Newtype wrapper over an [EVENT_TRACE_PROPERTIES]
///
/// [EVENT_TRACE_PROPERTIES]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.EVENT_TRACE_PROPERTIES.html
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventTraceProperties(Etw::EVENT_TRACE_PROPERTIES);

impl std::fmt::Debug for EventTraceProperties {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Default for EventTraceProperties {
    fn default() -> Self {
        unsafe { std::mem::zeroed::<EventTraceProperties>() }
    }
}

impl std::ops::Deref for EventTraceProperties {
    type Target = Etw::EVENT_TRACE_PROPERTIES;

    fn deref(&self) -> &self::Etw::EVENT_TRACE_PROPERTIES {
        &self.0
    }
}

impl std::ops::DerefMut for EventTraceProperties {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Complete Trace Properties struct
///
/// The [EventTraceProperties] struct contains the information about a tracing session, this struct
/// also needs two buffers right after it to hold the log file name and the session name. This struct
/// provides the full definition of the properties plus the the allocation for both names
///
/// See: [EVENT_TRACE_PROPERTIES](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TraceInfo {
    pub properties: EventTraceProperties,
    trace_name: [u8; MAX_PATH as usize],
    log_file_name: [u8; MAX_PATH as usize],
}

impl TraceInfo {
    pub(crate) fn fill<T>(
        &mut self,
        trace_name: &str,
        trace_properties: &TraceProperties,
        providers: &[Provider],
    ) where
        T: TraceTrait,
    {
        self.properties.0.Wnode.BufferSize = std::mem::size_of::<TraceInfo>() as u32;
        self.properties.0.Wnode.Guid = T::trace_guid();
        self.properties.0.Wnode.Flags = Etw::WNODE_FLAG_TRACED_GUID;
        self.properties.0.Wnode.ClientContext = 1; // QPC clock resolution
        self.properties.0.BufferSize = trace_properties.buffer_size;
        self.properties.0.MinimumBuffers = trace_properties.min_buffer;
        self.properties.0.MaximumBuffers = trace_properties.max_buffer;
        self.properties.0.FlushTimer = trace_properties.flush_timer;

        if trace_properties.log_file_mode != 0 {
            self.properties.0.LogFileMode = trace_properties.log_file_mode;
        } else {
            self.properties.0.LogFileMode =
                u32::from(LoggingMode::RealTime) | u32::from(LoggingMode::NoPerProcBuffering);
        }

        self.properties.0.LogFileMode |= T::augmented_file_mode();
        self.properties.0.EnableFlags = Etw::EVENT_TRACE_FLAG(T::enable_flags(providers));

        self.properties.0.LoggerNameOffset = offset_of!(TraceInfo, log_file_name) as u32;
        self.trace_name[..trace_name.len()].copy_from_slice(trace_name.as_bytes())
    }
}

impl Default for TraceInfo {
    fn default() -> Self {
        let properties = EventTraceProperties::default();
        TraceInfo {
            properties,
            trace_name: [0; 260],
            log_file_name: [0; 260],
        }
    }
}

/// Newtype wrapper over an [EVENT_TRACE_LOGFILEA]
///
/// [EVENT_TRACE_LOGFILEA]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.EVENT_TRACE_LOGFILEA.html
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventTraceLogfile<'tracedata> {
    native: Etw::EVENT_TRACE_LOGFILEA,
    lifetime: PhantomData<&'tracedata TraceData>,
}

impl<'tracedata> EventTraceLogfile<'tracedata> {
    /// Create a new instance
    pub fn create(trace_data: &'tracedata Box<TraceData>, callback: unsafe extern "system" fn(*mut Etw::EVENT_RECORD)) -> Self {
        let mut log_file = EventTraceLogfile::default();

        let not_really_mut_ptr = trace_data.name.as_ptr() as *mut _; // That's kind-of fine because the logger name is _not supposed_ to be changed by Windows APIs
        log_file.native.LoggerName = PSTR(not_really_mut_ptr);
        log_file.native.Anonymous1.ProcessTraceMode =
            u32::from(ProcessTraceMode::RealTime) | u32::from(ProcessTraceMode::EventRecord);

        log_file.native.Anonymous2.EventRecordCallback = Some(callback);

        let not_really_mut_ptr = trace_data.as_ref() as *const TraceData as *const c_void as *mut c_void; // That's kind-of fine because the user context is _not supposed_ to be changed by Windows APIs
        log_file.native.Context = not_really_mut_ptr;

        log_file
    }

    /// Retrieve the windows-rs compatible pointer to the contained `EVENT_TRACE_LOGFILEA`
    ///
    /// # Safety
    ///
    /// This pointer is valid as long as [`Self`] is alive (and not modified elsewhere)
    pub unsafe fn as_mut_ptr(&mut self) -> *mut Etw::EVENT_TRACE_LOGFILEA {
        &mut self.native as *mut Etw::EVENT_TRACE_LOGFILEA
    }
}

impl<'tracedata> Default for EventTraceLogfile<'tracedata> {
    fn default() -> Self {
        unsafe { std::mem::zeroed::<EventTraceLogfile>() }
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


        // Note: > Each type of filter (a specific Type member) may only appear once in a call to the EnableTraceEx2 function.
        //       https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
        //       > The maximum number of filters that can be included in a call to EnableTraceEx2 is set by MAX_EVENT_FILTERS_COUNT
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
