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
use crate::trace::{TraceProperties, TraceTrait};
use crate::trace::callback_data::CallbackData;
use std::ffi::{c_void, OsString};
use std::fmt::Formatter;
use std::marker::PhantomData;
use std::sync::Arc;

use windows::core::GUID;
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Etw;
use windows::Win32::System::Diagnostics::Etw::EVENT_FILTER_DESCRIPTOR;
use widestring::{U16CStr, U16CString};

pub(crate) mod event_record;
pub(crate) mod extended_data;

pub const TRACE_NAME_MAX_CHARS: usize = 200; // Microsoft documentation says the limit is 1024, but do not trust us. Experience shows that traces with names longer than ~240 character silently fail.

/// This enum is <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ne-evntrace-trace_query_info_class>
///
/// Re-defining it here, because all these values are not defined in windows-rs (yet?)
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
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

bitflags! {
    /// Logging Mode constants that applies to a general trace
    ///
    /// This is a subset of <https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants>
    pub struct LoggingMode: u32 {
        // Commented values only apply to DumpFileLoggingMod

        // EVENT_TRACE_FILE_MODE_NONE
        // EVENT_TRACE_FILE_MODE_SEQUENTIAL
        // EVENT_TRACE_FILE_MODE_CIRCULAR
        // EVENT_TRACE_FILE_MODE_APPEND
        // EVENT_TRACE_FILE_MODE_NEWFILE
        // EVENT_TRACE_FILE_MODE_PREALLOCATE
        const EVENT_TRACE_NONSTOPPABLE_MODE =          Etw::EVENT_TRACE_NONSTOPPABLE_MODE;
        const EVENT_TRACE_SECURE_MODE =                Etw::EVENT_TRACE_SECURE_MODE;
        const EVENT_TRACE_REAL_TIME_MODE =             Etw::EVENT_TRACE_REAL_TIME_MODE;
        // On Windows Vista or later, this mode is not applicable should not be used.
        // EVENT_TRACE_DELAY_OPEN_FILE_MODE
        const EVENT_TRACE_BUFFERING_MODE =             Etw::EVENT_TRACE_BUFFERING_MODE;
        const EVENT_TRACE_PRIVATE_LOGGER_MODE =        Etw::EVENT_TRACE_PRIVATE_LOGGER_MODE;
        // EVENT_TRACE_USE_KBYTES_FOR_SIZE
        // EVENT_TRACE_USE_GLOBAL_SEQUENCE
        // EVENT_TRACE_USE_LOCAL_SEQUENCE
        const EVENT_TRACE_PRIVATE_IN_PROC =            Etw::EVENT_TRACE_PRIVATE_IN_PROC;
        const EVENT_TRACE_MODE_RESERVED =              Etw::EVENT_TRACE_MODE_RESERVED;
        const EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN =    Etw::EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN;
        const EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN = Etw::EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN;
        const EVENT_TRACE_USE_PAGED_MEMORY =           Etw::EVENT_TRACE_USE_PAGED_MEMORY;
        const EVENT_TRACE_SYSTEM_LOGGER_MODE =         Etw::EVENT_TRACE_SYSTEM_LOGGER_MODE;
        const EVENT_TRACE_INDEPENDENT_SESSION_MODE =   Etw::EVENT_TRACE_INDEPENDENT_SESSION_MODE;
        const EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = Etw::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        const EVENT_TRACE_ADDTO_TRIAGE_DUMP =          Etw::EVENT_TRACE_ADDTO_TRIAGE_DUMP;
    }
}

bitflags! {
    /// Logging Mode constants that applies to a dump file.
    ///
    /// This is a subset of <https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants>
    ///
    /// See the documentation of [`crate::trace::TraceBuilder::set_etl_dump_file`] for more info.
    pub struct DumpFileLoggingMode: u32 {
        // Commented values only apply to LoggingMode

        /// > Same as EVENT_TRACE_FILE_MODE_SEQUENTIAL with no maximum file size specified.
        const EVENT_TRACE_FILE_MODE_NONE =             Etw::EVENT_TRACE_FILE_MODE_NONE;
        /// > Writes events to a log file sequentially; stops when the file reaches its maximum size.Do not use with EVENT_TRACE_FILE_MODE_CIRCULAR or EVENT_TRACE_FILE_MODE_NEWFILE.
        ///
        /// Note: "stop" here means "stop appending to the file", not "stop the trace"
        const EVENT_TRACE_FILE_MODE_SEQUENTIAL =       Etw::EVENT_TRACE_FILE_MODE_SEQUENTIAL;
        /// > Writes events to a log file. After the file reaches the maximum size, the oldest events are replaced with incoming events.Note that the contents of the circular log file may appear out of order on multiprocessor computers.<br/>
        /// > Do not use with EVENT_TRACE_FILE_MODE_APPEND, EVENT_TRACE_FILE_MODE_NEWFILE, or EVENT_TRACE_FILE_MODE_SEQUENTIAL.
        const EVENT_TRACE_FILE_MODE_CIRCULAR =         Etw::EVENT_TRACE_FILE_MODE_CIRCULAR;
        /// > Appends events to an existing sequential log file. If the file does not exist, it is created. Use only if you specify system time for the clock resolution, otherwise, ProcessTrace will return events with incorrect time stamps. When using EVENT_TRACE_FILE_MODE_APPEND, the values for BufferSize, NumberOfProcessors, and ClockType must be explicitly provided and must be the same in both the logger and the file being appended.<br/>
        /// > Do not use with EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_FILE_MODE_NEWFILE, or EVENT_TRACE_PRIVATE_LOGGER_MODE.
        const EVENT_TRACE_FILE_MODE_APPEND =           Etw::EVENT_TRACE_FILE_MODE_APPEND;
        /// > Automatically switches to a new log file when the file reaches the maximum size. The MaximumFileSize member of EVENT_TRACE_PROPERTIES must be set.The specified file name must be a formatted string (for example, the string contains a %d, such as c:\test%d.etl). Each time a new file is created, a counter is incremented and its value is used, the formatted string is updated, and the resulting string is used as the file name.<br/>
        /// > This option is not allowed for private event tracing sessions and should not be used for NT kernel logger sessions.<br/>
        /// > Do not use with EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_FILE_MODE_APPEND or EVENT_TRACE_FILE_MODE_SEQUENTIAL.
        const EVENT_TRACE_FILE_MODE_NEWFILE =          Etw::EVENT_TRACE_FILE_MODE_NEWFILE;
        /// > Reserves EVENT_TRACE_PROPERTIES.MaximumFileSize bytes of disk space for the log file in advance. The file occupies the entire space during logging, for both circular and sequential log files. When you stop the session, the log file is reduced to the size needed. You must set EVENT_TRACE_PROPERTIES.MaximumFileSize.<br/>
        /// > You cannot use the mode for private event tracing sessions.
        const EVENT_TRACE_FILE_MODE_PREALLOCATE =      Etw::EVENT_TRACE_FILE_MODE_PREALLOCATE;
        // EVENT_TRACE_NONSTOPPABLE_MODE
        // EVENT_TRACE_SECURE_MODE
        // EVENT_TRACE_REAL_TIME_MODE
        // On Windows Vista or later, this mode is not applicable should not be used.
        // EVENT_TRACE_DELAY_OPEN_FILE_MODE
        // EVENT_TRACE_BUFFERING_MODE
        // EVENT_TRACE_PRIVATE_LOGGER_MODE
        /// > Use kilobytes as the unit of measure for specifying the size of a file. The default unit of measure is megabytes. This mode applies to the MaxFileSize registry value for an AutoLogger session and the MaximumFileSize member of EVENT_TRACE_PROPERTIES.
        const EVENT_TRACE_USE_KBYTES_FOR_SIZE =        Etw::EVENT_TRACE_USE_KBYTES_FOR_SIZE;
        /// > Uses sequence numbers that are unique across event tracing sessions. This mode only applies to events logged using the TraceMessage function. For more information, see TraceMessage for usage details.<br/>
        /// > EVENT_TRACE_USE_GLOBAL_SEQUENCE and EVENT_TRACE_USE_LOCAL_SEQUENCE are mutually exclusive.
        const EVENT_TRACE_USE_GLOBAL_SEQUENCE =        Etw::EVENT_TRACE_USE_GLOBAL_SEQUENCE;
        /// > Uses sequence numbers that are unique only for an individual event tracing session. This mode only applies to events logged using the TraceMessage function. For more information, see TraceMessage for usage details.<br/>
        /// > EVENT_TRACE_USE_GLOBAL_SEQUENCE and EVENT_TRACE_USE_LOCAL_SEQUENCE are mutually exclusive.
        const EVENT_TRACE_USE_LOCAL_SEQUENCE =         Etw::EVENT_TRACE_USE_LOCAL_SEQUENCE;
        // EVENT_TRACE_PRIVATE_IN_PROC
        // EVENT_TRACE_MODE_RESERVED
        // EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN
        // EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN
        // EVENT_TRACE_USE_PAGED_MEMORY
        // EVENT_TRACE_SYSTEM_LOGGER_MODE
        // EVENT_TRACE_INDEPENDENT_SESSION_MODE
        // EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
        // EVENT_TRACE_ADDTO_TRIAGE_DUMP
    }
}

impl std::default::Default for DumpFileLoggingMode {
    fn default() -> Self {
        Self::EVENT_TRACE_FILE_MODE_NONE
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
    /// The trace name to subscribe to
    wide_trace_name: [u16; TRACE_NAME_MAX_CHARS+1],    // The +1 leaves space for the final null widechar.
    /// The file name (if any) we store our events to
    wide_etl_dump_file_path: [u16; TRACE_NAME_MAX_CHARS+1], // The +1 leaves space for the final null widechar.
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
    /// `trace_name` is limited to 200 characters.<br/>
    /// The path to the dump file is limited to 200 characters.
    pub(crate) fn new<T>(
        trace_name: &U16CStr,
        etl_dump_file: Option<(&U16CStr, DumpFileLoggingMode, Option<u32>)>,
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
        etw_trace_properties.FlushTimer = trace_properties.flush_timer.as_secs().clamp(1, u32::MAX as u64) as u32; // See https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties

        if trace_properties.log_file_mode.is_empty() == false {
            etw_trace_properties.LogFileMode = trace_properties.log_file_mode.bits();
        } else {
            etw_trace_properties.LogFileMode =
                (LoggingMode::EVENT_TRACE_REAL_TIME_MODE | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING).bits()
        }

        etw_trace_properties.LogFileMode |= T::augmented_file_mode();
        etw_trace_properties.EnableFlags = enable_flags;

        let mut s = Self {
            etw_trace_properties,
            wide_trace_name: [0u16; TRACE_NAME_MAX_CHARS+1],
            wide_etl_dump_file_path: [0u16; TRACE_NAME_MAX_CHARS+1],
        };

        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties#remarks
        // > You do not copy the session name to the offset. The StartTrace function copies the name for you.
        //
        // Let's do it anyway, even though that's not required
        let name_len = trace_name.len().min(TRACE_NAME_MAX_CHARS);
        s.wide_trace_name[..name_len].copy_from_slice(&trace_name.as_slice()[..name_len]);
        s.etw_trace_properties.LoggerNameOffset = offset_of!(EventTraceProperties, wide_trace_name) as u32;

        // Also populate the file name, if any
        match etl_dump_file {
            None => {
                // Here, we do not want to dump events to a file
                // > If you do not want to log events to a log file (for example, if you specify EVENT_TRACE_REAL_TIME_MODE only), set LogFileNameOffset to 0.
                // (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
                s.etw_trace_properties.LogFileNameOffset = 0;
            },
            Some((path, file_mode, max_size)) => {
                // Set the file path, and set the dump-file-related flags
                let path_len = path.len().min(TRACE_NAME_MAX_CHARS);
                s.wide_etl_dump_file_path[..path_len].copy_from_slice(&path.as_slice()[..path_len]);
                s.etw_trace_properties.LogFileNameOffset = offset_of!(EventTraceProperties, wide_etl_dump_file_path) as u32;

                s.etw_trace_properties.LogFileMode |= file_mode.bits();
                if let Some(max_file_size) = max_size {
                    s.etw_trace_properties.MaximumFileSize = max_file_size;
                }
            },
        }

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
    pub fn name(&self) -> OsString {
        widestring::U16CStr::from_slice_truncate(&self.wide_trace_name)
            .map(|ws| ws.to_os_string())
            .unwrap_or_else(|_| OsString::from("<invalid name>"))
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
    #[allow(clippy::borrowed_box)] // Being Boxed is really important, let's keep the Box<...> in the function signature to make the intent clearer (see https://github.com/n4r1b/ferrisetw/issues/72)
    pub fn create(callback_data: &'callbackdata Box<Arc<CallbackData>>, mut wide_logger_name: U16CString, callback: unsafe extern "system" fn(*mut Etw::EVENT_RECORD)) -> Self {
        let not_really_mut_ptr = callback_data.as_ref() as *const Arc<CallbackData> as *const c_void as *mut c_void; // That's kind-of fine because the user context is _not supposed_ to be changed by Windows APIs

        let native = Etw::EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(wide_logger_name.as_mut_ptr()),
            Anonymous1: Etw::EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: Etw::PROCESS_TRACE_MODE_REAL_TIME | Etw::PROCESS_TRACE_MODE_EVENT_RECORD
                // In case you really want to use PROCESS_TRACE_MODE_RAW_TIMESTAMP, please review EventRecord::timestamp(), which could not be valid anymore
            },
            Anonymous2: Etw::EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(callback)
            },
            Context: not_really_mut_ptr,
            ..Default::default()
        };

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

    /// The current Context pointer.
    pub fn context_ptr(&self) -> *const std::ffi::c_void {
        self.native.Context
    }
}

/// Newtype wrapper over an [ENABLE_TRACE_PARAMETERS]
///
/// [ENABLE_TRACE_PARAMETERS]: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Etw/struct.ENABLE_TRACE_PARAMETERS.html
#[repr(C)]
#[derive(Clone, Default)]
pub struct EnableTraceParameters<'filters>{
    native: Etw::ENABLE_TRACE_PARAMETERS,
    /// `native` has pointers to an array of EVENT_FILTER_DESCRIPTOR, let's store it here
    array_of_event_filter_descriptor: Vec<EVENT_FILTER_DESCRIPTOR>,
    /// `array_of_event_filter_descriptor` points to data somewhere else. Let's bind it to their lifetime
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
        params.array_of_event_filter_descriptor = filters
            .iter()
            .map(|efd| efd.as_event_filter_descriptor())
            .collect();
        params.native.FilterDescCount = params.array_of_event_filter_descriptor.len() as u32; // (let's assume we won't try to fit more than 4 billion filters)
        if filters.is_empty() {
            params.native.EnableFilterDesc = std::ptr::null_mut();
        } else {
            params.native.EnableFilterDesc = params.array_of_event_filter_descriptor.as_mut_ptr();
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
/// [DECODING_SOURCE]: https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-decoding_source
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
