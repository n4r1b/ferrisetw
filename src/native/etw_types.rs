//! Basic ETW types
//!
//! The `etw_types` module provides an abstraction over the basic ETW types needed to control and
//! parse a trace session. Most of the types in this module are wrappers over the windows bindings
//! using the newtype pattern to extend their implementations
//!
//! In most cases a user of the crate won't have to deal with this and can directly obtain the data
//! needed by using the functions exposed by the modules at the crate level
use crate::native::tdh_types::Property;
use crate::provider::Provider;
use crate::trace::{TraceData, TraceProperties, TraceTrait};
use crate::utils;
use std::fmt::Formatter;
use std::sync::RwLock;
use windows::core::GUID;
use windows::core::PSTR;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Diagnostics::Etw;

// typedef ULONG64 TRACEHANDLE, *PTRACEHANDLE;
pub(crate) type TraceHandle = u64;
pub(crate) type EvenTraceControl = Etw::EVENT_TRACE_CONTROL;

/// Renaming type [EVENT_RECORD] type to match rust Naming Convention
///
/// [EVENT_RECORD]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.EVENT_RECORD.html
pub type EventRecord = Etw::EVENT_RECORD;
pub(crate) type PEventRecord = *mut EventRecord;

pub const INVALID_TRACE_HANDLE: TraceHandle = u64::MAX;

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
        providers: &RwLock<Vec<Provider>>,
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
pub struct EventTraceLogfile(Etw::EVENT_TRACE_LOGFILEA);

impl EventTraceLogfile {
    /// Create a new instance
    ///
    /// # Safety
    ///
    /// Note that the returned structure contains pointers to the given `TraceData`, that should thus stay valid (and constant) during its lifetime
    pub fn create(trace_data: &TraceData, callback: unsafe extern "system" fn(*mut EventRecord)) -> Self {
        let mut log_file = EventTraceLogfile::default();

        let not_really_mut_ptr = trace_data.name.as_ptr() as *mut _; // That's kind-of fine because the logger name is _not supposed_ to be changed by Windows APIs
        log_file.0.LoggerName = PSTR(not_really_mut_ptr);
        log_file.0.Anonymous1.ProcessTraceMode =
            u32::from(ProcessTraceMode::RealTime) | u32::from(ProcessTraceMode::EventRecord);

        log_file.0.Anonymous2.EventRecordCallback = Some(callback);
        log_file.0.Context = unsafe { std::mem::transmute(trace_data as *const _) };

        log_file
    }
}

impl Default for EventTraceLogfile {
    fn default() -> Self {
        unsafe { std::mem::zeroed::<EventTraceLogfile>() }
    }
}

impl std::ops::Deref for EventTraceLogfile {
    type Target = Etw::EVENT_TRACE_LOGFILEA;

    fn deref(&self) -> &self::Etw::EVENT_TRACE_LOGFILEA {
        &self.0
    }
}

impl std::ops::DerefMut for EventTraceLogfile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Newtype wrapper over an [ENABLE_TRACE_PARAMETERS]
///
/// [ENABLE_TRACE_PARAMETERS]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.ENABLE_TRACE_PARAMETERS.html
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EnableTraceParameters(Etw::ENABLE_TRACE_PARAMETERS);

impl EnableTraceParameters {
    pub fn create(guid: GUID, trace_flags: u32) -> Self {
        let mut params = EnableTraceParameters::default();
        params.0.ControlFlags = 0;
        params.0.Version = Etw::ENABLE_TRACE_PARAMETERS_VERSION_2;
        params.0.SourceId = guid;
        params.0.EnableProperty = trace_flags;

        // TODO: Add Filters option
        params.0.EnableFilterDesc = std::ptr::null_mut();
        params.0.FilterDescCount = 0;

        params
    }
}

impl std::ops::Deref for EnableTraceParameters {
    type Target = Etw::ENABLE_TRACE_PARAMETERS;

    fn deref(&self) -> &self::Etw::ENABLE_TRACE_PARAMETERS {
        &self.0
    }
}

impl std::ops::DerefMut for EnableTraceParameters {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Newtype wrapper over an [TRACE_EVENT_INFO]
///
/// [TRACE_EVENT_INFO]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.TRACE_EVENT_INFO.html
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TraceEventInfo(Etw::TRACE_EVENT_INFO);

impl std::ops::Deref for TraceEventInfo {
    type Target = Etw::TRACE_EVENT_INFO;

    fn deref(&self) -> &self::Etw::TRACE_EVENT_INFO {
        &self.0
    }
}

impl std::ops::DerefMut for TraceEventInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<&TraceEventInfoRaw> for TraceEventInfo {
    fn from(val: &TraceEventInfoRaw) -> Self {
        unsafe { *(val.info.as_ptr() as *mut TraceEventInfo) }
    }
}

/// Newtype wrapper over an [EVENT_PROPERTY_INFO]
///
/// [EVENT_PROPERTY_INFO]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.EVENT_PROPERTY_INFO.html
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventPropertyInfo(Etw::EVENT_PROPERTY_INFO);

impl std::ops::Deref for EventPropertyInfo {
    type Target = Etw::EVENT_PROPERTY_INFO;

    fn deref(&self) -> &self::Etw::EVENT_PROPERTY_INFO {
        &self.0
    }
}

impl std::ops::DerefMut for EventPropertyInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<&[u8]> for EventPropertyInfo {
    fn from(val: &[u8]) -> Self {
        unsafe { *(val.as_ptr() as *mut EventPropertyInfo) }
    }
}

impl Default for EventPropertyInfo {
    fn default() -> Self {
        unsafe { std::mem::zeroed::<EventPropertyInfo>() }
    }
}

/// Wrapper over the [DECODING_SOURCE] type
///
/// [DECODING_SOURCE]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.DECODING_SOURCE.html
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

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub(crate) struct TraceEventInfoRaw {
    info: Vec<u8>,
}

impl TraceEventInfoRaw {
    pub(crate) fn alloc(len: u32) -> Self {
        TraceEventInfoRaw {
            info: vec![0; len as usize],
        }
    }

    pub(crate) fn info_as_ptr(&mut self) -> *mut u8 {
        self.info.as_mut_ptr()
    }

    pub(crate) fn provider_guid(&self) -> GUID {
        TraceEventInfo::from(self).ProviderGuid
    }

    pub(crate) fn event_id(&self) -> u16 {
        TraceEventInfo::from(self).EventDescriptor.Id
    }

    pub(crate) fn event_version(&self) -> u8 {
        TraceEventInfo::from(self).EventDescriptor.Version
    }

    pub(crate) fn decoding_source(&self) -> DecodingSource {
        DecodingSource::from(TraceEventInfo::from(self).DecodingSource)
    }

    pub(crate) fn provider_name(&self) -> String {
        let provider_name_offset = TraceEventInfo::from(self).ProviderNameOffset as usize;
        // TODO: Evaluate performance, but this sounds better than creating a whole Vec<u16> and getting the string from the offset/2
        utils::parse_unk_size_null_utf16_string(&self.info[provider_name_offset..])
    }

    pub(crate) fn task_name(&self) -> String {
        let task_name_offset = TraceEventInfo::from(self).TaskNameOffset as usize;
        utils::parse_unk_size_null_utf16_string(&self.info[task_name_offset..])
    }

    pub(crate) fn opcode_name(&self) -> String {
        let opcode_name_offset = TraceEventInfo::from(self).OpcodeNameOffset as usize;
        if opcode_name_offset == 0 {
            return String::from("");
        }
        utils::parse_unk_size_null_utf16_string(&self.info[opcode_name_offset..])
    }

    pub(crate) fn property_count(&self) -> u32 {
        TraceEventInfo::from(self).PropertyCount
    }

    pub(crate) fn property(&self, index: u32) -> Property {
        // let's make sure index is not bigger thant the PropertyCount
        assert!(index <= self.property_count());

        // We need to subtract the sizeof(EVENT_PROPERTY_INFO) due to how TRACE_EVENT_INFO is declared
        // in the bindings, the last field `EventPropertyInfoArray[ANYSIZE_ARRAY]` is declared as
        // [EVENT_PROPERTY_INFO; 1]
        // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.TRACE_EVENT_INFO.html#structfield.EventPropertyInfoArray
        let curr_prop_offset = index as usize * std::mem::size_of::<EventPropertyInfo>()
            + (std::mem::size_of::<TraceEventInfo>() - std::mem::size_of::<EventPropertyInfo>());

        let curr_prop = EventPropertyInfo::from(&self.info[curr_prop_offset..]);
        let name =
            utils::parse_unk_size_null_utf16_string(&self.info[curr_prop.NameOffset as usize..]);
        Property::new(name, &curr_prop)
    }
}
