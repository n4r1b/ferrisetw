//! ETW Tracing/Session abstraction
//!
//! Provides both a Kernel and User trace that allows to start an ETW session
use super::traits::*;
use crate::native::etw_types::{EventRecord, INVALID_TRACE_HANDLE};
use crate::native::{evntrace, version_helper};
use crate::provider::Provider;
use crate::{provider, schema, utils};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use windows::core::GUID;

const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
const SYSTEM_TRACE_CONTROL_GUID: &str = "9e814aad-3204-11d2-9a82-006008a86939";
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x02000000;

/// Trace module errors
#[derive(Debug)]
pub enum TraceError {
    /// Wrapper over an internal [EvntraceNativeError]
    ///
    /// [EvntraceNativeError]: crate::native::evntrace::EvntraceNativeError
    EtwNativeError(evntrace::EvntraceNativeError),
    /// Wrapper over an standard IO Error
    IoError(std::io::Error),
}

impl LastOsError<TraceError> for TraceError {}

impl From<std::io::Error> for TraceError {
    fn from(err: std::io::Error) -> Self {
        TraceError::IoError(err)
    }
}

impl From<evntrace::EvntraceNativeError> for TraceError {
    fn from(err: evntrace::EvntraceNativeError) -> Self {
        TraceError::EtwNativeError(err)
    }
}

type TraceResult<T> = Result<T, TraceError>;

/// Trace Properties struct
///
/// Keeps the ETW session configuration settings
///
/// [More info](https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings#configuring-the-etw-session)
#[derive(Debug, Copy, Clone, Default)]
pub struct TraceProperties {
    /// Represents the ETW Session in KB
    pub buffer_size: u32,
    /// Represents the ETW Session minimum number of buffers to use
    pub min_buffer: u32,
    /// Represents the ETW Session maximum number of buffers in the buffer pool
    pub max_buffer: u32,
    /// Represents the ETW Session flush interval in seconds
    pub flush_timer: u32,
    /// Represents the ETW Session [Logging Mode](https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
    pub log_file_mode: u32,
}

/// Struct which holds the Trace data
///
/// This struct will hold the main data required to handle an ETW Session
#[derive(Debug, Default)]
pub struct TraceData {
    /// Represents the trace name
    pub name: String,
    /// Represents the [TraceProperties]
    pub properties: TraceProperties,
    /// Represents the current events handled
    pub events_handled: AtomicUsize,
    /// List of Providers associated with the Trace
    pub providers: Vec<provider::Provider>,
    schema_locator: Mutex<schema::SchemaLocator>,
    // buffers_read : isize
}

impl TraceData {
    fn new() -> Self {
        let name = format!("n4r1b-trace-{}", utils::rand_string());
        Self::with_name(name)
    }

    fn with_name(name: String) -> Self {
        TraceData {
            name,
            events_handled: AtomicUsize::new(0),
            properties: TraceProperties::default(),
            providers: Vec::new(),
            schema_locator: Mutex::new(schema::SchemaLocator::new()),
        }
    }

    // TODO: Should be void???
    fn insert_provider(&mut self, provider: provider::Provider) {
        self.providers.push(provider);
    }

    pub(crate) fn on_event(&self, record: &mut EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);
        let mut locator = self.schema_locator.lock().unwrap();

        // We need a mutable reference to be able to modify the data it refers, which is actually
        // done within the Callback (The schema locator is modified)
        self.providers.iter().for_each(|prov| {
            // We can unwrap safely, provider builder wouldn't accept a provider without guid
            // so we must have Some(Guid)
            if prov.guid.unwrap() == record.EventHeader.ProviderId {
                prov.on_event(record, &mut locator);
            }
        });
    }
}

/// Specific trait for a Trace
///
/// This trait defines the specific methods that differentiate from a Kernel to a User Trace
pub trait TraceTrait {
    fn augmented_file_mode() -> u32 {
        0
    }
    fn enable_flags(_providers: &Vec<Provider>) -> u32 {
        0
    }
    fn trace_guid() -> GUID {
        GUID::new().unwrap_or(GUID::zeroed())
    }
}

// Prevent others from implementing our type trait.
mod sealed {
    pub trait Sealed {}
}

pub trait TraceType: sealed::Sealed {}
pub struct Kernel;
pub struct User;

impl sealed::Sealed for Kernel {}
impl sealed::Sealed for User {}

impl TraceType for Kernel {}
impl TraceType for User {}

pub struct KernelTraceBuilder;
pub struct UserTraceBuilder;
impl KernelTraceBuilder {
    pub fn new() -> TraceBuilder<Kernel> {
        TraceBuilder::<Kernel>::new()
    }
}

impl UserTraceBuilder {
    pub fn new() -> TraceBuilder<User> {
        TraceBuilder::<User>::new()
    }
}

#[derive(Default, Debug)]
pub struct TraceBuilder<T: TraceType> {
    _type: PhantomData<T>,
    data: TraceData,
}

impl<T: TraceType> TraceBuilder<T> {
    pub fn properties(mut self, props: TraceProperties) -> Self {
        self.data.properties = props;
        self
    }

    pub fn enable(mut self, provider: provider::Provider) -> Self {
        if provider.guid.is_none() {
            panic!("Attempted to enable provider with no GUID");
        }
        self.data.insert_provider(provider);

        self
    }

    pub fn open(self) -> TraceResult<Trace<T>>
    where
        Trace<T>: TraceTrait,
    {
        let mut etw = evntrace::NativeEtw::new();

        etw.fill_info::<Trace<T>>(&self.data.name, &self.data.properties, &self.data.providers);
        etw.register_trace(&self.data)?;

        let data = Arc::new(self.data);
        etw.open(data.clone())?;

        Ok(Trace::<T> {
            _type: PhantomData,
            data,
            etw,
        })
    }
}

impl TraceBuilder<Kernel> {
    pub fn new() -> Self {
        Self {
            _type: PhantomData,
            data: if version_helper::is_win8_or_greater() {
                TraceData::new()
            } else {
                TraceData::with_name(KERNEL_LOGGER_NAME.to_string())
            },
        }
    }

    pub fn named(mut self, name: String) -> Self {
        if !name.is_empty() && !version_helper::is_win8_or_greater() {
            self.data.name = name;
        }

        self
    }
}

impl TraceBuilder<User> {
    pub fn new() -> Self {
        Self {
            _type: PhantomData,
            data: TraceData::new(),
        }
    }

    pub fn named(mut self, name: String) -> Self {
        if name.is_empty() {
            panic!("Attempted to set an empty name for a trace logger");
        }

        self.data.name = name;
        self
    }
}

impl TraceTrait for Trace<Kernel> {
    fn augmented_file_mode() -> u32 {
        if version_helper::is_win8_or_greater() {
            EVENT_TRACE_SYSTEM_LOGGER_MODE
        } else {
            0
        }
    }

    fn enable_flags(providers: &Vec<Provider>) -> u32 {
        providers.iter().fold(0, |acc, x| acc | x.flags)
    }

    fn trace_guid() -> GUID {
        if version_helper::is_win8_or_greater() {
            GUID::new().unwrap_or(GUID::zeroed())
        } else {
            GUID::from(SYSTEM_TRACE_CONTROL_GUID)
        }
    }
}

impl TraceTrait for Trace<User> {}

/// Active trace struct
#[derive(Debug)]
pub struct Trace<T: TraceType> {
    _type: PhantomData<T>,
    data: Arc<TraceData>,
    etw: evntrace::NativeEtw,
}

impl<T: TraceType> Trace<T> {
    pub fn close(mut self) -> TraceResult<()> {
        self.etw.close()?;
        Ok(())
    }

    pub fn start(&mut self) -> TraceResult<()> {
        self.etw.start(&self.data)?;
        Ok(())
    }

    pub fn stop(&self) -> TraceResult<()> {
        self.etw.stop(&self.data)?;
        Ok(())
    }

    pub fn process(&self) -> TraceResult<()> {
        self.etw.process()?;

        Ok(())
    }
}

/// On drop the ETW session will be stopped if not stopped before
// TODO: log if it fails??
impl<T: TraceType> Drop for Trace<T> {
    fn drop(&mut self) {
        if self.etw.session_handle() != INVALID_TRACE_HANDLE {
            let _ = self.stop();
            let _ = self.etw.close();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_set_properties() {
        let prop = TraceProperties {
            buffer_size: 10,
            min_buffer: 1,
            max_buffer: 20,
            flush_timer: 60,
            log_file_mode: 5,
        };
        let trace = UserTraceBuilder::new().properties(prop);

        assert_eq!(trace.data.properties.buffer_size, 10);
        assert_eq!(trace.data.properties.min_buffer, 1);
        assert_eq!(trace.data.properties.max_buffer, 20);
        assert_eq!(trace.data.properties.flush_timer, 60);
        assert_eq!(trace.data.properties.log_file_mode, 5);
    }

    #[test]
    fn test_set_name() {
        let trace = UserTraceBuilder::new().named(String::from("TestName"));

        assert_eq!(trace.data.name, "TestName");
    }

    #[test]
    fn test_enable_multiple_providers() {
        let prov = Provider::new().by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
        let prov1 = Provider::new().by_guid("A0C1853B-5C40-4B15-8766-3CF1C58F985A");

        let trace = UserTraceBuilder::new().enable(prov).enable(prov1);

        assert_eq!(trace.data.providers.len(), 2);
    }

    #[test]
    #[should_panic(expected = "Attempted to enable provider with no GUID")]
    fn test_provider_no_guid_should_panic() {
        let prov = Provider::new();

        let _trace = UserTraceBuilder::new().enable(prov);
    }
}
