//! ETW Tracing/Session abstraction
//!
//! Provides both a Kernel and User trace that allows to start an ETW session
use std::sync::atomic::{AtomicUsize, Ordering};

use super::traits::*;
use crate::native::etw_types::{EnableTraceParameters, EventRecord, INVALID_TRACE_HANDLE};
use crate::native::{evntrace, version_helper};
use crate::provider::Provider;
use crate::provider::event_filter::EventFilterDescriptor;
use crate::{provider, utils};
use crate::schema_locator::SchemaLocator;
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
    events_handled: AtomicUsize,
    /// List of Providers associated with the Trace
    providers: Vec<provider::Provider>,
    schema_locator: SchemaLocator,
    // buffers_read : isize
}

impl TraceData {
    fn new() -> Self {
        let name = format!("n4r1b-trace-{}", utils::rand_string());
        TraceData {
            name,
            events_handled: AtomicUsize::new(0),
            properties: TraceProperties::default(),
            providers: Vec::new(),
            schema_locator: SchemaLocator::new(),
        }
    }

    /// How many events have been handled so far
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    // TODO: Should be void???
    fn insert_provider(&mut self, provider: provider::Provider) {
        self.providers.push(provider);
    }

    pub(crate) fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);

        // We need a mutable reference to be able to modify the data it refers, which is actually
        // done within the Callback (The schema locator is modified)
        for prov in &self.providers {
            // We can unwrap safely, provider builder wouldn't accept a provider without guid
            // so we must have Some(Guid)
            if prov.guid.unwrap() == record.provider_id() {
                prov.on_event(record, &self.schema_locator);
            }
        }
    }
}

/// Base trait for a Trace
///
/// This trait define the general methods required to control an ETW Session
pub trait TraceBaseTrait {
    /// Internal function to set TraceName. See [TraceTrait::named]
    fn set_trace_name(&mut self, name: &str);
    /// Sets the ETW session configuration properties
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::trace::{UserTrace, TraceProperties, TraceBaseTrait};
    /// let mut props = TraceProperties::default();
    /// props.flush_timer = 60;
    /// let my_trace = UserTrace::new().set_trace_properties(props);
    /// ```
    fn set_trace_properties(self, props: TraceProperties) -> Self;
    /// Enables a [Provider] for the Trace
    ///
    /// # Remarks
    /// Multiple providers can be enabled for the same trace, as long as they are from the same CPU privilege
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::trace::{UserTrace, TraceBaseTrait};
    /// # use ferrisetw::provider::Provider;
    /// let provider = Provider::new()
    ///     .by_name(String::from("Microsoft-Windows-DistributedCOM"))
    ///     .add_callback(|record, schema| { println!("{}", record.process_id()); })
    ///     .build()
    ///     .unwrap();
    /// let my_trace = UserTrace::new().enable(provider);
    /// ```
    fn enable(self, provider: provider::Provider) -> Self;
    /// Opens a Trace session
    fn open(self) -> TraceResult<Self>
    where
        Self: Sized;
    /// Starts a Trace session (which includes `open`ing and `process`ing  the trace)
    ///
    /// # Note
    /// This function will spawn a new thread, ETW blocks the thread listening to events, so we need
    /// a new thread to which delegate this process.
    fn start(self) -> TraceResult<Self>
    where
        Self: Sized;
    /// Start processing a Trace session
    ///
    /// # Note
    /// This function will spawn the new thread which starts listening for events.
    ///
    /// See [ProcessTrace](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace#remarks)
    fn process(self) -> TraceResult<Self>
    where
        Self: Sized;
    /// Stops a Trace session
    ///
    /// # Note
    /// Since a call to `start` will block thread and in case we want to execute it within a thread
    /// we would -- for now -- have to move it to the context of the new thread, this function is
    /// called from the [Drop] implementation.
    ///
    /// This function will log if it fails
    fn stop(&mut self);
}

// Hyper Macro to create an impl of the BaseTrace for the Kernel and User Trace
macro_rules! impl_base_trace {
    (for $($t: ty),+) => {
        $(impl TraceBaseTrait for $t {
            fn set_trace_name(&mut self, name: &str) {
                self.data.name = name.to_string();
            }

            fn set_trace_properties(mut self, props: TraceProperties) -> Self {
                self.data.properties = props;
                self
            }

            // TODO: Check if provider is built before inserting
            fn enable(mut self, provider: provider::Provider) -> Self {
                if provider.guid.is_none() {
                    panic!("Can't enable Provider with no GUID");
                }
                self.data.insert_provider(provider);
                self
            }

            fn open(mut self) -> TraceResult<Self> {
                self.data.events_handled.store(0, Ordering::Relaxed);

                // Populate self.info
                self.etw.fill_info::<$t>(&self.data.name, &self.data.properties, &self.data.providers);
                // Call StartTrace(..., self.info.properties)
                self.etw.register_trace(&self.data)?;
                // Call EnableTraceEx2 for each provider
                <$t>::enable_provider(&self);
                self.etw.open(&self.data)?;

                Ok(self)
            }

            fn start(mut self) -> TraceResult<Self> {
                self.data.events_handled.store(0, Ordering::Relaxed);

                if let Err(err) = self.etw.start() {
                    match err {
                        evntrace::EvntraceNativeError::InvalidHandle => {
                            return self.open()?.process();
                        },
                        _=> return Err(TraceError::EtwNativeError(err)),
                    };
                };
                Ok(self)
            }

            fn stop(&mut self)  {
                if let Err(err) = self.etw.stop(&self.data) {
                    println!("Error stopping trace: {:?}", err);
                }
            }

            fn process(mut self) -> TraceResult<Self> {
                self.data.events_handled.store(0, Ordering::Relaxed);
                self.etw.process()?;

                Ok(self)
            }

            // query_stats
            // set_default_event_callback
            // buffers_processed
        })*
    }
}

/// User Trace struct
#[derive(Debug)]
pub struct UserTrace {
    // This is `Box`ed so that it does not move around the stack in case the `UserTrace` is moved
    // This is important, because we give a pointer to it to Windows, so that it passes it back to us on callbacks
    data: Box<TraceData>,
    etw: evntrace::NativeEtw,
}

/// Kernel Trace struct
#[derive(Debug)]
pub struct KernelTrace {
    // This is `Box`ed so that it does not move around the stack in case the `UserTrace` is moved
    // This is important, because we give a pointer to it to Windows, so that it passes it back to us on callbacks
    data: Box<TraceData>,
    etw: evntrace::NativeEtw,
}

impl_base_trace!(for UserTrace, KernelTrace);

/// Specific trait for a Trace
///
/// This trait defines the specific methods that differentiate from a Kernel to a User Trace
pub trait TraceTrait: TraceBaseTrait {
    /// Set the trace name
    ///
    /// # Remarks
    /// If this function is not called during the process of building the trace a random name will be generated
    fn named(self, name: String) -> Self;
    fn enable_provider(&self) {}
    fn augmented_file_mode() -> u32 {
        0
    }
    fn enable_flags(_providers: &[Provider]) -> u32 {
        0
    }
    fn trace_guid() -> GUID {
        GUID::new().unwrap_or(GUID::zeroed())
    }
}

impl UserTrace {
    /// Create a UserTrace builder
    pub fn new() -> Self {
        let data = Box::new(TraceData::new());
        UserTrace {
            data,
            etw: evntrace::NativeEtw::new(),
        }
    }
}

impl KernelTrace {
    /// Create a KernelTrace builder
    pub fn new() -> Self {
        let data = Box::new(TraceData::new());

        let mut kt = KernelTrace {
            data,
            etw: evntrace::NativeEtw::new(),
        };

        if !version_helper::is_win8_or_greater() {
            kt.set_trace_name(KERNEL_LOGGER_NAME);
        }

        kt
    }
}

impl TraceTrait for UserTrace {
    /// See [TraceTrait::named]
    fn named(mut self, name: String) -> Self {
        if !name.is_empty() {
            self.set_trace_name(&name);
        }

        self
    }

    // TODO: Should this fail???
    // TODO: Add option to enable same provider twice with different flags
    #[allow(unused_must_use)]
    fn enable_provider(&self) {
        for prov in &self.data.providers {
            // Should always be Some but just in case
            if let Some(prov_guid) = prov.guid {

                let owned_event_filter_descriptors: Vec<EventFilterDescriptor> = prov.filters()
                    .iter()
                    .filter_map(|filter| filter.to_event_filter_descriptor().ok()) // Silently ignoring invalid filters (basically, empty ones)
                    .collect();

                let parameters =
                    EnableTraceParameters::create(prov_guid, prov.trace_flags, &owned_event_filter_descriptors);

                // Fixme: return error if this fails
                self.etw.enable_trace(
                    prov_guid,
                    prov.any,
                    prov.all,
                    prov.level,
                    parameters,
                );
            }
        }
    }
}

// TODO: Implement enable_provider function for providers that require call to TraceSetInformation with extended PERFINFO_GROUPMASK
impl TraceTrait for KernelTrace {
    /// See [TraceTrait::named]
    ///
    /// # Remarks
    /// On Windows Versions older than Win8 this method won't change the trace name. In those versions the trace name need to be set to "NT Kernel Logger", that's handled by the module
    fn named(mut self, name: String) -> Self {
        if !name.is_empty() && version_helper::is_win8_or_greater() {
            self.set_trace_name(&name);
        }
        self
    }

    fn augmented_file_mode() -> u32 {
        if version_helper::is_win8_or_greater() {
            EVENT_TRACE_SYSTEM_LOGGER_MODE
        } else {
            0
        }
    }

    fn enable_flags(providers: &[Provider]) -> u32 {
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

/// On drop the ETW session will be stopped if not stopped before
// TODO: log if it fails??
#[allow(unused_must_use)]
impl Drop for UserTrace {
    fn drop(&mut self) {
        if self.etw.session_handle() != INVALID_TRACE_HANDLE {
            self.stop();
        }
    }
}

/// On drop the ETW session will be stopped if not stopped before
#[allow(unused_must_use)]
impl Drop for KernelTrace {
    fn drop(&mut self) {
        if self.etw.session_handle() != INVALID_TRACE_HANDLE {
            self.stop();
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
        let trace = UserTrace::new().set_trace_properties(prop);

        assert_eq!(trace.data.properties.buffer_size, 10);
        assert_eq!(trace.data.properties.min_buffer, 1);
        assert_eq!(trace.data.properties.max_buffer, 20);
        assert_eq!(trace.data.properties.flush_timer, 60);
        assert_eq!(trace.data.properties.log_file_mode, 5);
    }

    #[test]
    fn test_set_name() {
        let trace = UserTrace::new().named(String::from("TestName"));

        assert_eq!(trace.data.name, "TestName");
    }

    #[test]
    fn test_enable_multiple_providers() {
        let prov = Provider::new().by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
        let prov1 = Provider::new().by_guid("A0C1853B-5C40-4B15-8766-3CF1C58F985A");

        let trace = UserTrace::new().enable(prov).enable(prov1);

        assert_eq!(trace.data.providers.len(), 2);
    }

    #[test]
    #[should_panic(expected = "Can't enable Provider with no GUID")]
    fn test_provider_no_guid_should_panic() {
        let prov = Provider::new();

        let trace = UserTrace::new().enable(prov);
    }
}
