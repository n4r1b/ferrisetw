//! ETW Providers abstraction.
//!
//! Provides an abstraction over an [ETW Provider](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing#providers)
use super::traits::*;
use crate::native::etw_types::EventRecord;
use crate::native::pla;
use crate::schema_locator::SchemaLocator;

use std::sync::{Arc, RwLock};
use windows::core::GUID;

pub(crate) mod event_filter;
pub use event_filter::EventFilter;

pub mod kernel_providers;
mod trace_flags;
pub use trace_flags::TraceFlags;

/// Provider module errors
#[derive(Debug)]
pub enum ProviderError {
    /// Returned whenever a provider doesn't have an associated GUID
    NoGuid,
    /// Wrapper over an internal [PlaError]
    ///
    /// [PlaError]: crate::native::pla::PlaError
    ComProvider(pla::PlaError),
    /// Wrapper over an standard IO Error
    IoError(std::io::Error),
}

impl LastOsError<ProviderError> for ProviderError {}

impl From<std::io::Error> for ProviderError {
    fn from(err: std::io::Error) -> Self {
        ProviderError::IoError(err)
    }
}

impl From<pla::PlaError> for ProviderError {
    fn from(err: pla::PlaError) -> Self {
        ProviderError::ComProvider(err)
    }
}

type EtwCallback = Box<dyn FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static>;

/// Describes an ETW Provider to use, along with its options
pub struct Provider {
    /// Provider GUID
    guid: GUID,
    /// Provider Any keyword
    any: u64,
    /// Provider All keyword
    all: u64,
    /// Provider level flag
    level: u8,
    /// Provider trace flags
    ///
    /// Used as `EnableParameters.EnableProperty` when starting the trace (using [EnableTraceEx2](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2))
    trace_flags: TraceFlags,
    /// Provider kernel flags, only apply to KernelProvider
    kernel_flags: u32,
    /// Provider filters
    filters: Vec<EventFilter>,
    /// Callbacks that will receive events from this Provider
    callbacks: Arc<RwLock<Vec<EtwCallback>>>,
}

/// A Builder for a `Provider`
///
/// See [`Provider`] for various functions that create `ProviderBuilder`s.
pub struct ProviderBuilder {
    guid: GUID,
    any: u64,
    all: u64,
    level: u8,
    trace_flags: TraceFlags,
    kernel_flags: u32,
    filters: Vec<EventFilter>,
    callbacks: Arc<RwLock<Vec<EtwCallback>>>,
}

impl std::fmt::Debug for ProviderBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderBuilder")
            .field("guid", &self.guid)
            .field("any", &self.any)
            .field("all", &self.all)
            .field("level", &self.level)
            .field("trace_flags", &self.trace_flags)
            .field("kernel_flags", &self.kernel_flags)
            .field("filters", &self.filters)
            .field("n_callbacks", &self.callbacks.read().unwrap().len())
            .finish()
    }
}

// Create builders
impl Provider {
    /// Create a Provider defined by its GUID
    ///
    /// Many types [implement `Into<GUID>`](https://microsoft.github.io/windows-docs-rs/doc/windows/core/struct.GUID.html#trait-implementations)
    /// and are acceptable as argument: `GUID` themselves, but also `&str`, etc.
    pub fn by_guid<G: Into<GUID>>(guid: G) -> ProviderBuilder {
        ProviderBuilder {
            guid: guid.into(),
            any: 0,
            all: 0,
            level: 5,
            trace_flags: TraceFlags::empty(),
            kernel_flags: 0,
            filters: Vec::new(),
            callbacks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a Kernel Provider
    pub fn kernel(kernel_provider: &kernel_providers::KernelProvider) -> ProviderBuilder {
        let mut builder = Self::by_guid(kernel_provider.guid);
        builder.kernel_flags = kernel_provider.flags;
        builder
    }

    /// Create a Provider defined by its name.
    ///
    /// This function will look for the Provider GUID by means of the [ITraceDataProviderCollection](https://docs.microsoft.com/en-us/windows/win32/api/pla/nn-pla-itracedataprovidercollection)
    /// interface.
    ///
    /// # Remark
    /// This function is considerably slow, prefer using the `by_guid` function when possible
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// let my_provider = Provider::by_name("Microsoft-Windows-WinINet").unwrap().build();
    /// ```
    pub fn by_name(name: &str) -> Result<ProviderBuilder, pla::PlaError> {
        let guid = unsafe { pla::get_provider_guid(name) }?;
        Ok(Self::by_guid(guid))
    }
}

// Actually use the Provider
impl Provider {
    pub fn guid(&self) -> GUID {
        self.guid
    }
    pub fn any(&self) -> u64 {
        self.any
    }
    pub fn all(&self) -> u64 {
        self.all
    }
    pub fn level(&self) -> u8 {
        self.level
    }
    pub fn trace_flags(&self) -> TraceFlags {
        self.trace_flags
    }
    pub fn kernel_flags(&self) -> u32 {
        self.kernel_flags
    }
    pub fn filters(&self) -> &[EventFilter] {
        &self.filters
    }

    pub(crate) fn on_event(&self, record: &EventRecord, locator: &SchemaLocator) {
        if let Ok(mut callbacks) = self.callbacks.write() {
            callbacks.iter_mut().for_each(|cb| cb(record, locator))
        };
    }
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
         .field("guid", &self.guid)
         .field("any", &self.any)
         .field("all", &self.all)
         .field("level", &self.level)
         .field("trace_flags", &self.trace_flags)
         .field("kernel_flags", &self.kernel_flags)
         .field("filters", &self.filters)
         .field("callbacks", &self.callbacks.read().unwrap().len())
         .finish()
    }
}

impl ProviderBuilder {
    /// Set the `any` flag in the Provider instance
    /// [More info](https://docs.microsoft.com/en-us/message-analyzer/system-etw-provider-event-keyword-level-settings#filtering-with-system-etw-provider-event-keywords-and-levels)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// let my_provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F").any(0xf0010000000003ff).build();
    /// ```
    pub fn any(mut self, any: u64) -> Self {
        self.any = any;
        self
    }

    /// Set the `all` flag in the Provider instance
    /// [More info](https://docs.microsoft.com/en-us/message-analyzer/system-etw-provider-event-keyword-level-settings#filtering-with-system-etw-provider-event-keywords-and-levels)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// let my_provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F").all(0x4000000000000000).build();
    /// ```
    pub fn all(mut self, all: u64) -> Self {
        self.all = all;
        self
    }

    /// Set the `level` flag in the Provider instance
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::{Provider};
    /// // LogAlways (0x0)
    /// // Critical (0x1)
    /// // Error (0x2)
    /// // Warning (0x3)
    /// // Information (0x4)
    /// // Verbose (0x5)
    /// let my_provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F").level(0x5).build();
    /// ```
    pub fn level(mut self, level: u8) -> Self {
        self.level = level;
        self
    }

    /// Set the `trace_flags` flag in the Provider instance
    /// [More info](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-flags)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::{Provider, TraceFlags};
    /// let my_provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F").trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_SID).build();
    /// ```
    pub fn trace_flags(mut self, trace_flags: TraceFlags) -> Self {
        self.trace_flags = trace_flags;
        self
    }

    /// Add a callback function that will be called when the Provider generates an Event
    ///
    /// # Notes
    ///
    /// The callback will be run on a background thread (the one that is blocked on the `process` function).
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// # use ferrisetw::trace::UserTrace;
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F").add_callback(|record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     // Handle Event
    /// }).build();
    /// UserTrace::new().enable(provider).start().unwrap();
    /// ```
    ///
    /// [SchemaLocator]: crate::schema_locator::SchemaLocator
    pub fn add_callback<T>(self, callback: T) -> Self
    where
        T: FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static,
    {
        if let Ok(mut callbacks) = self.callbacks.write() {
            callbacks.push(Box::new(callback));
        }
        self
    }

    /// Add a filter to this Provider.
    ///
    /// Adding multiple filters will bind them with an `AND` relationship.<br/>
    /// If you want an `OR` relationship, include them in the same `EventFilter`.
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::{EventFilter, Provider};
    /// let only_events_18_or_42 = EventFilter::ByEventIds(vec![18, 42]);
    /// let only_pid_1234 = EventFilter::ByPids(vec![1234]);
    ///
    /// Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
    ///     .add_filter(only_events_18_or_42)
    ///     .add_filter(only_pid_1234)
    ///     .build();
    /// ```
    pub fn add_filter(mut self, filter: EventFilter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Build the provider
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// # let process_callback = |_event: &EventRecord, _locator: &SchemaLocator| {};
    /// Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
    ///   .add_callback(process_callback)
    ///   .build();
    /// ```
    // TODO: should we check if callbacks is empty ???
    pub fn build(self) -> Provider {
        Provider {
            guid: self.guid,
            any: self.any,
            all: self.all,
            level: self.level,
            trace_flags: self.trace_flags,
            kernel_flags: self.kernel_flags,
            filters: self.filters,
            callbacks: self.callbacks,
        }
    }
}
