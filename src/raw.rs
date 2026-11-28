//! Opt-in raw QPC timestamps for newly created kernel traces.
//!
//! Raw event callbacks receive a distinct type, so they cannot accidentally call
//! `EventRecord::timestamp()` or serialize QPC ticks as wall-clock time.

use crate::provider::{kernel_providers::KernelProvider, Provider};
use crate::trace::{KernelStackEvent, KernelTrace, TraceBuilder};
use crate::EventRecord;
use windows::core::GUID;

/// An unconverted timestamp in the clock domain of a kernel trace.
///
/// This is not wall-clock time. Compare values only when their clock domain is
/// known to be the same, such as a sample and its StackWalk event in one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RawTimestamp(i64);

impl RawTimestamp {
    /// Construct a value from raw ticks, for example a StackWalk timestamp.
    pub const fn from_ticks(ticks: i64) -> Self {
        Self(ticks)
    }
    /// Return raw ticks without converting to a wall-clock time.
    pub const fn ticks(self) -> i64 {
        self.0
    }
}

/// An event from a newly created kernel session using raw QPC timestamps.
///
/// The session requests QPC timestamps; they are raw ticks, not FILETIME or Unix time. Values may be
/// compared only with timestamps from the same session and clock domain.
/// The underlying `EventRecord` is deliberately not exposed.
///
/// A raw timestamp is not an `OffsetDateTime`:
/// ```compile_fail
/// use ferrisetw::raw::RawTimestamp;
/// let ticks = RawTimestamp::from_ticks(42);
/// let _ = ticks.unix_timestamp();
/// ```
pub struct RawKernelEvent<'a> {
    record: &'a EventRecord,
    locator: &'a crate::schema_locator::SchemaLocator,
}

impl RawKernelEvent<'_> {
    /// The event class/provider GUID.
    pub fn provider_id(&self) -> GUID {
        self.record.provider_id()
    }
    /// The event identifier.
    pub fn event_id(&self) -> u16 {
        self.record.event_id()
    }
    /// The classic event opcode.
    pub fn opcode(&self) -> u8 {
        self.record.opcode()
    }
    /// The process ID from the event header.
    pub fn process_id(&self) -> u32 {
        self.record.process_id()
    }
    /// The thread ID from the event header.
    pub fn thread_id(&self) -> u32 {
        self.record.thread_id()
    }
    /// The unconverted QPC timestamp in ticks, not a wall-clock time.
    pub fn timestamp(&self) -> RawTimestamp {
        RawTimestamp(self.record.raw_timestamp())
    }
    /// Pointer width in bytes encoded by the event header.
    pub fn pointer_size(&self) -> usize {
        self.record.pointer_size()
    }
    /// Parse properties using the event schema without exposing a wall-clock event.
    /// Schema lookup can fail independently of the caller's parsing operation.
    pub fn with_parser<R>(
        &self,
        parse: impl FnOnce(&crate::parser::Parser<'_, '_>) -> R,
    ) -> Result<R, crate::schema_locator::SchemaError> {
        let schema = self.locator.event_schema(self.record)?;
        let parser = crate::parser::Parser::create(self.record, &schema);
        Ok(parse(&parser))
    }
    /// Event payload as reported by ETW. Its format depends on the event schema.
    /// Returns an empty slice if the payload pointer is null.
    pub fn user_data(&self) -> &[u8] {
        if self.record.0.UserDataLength == 0 || self.record.0.UserData.is_null() {
            &[]
        } else {
            self.record.user_buffer()
        }
    }
}

/// Builder for a new kernel trace whose callbacks receive unconverted timestamps from a QPC-configured session.
///
/// This deliberately cannot accept ordinary `Provider` callbacks: their
/// `EventRecord::timestamp()` expects system time. It does not open existing
/// sessions or ETL files, whose clock domains may differ.
///
/// Ordinary providers cannot be added to this builder:
/// ```compile_fail
/// use ferrisetw::provider::Provider;
/// use ferrisetw::trace::KernelTrace;
/// let provider = Provider::by_guid(0u128).build();
/// let _ = KernelTrace::new_raw().enable(provider);
/// ```
pub struct RawKernelTraceBuilder {
    inner: TraceBuilder<KernelTrace>,
}

impl KernelTrace {
    /// Create a kernel trace builder that delivers raw QPC events separately
    /// from the existing wall-clock `EventRecord` API.
    pub fn new_raw() -> RawKernelTraceBuilder {
        RawKernelTraceBuilder {
            inner: Self::new().with_raw_timestamps(),
        }
    }
}

impl RawKernelTraceBuilder {
    /// Set the name of the new trace.
    pub fn named(mut self, name: String) -> Self {
        self.inner = self.inner.named(name);
        self
    }
    /// Configure whether a same-named session is stopped before starting.
    pub fn stop_if_exist(mut self, stop: bool) -> Self {
        self.inner = self.inner.stop_if_exist(stop);
        self
    }
    /// Enable a standard kernel provider with a raw-event callback.
    pub fn enable_kernel<F>(mut self, provider: &KernelProvider, mut callback: F) -> Self
    where
        F: FnMut(&RawKernelEvent<'_>) + Send + Sync + 'static,
    {
        let provider = Provider::kernel(provider)
            .add_callback(move |record, locator| callback(&RawKernelEvent { record, locator }))
            .build();
        self.inner = self.inner.enable(provider);
        self
    }
    /// Enable a kernel provider requiring an extended group mask.
    pub fn enable_group_mask<F>(
        mut self,
        provider: &crate::provider::kernel_providers::KernelGroupMaskProvider,
        mut callback: F,
    ) -> Self
    where
        F: FnMut(&RawKernelEvent<'_>) + Send + Sync + 'static,
    {
        let provider = Provider::kernel_with_group_mask(provider)
            .add_callback(move |record, locator| callback(&RawKernelEvent { record, locator }))
            .build();
        self.inner = self.inner.enable(provider);
        self
    }
    /// Register a callback for a GUID, such as the separate StackWalk class.
    /// This does not itself enable kernel provider flags.
    pub fn enable_guid<G, F>(mut self, guid: G, mut callback: F) -> Self
    where
        G: Into<GUID>,
        F: FnMut(&RawKernelEvent<'_>) + Send + Sync + 'static,
    {
        let provider = Provider::by_guid(guid)
            .add_callback(move |record, locator| callback(&RawKernelEvent { record, locator }))
            .build();
        self.inner = self.inner.enable(provider);
        self
    }
    /// Configure call-stack capture for the given classic kernel events.
    pub fn stack_tracing(mut self, events: Vec<KernelStackEvent>) -> Self {
        self.inner = self.inner.stack_tracing(events);
        self
    }
    /// Start the owned trace and process its events on a background thread.
    pub fn start_and_process(self) -> Result<KernelTrace, crate::trace::TraceError> {
        self.inner.start_and_process()
    }
}
