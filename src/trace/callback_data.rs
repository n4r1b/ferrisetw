use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw;

use crate::native::etw_types::event_record::EventRecord;
use crate::provider::Provider;
use crate::schema_locator::SchemaLocator;
use crate::trace::{RealTimeTraceTrait, TraceKind};
use crate::EtwCallback;

/// Data used by callbacks when the trace is running
// NOTE: this structure is accessed in an unsafe block in a separate thread (see the `trace_callback_thunk` function)
//       Thus, this struct must not be mutated (outside of interior mutability and/or using Mutex and other synchronization mechanisms) when the associated trace is running.
#[derive(Debug)]
pub enum CallbackData {
    RealTime(RealTimeCallbackData),
    FromFile(CallbackDataFromFile),
}

#[derive(Debug)]
pub struct RealTimeCallbackData {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    schema_locator: SchemaLocator,
    /// List of Providers associated with the Trace. This also owns the callback closures and their state
    providers: Vec<Provider>,
    trace_kind: TraceKind,
}

pub struct CallbackDataFromFile {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    schema_locator: SchemaLocator,
    /// This trace is reading from an ETL file, and has a single callback
    callback: RwLock<EtwCallback>,
}

impl CallbackData {
    pub fn on_event(&self, record: &EventRecord) {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.on_event(record),
            CallbackData::FromFile(f_cb) => f_cb.on_event(record),
        }
    }

    pub fn events_handled(&self) -> usize {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.events_handled(),
            CallbackData::FromFile(f_cb) => f_cb.events_handled(),
        }
    }
}

/// Whether an event was logged by a classic (MOF) provider.
///
/// Like krabsetw, this only looks at the event header, so that manifest and TraceLogging events
/// never need a schema lookup to be dispatched.
/// WPP events also carry a classic header, but are told apart by `EVENT_HEADER_FLAG_TRACE_MESSAGE`.
fn is_mof(flags: u16) -> bool {
    const CLASSIC_HEADER: u16 = Etw::EVENT_HEADER_FLAG_CLASSIC_HEADER as u16;
    const TRACE_MESSAGE: u16 = Etw::EVENT_HEADER_FLAG_TRACE_MESSAGE as u16;
    flags & CLASSIC_HEADER != 0 && flags & TRACE_MESSAGE == 0
}

impl RealTimeCallbackData {
    pub fn new(trace_kind: TraceKind) -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            schema_locator: SchemaLocator::new(),
            providers: Vec::new(),
            trace_kind,
        }
    }

    pub fn add_provider(&mut self, provider: Provider) {
        self.providers.push(provider)
    }

    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    /// How many events have been handled since this instance was created
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    pub fn provider_flags<T: RealTimeTraceTrait>(&self) -> Etw::EVENT_TRACE_FLAG {
        Etw::EVENT_TRACE_FLAG(T::enable_flags(&self.providers))
    }

    pub fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);
        self.dispatch(record, |record| {
            self.schema_locator
                .event_schema(record)
                .ok()
                .map(|schema| schema.provider_guid())
        });
    }

    /// Invokes every provider registered for this event.
    ///
    /// A provider matches when its GUID is the one in the event header.
    /// For MOF events in user traces, the header holds the event class GUID rather than the provider GUID,
    /// so providers whose GUID is the provider GUID of the event schema (as given by `resolve_schema_provider`) match as well.
    /// Each matching provider is invoked once.
    pub(crate) fn dispatch(
        &self,
        record: &EventRecord,
        resolve_schema_provider: impl FnOnce(&EventRecord) -> Option<GUID>,
    ) {
        let header_guid = record.provider_id();
        let schema_guid = if self.trace_kind == TraceKind::User && is_mof(record.event_flags()) {
            resolve_schema_provider(record)
        } else {
            None
        };

        for prov in &self.providers {
            if prov.guid() == header_guid || Some(prov.guid()) == schema_guid {
                prov.on_event(record, &self.schema_locator);
            }
        }
    }
}

impl CallbackDataFromFile {
    pub fn new(callback: EtwCallback) -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            schema_locator: SchemaLocator::new(),
            callback: RwLock::new(callback),
        }
    }

    /// How many events have been handled since this instance was created
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    pub fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut cb) = self.callback.write() {
            cb(record, &self.schema_locator);
        }
    }
}

impl std::fmt::Debug for CallbackDataFromFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackDataFromFile")
            .field("events_handled", &self.events_handled)
            .field("schema_locator", &self.schema_locator)
            .finish()
    }
}
