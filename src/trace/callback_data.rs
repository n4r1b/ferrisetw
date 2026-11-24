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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::Arc;
    use windows::Win32::System::Diagnostics::Etw::{EVENT_HEADER, EVENT_RECORD};

    const PROVIDER_A: GUID = GUID::from_u128(0x0a0a0a0a_0000_0000_0000_00000000000a);
    const PROVIDER_B: GUID = GUID::from_u128(0x0b0b0b0b_0000_0000_0000_00000000000b);
    const MOF_EVENT_CLASS: GUID = GUID::from_u128(0x0c0c0c0c_0000_0000_0000_00000000000c);

    const CLASSIC_HEADER: u16 = Etw::EVENT_HEADER_FLAG_CLASSIC_HEADER as u16;
    const TRACE_MESSAGE: u16 = Etw::EVENT_HEADER_FLAG_TRACE_MESSAGE as u16;
    const HEADER_64_BIT: u16 = Etw::EVENT_HEADER_FLAG_64_BIT_HEADER as u16;

    fn record(provider_id: GUID, flags: u16) -> EventRecord {
        EventRecord(EVENT_RECORD {
            EventHeader: EVENT_HEADER {
                ProviderId: provider_id,
                Flags: flags,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    /// Builds callback data with one provider per GUID, returning how many times each one was invoked
    fn callback_data(
        trace_kind: TraceKind,
        guids: &[GUID],
    ) -> (RealTimeCallbackData, Vec<Arc<AtomicUsize>>) {
        let mut data = RealTimeCallbackData::new(trace_kind);
        let mut counters = Vec::new();
        for guid in guids {
            let counter = Arc::new(AtomicUsize::new(0));
            let c = Arc::clone(&counter);
            data.add_provider(
                Provider::by_guid(*guid)
                    .add_callback(move |_, _| {
                        c.fetch_add(1, Ordering::Relaxed);
                    })
                    .build(),
            );
            counters.push(counter);
        }
        (data, counters)
    }

    fn counts(counters: &[Arc<AtomicUsize>]) -> Vec<usize> {
        counters.iter().map(|c| c.load(Ordering::Relaxed)).collect()
    }

    fn no_lookup(_: &EventRecord) -> Option<GUID> {
        panic!("the schema must not be looked up for this event")
    }

    #[test]
    fn mof_classification() {
        assert!(is_mof(CLASSIC_HEADER));
        assert!(is_mof(CLASSIC_HEADER | HEADER_64_BIT));
        assert!(!is_mof(0));
        assert!(!is_mof(HEADER_64_BIT));
        assert!(!is_mof(CLASSIC_HEADER | TRACE_MESSAGE));
    }

    #[test]
    fn all_registrations_of_a_guid_receive_manifest_events() {
        let (data, counters) = callback_data(TraceKind::User, &[PROVIDER_A, PROVIDER_A]);
        data.dispatch(&record(PROVIDER_A, HEADER_64_BIT), no_lookup);
        assert_eq!(counts(&counters), [1, 1]);
    }

    #[test]
    fn all_registrations_of_a_guid_receive_mof_events() {
        let (data, counters) = callback_data(TraceKind::User, &[PROVIDER_A, PROVIDER_A]);
        data.dispatch(&record(MOF_EVENT_CLASS, CLASSIC_HEADER), |_| {
            Some(PROVIDER_A)
        });
        assert_eq!(counts(&counters), [1, 1]);
    }

    #[test]
    fn mof_event_is_routed_by_schema_provider_guid() {
        let (data, counters) = callback_data(TraceKind::User, &[PROVIDER_A, PROVIDER_B]);
        data.dispatch(&record(MOF_EVENT_CLASS, CLASSIC_HEADER), |_| {
            Some(PROVIDER_A)
        });
        assert_eq!(counts(&counters), [1, 0]);
    }

    #[test]
    fn non_mof_events_are_routed_by_header_without_schema_lookup() {
        let (data, counters) = callback_data(TraceKind::User, &[PROVIDER_A, PROVIDER_B]);
        // Manifest-based and TraceLogging events alike have no classic header
        data.dispatch(&record(PROVIDER_A, 0), no_lookup);
        data.dispatch(&record(PROVIDER_A, HEADER_64_BIT), no_lookup);
        // WPP events have a classic header, but are not MOF events
        data.dispatch(
            &record(PROVIDER_B, CLASSIC_HEADER | TRACE_MESSAGE),
            no_lookup,
        );
        assert_eq!(counts(&counters), [2, 1]);
    }

    #[test]
    fn mof_event_falls_back_to_header_when_schema_lookup_fails() {
        let (data, counters) = callback_data(TraceKind::User, &[PROVIDER_A, PROVIDER_B]);
        let lookups = Cell::new(0);
        let failed_lookup = |_: &EventRecord| {
            lookups.set(lookups.get() + 1);
            None
        };
        data.dispatch(&record(PROVIDER_A, CLASSIC_HEADER), failed_lookup);
        data.dispatch(&record(MOF_EVENT_CLASS, CLASSIC_HEADER), failed_lookup);
        assert_eq!(lookups.get(), 2);
        assert_eq!(counts(&counters), [1, 0]);
    }

    #[test]
    fn mof_event_reaches_both_header_and_schema_providers() {
        let (data, counters) = callback_data(TraceKind::User, &[PROVIDER_A, PROVIDER_B]);
        data.dispatch(&record(PROVIDER_A, CLASSIC_HEADER), |_| Some(PROVIDER_B));
        assert_eq!(counts(&counters), [1, 1]);
    }

    #[test]
    fn mof_event_matching_header_and_schema_is_delivered_once() {
        let (data, counters) = callback_data(TraceKind::User, &[PROVIDER_A, PROVIDER_B]);
        data.dispatch(&record(PROVIDER_A, CLASSIC_HEADER), |_| Some(PROVIDER_A));
        assert_eq!(counts(&counters), [1, 0]);
    }

    #[test]
    fn kernel_events_are_routed_by_header_without_schema_lookup() {
        let (data, counters) = callback_data(TraceKind::Kernel, &[PROVIDER_A, PROVIDER_B]);
        data.dispatch(&record(PROVIDER_A, CLASSIC_HEADER), no_lookup);
        data.dispatch(&record(MOF_EVENT_CLASS, CLASSIC_HEADER), no_lookup);
        assert_eq!(counts(&counters), [1, 0]);
    }
}
