use std::sync::atomic::{AtomicUsize, Ordering};

use windows::Win32::System::Diagnostics::Etw;

use crate::native::etw_types::event_record::EventRecord;
use crate::provider::Provider;
use crate::schema_locator::SchemaLocator;

pub use crate::native::etw_types::LoggingMode;

/// Data used by callbacks when the trace is running
// NOTE: this structure is accessed in an unsafe block in a separate thread (see the `trace_callback_thunk` function)
//       Thus, this struct must not be mutated (outside of interior mutability and/or using Mutex and other synchronization mechanisms) when the associated trace is running.
#[derive(Debug, Default)]
pub struct CallbackData {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    /// List of Providers associated with the Trace. This also owns the callback closures and their state
    providers: Vec<Provider>,
    schema_locator: SchemaLocator,
}

impl CallbackData {
    pub fn new() -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            providers: Vec::new(),
            schema_locator: SchemaLocator::new(),
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

        // We need a mutable reference to be able to modify the data it refers, which is actually
        // done within the Callback (The schema locator is modified)
        for prov in &self.providers {
            if prov.guid() == record.provider_id() {
                prov.on_event(record, &self.schema_locator);
            }
        }
    }
}
