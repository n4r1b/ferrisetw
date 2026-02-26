//! A way to cache and retrieve Schemas

use std::cell::UnsafeCell;
use std::sync::Arc;
use rustc_hash::FxHashMap;

use windows::core::GUID;

use crate::native::etw_types::event_record::EventRecord;
use crate::native::tdh;
use crate::native::tdh::TraceEventInfo;
use crate::schema::Schema;

/// Schema module errors
#[derive(Debug)]
pub enum SchemaError {
    /// Represents an internal [TdhNativeError]
    ///
    /// [TdhNativeError]: tdh::TdhNativeError
    TdhNativeError(tdh::TdhNativeError),
}

impl From<tdh::TdhNativeError> for SchemaError {
    fn from(err: tdh::TdhNativeError) -> Self {
        SchemaError::TdhNativeError(err)
    }
}

pub(crate) type SchemaResult<T> = Result<T, SchemaError>;

/// A way to group events that share the same [`Schema`]
///
/// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor):
/// > For manifest-based ETW, the combination Provider.DecodeGuid + Event.Id + Event.Version should uniquely identify an event,
/// > i.e. all events with the same DecodeGuid, Id, and Version should have the same set of fields with no changes in field names, field types, or field ordering.
#[derive(Debug, Eq, PartialEq, Hash)]
struct SchemaKey {
    provider: GUID,
    /// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor): A 16-bit number used to identify manifest-based events
    id: u16,
    /// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor): An 8-bit number used to specify the version of a manifest-based event.
    // The version indicates a revision to the definition of an event with a particular Id.
    // All events with a given Id should have similar semantics, but a change in version
    // can be used to indicate a minor modification of the event details, e.g. a change to
    // the type of a field or the addition of a new field.
    version: u8,

    // TODO: not sure why these ones are required in a SchemaKey. If they are, document why.
    //       note that krabsetw also uses these fields (without an explanation)
    //       however, krabsetw's `schema::operator==` do not use them to compare schemas for equality.
    //       see https://github.com/microsoft/krabsetw/issues/195
    opcode: u8,
    level: u8,
    //
    // From MS documentation `evntprov.h`
    // For manifest-free events (i.e. TraceLogging), Event.Id and Event.Version are not useful
    // and should be ignored. Use Event name, level, keyword, and opcode for event filtering and
    // identification.
    //
    event_name: String,
}

impl SchemaKey {
    pub fn new(event: &EventRecord) -> Self {
        SchemaKey {
            provider: event.provider_id(),
            id: event.event_id(),
            opcode: event.opcode(),
            version: event.version(),
            level: event.level(),
            event_name: event.event_name(),
        }
    }
}

/// Represents a cache of Schemas already located
///
/// This cache is implemented as a [HashMap] where the key is a combination of the following elements
/// of an [Event Record](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)
/// * EventHeader.ProviderId
/// * EventHeader.EventDescriptor.Id
/// * EventHeader.EventDescriptor.Opcode
/// * EventHeader.EventDescriptor.Version
/// * EventHeader.EventDescriptor.Level
///
/// Credits: [KrabsETW::schema_locator](https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/schema_locator.hpp).
/// See also the code of `SchemaKey` for more info
///
/// # Thread Safety
///
/// `SchemaLocator` is `Sync` by assertion: the schema cache is only ever accessed from
/// `trace_callback_thunk` (see `src/native/evntrace.rs`), which ETW's `ProcessTrace` guarantees
/// is called sequentially on a single thread. A `SchemaLocator` is never shared between two
/// trace sessions, so no two threads can race on the same instance.
///
/// `UnsafeCell` is used in place of `Mutex` because the lock was never contended — paying
/// atomic CAS overhead on every event for a guarantee that ETW already provides externally is
/// unnecessary.
#[derive(Default)]
pub struct SchemaLocator {
    schemas: UnsafeCell<FxHashMap<SchemaKey, Arc<Schema>>>,
}

// SAFETY: See the doc comment on `SchemaLocator` above.
unsafe impl Sync for SchemaLocator {}

impl std::fmt::Debug for SchemaLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The schema cache is only safely accessible from the ETW callback thread,
        // so we do not attempt to read it here.
        f.debug_struct("SchemaLocator").finish_non_exhaustive()
    }
}

impl SchemaLocator {
    pub(crate) fn new() -> Self {
        SchemaLocator {
            schemas: UnsafeCell::new(FxHashMap::default()),
        }
    }

    /// Retrieve the Schema of an ETW Event
    ///
    /// # Arguments
    /// * `event` - The [EventRecord] that's passed to the callback
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    /// };
    /// ```
    pub fn event_schema(&self, event: &EventRecord) -> SchemaResult<Arc<Schema>> {
        let key = SchemaKey::new(event);

        // SAFETY: `event_schema` is only called from `trace_callback_thunk` (see
        // `src/native/evntrace.rs`). ETW's `ProcessTrace` guarantees all callbacks for a given
        // session are delivered sequentially on a single thread, so no concurrent access to
        // this HashMap can occur. See also the `unsafe impl Sync` on `SchemaLocator`.
        let schemas = unsafe { &mut *self.schemas.get() };
        match schemas.get(&key) {
            Some(s) => Ok(Arc::clone(s)),
            None => {
                let tei = TraceEventInfo::build_from_event(event)?;
                let new_schema = Arc::from(Schema::new(tei));
                schemas.insert(key, Arc::clone(&new_schema));
                Ok(new_schema)
            }
        }
    }
}
