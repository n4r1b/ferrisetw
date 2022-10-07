//! A way to cache and retrieve Schemas

use std::collections::HashMap;
use std::sync::Arc;

use crate::native::tdh;
use crate::native::tdh::TraceEventInfo;
use crate::native::etw_types::EventRecord;
use crate::schema::Schema;

/// Schema module errors
#[derive(Debug)]
pub enum SchemaError {
    /// Represents a Parser error
    ParseError,
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

type SchemaResult<T> = Result<T, SchemaError>;

/// A way to group events that share the same [`Schema`]
///
/// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor):
/// > For manifest-based ETW, the combination Provider.DecodeGuid + Event.Id + Event.Version should uniquely identify an event,
/// > i.e. all events with the same DecodeGuid, Id, and Version should have the same set of fields with no changes in field names, field types, or field ordering.
#[derive(Debug, Eq, PartialEq, Hash)]
struct SchemaKey {
    // For now, lazy to wrap Guid around an implement Hash
    // TODO: wrap Guid and implement hash
    provider: String,
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
}

impl SchemaKey {
    pub fn new(event: &EventRecord) -> Self {
        let provider = format!("{:?}", event.provider_id());
        SchemaKey {
            provider,
            id: event.event_id(),
            opcode: event.opcode(),
            version: event.version(),
            level: event.level(),
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
#[derive(Default)]
pub struct SchemaLocator {
    schemas: HashMap<SchemaKey, Arc<TraceEventInfo>>,
}

impl std::fmt::Debug for SchemaLocator {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl SchemaLocator {
    pub(crate) fn new() -> Self {
        SchemaLocator {
            schemas: HashMap::new(),
        }
    }

    /// Retrieve the Schema of an ETW Event
    ///
    /// # Arguments
    /// * `event` - The [EventRecord] that's passed to the callback
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::native::etw_types::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    /// };
    /// ```
    pub fn event_schema(&mut self, event: &EventRecord) -> SchemaResult<Schema> {
        let key = SchemaKey::new(event);
        let info: Arc<_>;

        if !self.schemas.contains_key(&key) {
            // TODO: Cloning for now, should be a reference at some point...
            info = Arc::from(TraceEventInfo::build_from_event(event)?);
            self.schemas.insert(key, Arc::clone(&info));
        } else {
            info = Arc::clone(self.schemas.get(&key).unwrap());
        }

        Ok(Schema::new(info))
    }
}