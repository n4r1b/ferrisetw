//! ETW Event Schema locator and handler
//!
//! This module contains the means needed to locate and interact with the Schema of an ETW event
use crate::native::etw_types::{DecodingSource, EventRecord, TraceEventInfoRaw};
use crate::native::tdh;
use crate::native::tdh_types::Property;
use std::collections::HashMap;
use std::sync::Arc;
use windows::core::GUID;

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
        let provider = format!("{:?}", event.EventHeader.ProviderId);
        SchemaKey {
            provider,
            id: event.EventHeader.EventDescriptor.Id,
            opcode: event.EventHeader.EventDescriptor.Opcode,
            version: event.EventHeader.EventDescriptor.Version,
            level: event.EventHeader.EventDescriptor.Level,
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
/// See also the [`SchemaKey`] for more info
#[derive(Default)]
pub struct SchemaLocator {
    schemas: HashMap<SchemaKey, Arc<TraceEventInfoRaw>>,
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
    /// # Remark
    /// This is the first function that should be called within a Provider callback.
    /// It consumes the ETW event and wrap it into a [Schema] that represents it
    /// and provides a way to access its fields.
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    /// };
    /// ```
    pub fn event_schema(&mut self, event: EventRecord) -> SchemaResult<Schema> {
        let key = SchemaKey::new(&event);
        let info: Arc<_>;

        if !self.schemas.contains_key(&key) {
            // TODO: Cloning for now, should be a reference at some point...
            info = Arc::from(tdh::schema_from_tdh(event)?);
            self.schemas.insert(key, Arc::clone(&info));
        } else {
            info = Arc::clone(self.schemas.get(&key).unwrap());
        }

        Ok(Schema::new(event, info))
    }
}

/// Represents an `EventRecord` along with its suitable Schema
///
/// It is usually built from [`SchemaLocator::event_schema`].
///
/// This structure holds a [TraceEventInfo](https://docs.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info)
/// which let us obtain information from the ETW event.
pub struct Schema {
    record: EventRecord,
    schema: Arc<TraceEventInfoRaw>,
}

impl Schema {
    pub(crate) fn new(record: EventRecord, schema: Arc<TraceEventInfoRaw>) -> Self {
        Schema { record, schema }
    }

    pub(crate) fn user_buffer(&self) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                self.record.UserData as *mut _,
                self.record.UserDataLength.into(),
            )
            .to_vec()
        }
    }

    // Horrible getters FTW!! :D
    // TODO: Not a big fan of this, think a better way..
    pub(crate) fn record(&self) -> EventRecord {
        self.record
    }

    /// Return the EventId of the ETW Event that triggered the registered callback
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let event_id = schema.event_id();
    /// };
    /// ```
    pub fn event_id(&self) -> u16 {
        self.record.EventHeader.EventDescriptor.Id
    }

    /// Return the opcode of the ETW Event that triggered the registered callback
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let event_id = schema.opcode();
    /// };
    /// ```
    pub fn opcode(&self) -> u8 {
        self.record.EventHeader.EventDescriptor.Opcode
    }

    /// Returns the Event Flags of the ETW Event that triggered the registered callback
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let event_flags = schema.event_flags();
    /// };
    /// ```
    pub fn event_flags(&self) -> u16 {
        self.record.EventHeader.Flags
    }

    /// Returns the Version of the ETW Event that triggered the registered callback
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let event_version = schema.event_version();
    /// };
    /// ```
    pub fn event_version(&self) -> u8 {
        self.record.EventHeader.EventDescriptor.Version
    }

    /// Returns the ProcessId of the process that triggered the ETW Event
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let pid = schema.process_id();
    /// };
    /// ```
    pub fn process_id(&self) -> u32 {
        self.record.EventHeader.ProcessId
    }

    /// Returns the ThreadId of the thread that triggered the ETW Event
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let tid = schema.thread_id();
    /// };
    /// ```
    pub fn thread_id(&self) -> u32 {
        self.record.EventHeader.ThreadId
    }

    /// Returns the TimeStamp of the ETW Event
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let timestamp = schema.timestamp();
    /// };
    /// ```
    pub fn timestamp(&self) -> i64 {
        self.record.EventHeader.TimeStamp
    }

    /// Returns the ActivityId from the ETW Event, this value is used to related Two events
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let activity_id = schema.activity_id();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn activity_id(&self) -> GUID {
        self.record.EventHeader.ActivityId
    }

    /// Use the `decoding_source` function to obtain the [DecodingSource] from the [TraceEventInfo]
    ///
    /// This getter returns the DecodingSource from the event, this value identifies the source used
    /// parse the event data
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let decoding_source = schema.decoding_source();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn decoding_source(&self) -> DecodingSource {
        self.schema.decoding_source()
    }

    /// Use the `provider_name` function to obtain the Provider name from the [TraceEventInfo]
    ///
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let provider_name = schema.provider_name();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn provider_name(&self) -> String {
        self.schema.provider_name()
    }

    /// Use the `task_name` function to obtain the Task name from the [TraceEventInfo]
    ///
    /// See: [TaskType](https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-tasktype-complextype)
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let task_name = schema.task_name();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn task_name(&self) -> String {
        self.schema.task_name()
    }

    /// Use the `opcode_name` function to obtain the Opcode name from the [TraceEventInfo]
    ///
    /// See: [OpcodeType](https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-opcodetype-complextype)
    /// # Example
    /// ```rust
    /// let my_callback = |record: EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record)?;
    ///     let opcode_name = schema.opcode_name();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn opcode_name(&self) -> String {
        self.schema.opcode_name()
    }

    pub(crate) fn property_count(&self) -> u32 {
        self.schema.property_count()
    }

    pub(crate) fn property(&self, index: u32) -> Property {
        self.schema.property(index)
    }
}

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool {
        self.schema.event_id() == other.schema.event_id()
            && self.schema.provider_guid() == other.schema.provider_guid()
            && self.schema.event_version() == other.schema.event_version()
    }
}

impl Eq for Schema {}

#[cfg(test)]
mod test {
    use super::*;

    fn test_getters() {
        todo!()
    }

    fn test_schema_key() {
        todo!()
    }
}
