//! ETW Event Schema and handler
//!
//! This module contains the means needed to interact with the Schema of an ETW event
use crate::native::etw_types::{DecodingSource, EventRecord, TraceEventInfoRaw};
use crate::native::tdh_types::Property;
use std::sync::Arc;

/// Represents an `EventRecord` along with its suitable Schema
///
/// It is usually built from [`crate::schema_locator::SchemaLocator::event_schema`].
///
/// This structure holds a [TraceEventInfo](https://docs.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info)
/// which let us obtain information from the ETW event.
pub struct Schema {
    record: EventRecord,
    te_info: Arc<TraceEventInfoRaw>,
}

impl Schema {
    pub(crate) fn new(record: &EventRecord, te_info: Arc<TraceEventInfoRaw>) -> Self {
        Schema { record: EventRecord::clone(record), te_info }
    }

    // This is temporary and will be removed in a later commit
    pub fn record(&self) -> &EventRecord {
        &self.record
    }

    /// Use the `decoding_source` function to obtain the [DecodingSource] from the [TraceEventInfo]
    ///
    /// This getter returns the DecodingSource from the event, this value identifies the source used
    /// parse the event data
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::native::etw_types::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;

    /// let my_callback = |record: &EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let decoding_source = schema.decoding_source();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn decoding_source(&self) -> DecodingSource {
        self.te_info.decoding_source()
    }

    /// Use the `provider_name` function to obtain the Provider name from the [TraceEventInfo]
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::native::etw_types::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let provider_name = schema.provider_name();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn provider_name(&self) -> String {
        self.te_info.provider_name()
    }

    /// Use the `task_name` function to obtain the Task name from the [TraceEventInfo]
    ///
    /// See: [TaskType](https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-tasktype-complextype)
    /// # Example
    /// ```
    /// # use ferrisetw::native::etw_types::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let task_name = schema.task_name();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn task_name(&self) -> String {
        self.te_info.task_name()
    }

    /// Use the `opcode_name` function to obtain the Opcode name from the [TraceEventInfo]
    ///
    /// See: [OpcodeType](https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-opcodetype-complextype)
    /// # Example
    /// ```
    /// # use ferrisetw::native::etw_types::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &mut SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let opcode_name = schema.opcode_name();
    /// };
    /// ```
    /// [TraceEventInfo]: crate::native::etw_types::TraceEventInfo
    pub fn opcode_name(&self) -> String {
        self.te_info.opcode_name()
    }

    pub(crate) fn property_count(&self) -> u32 {
        self.te_info.property_count()
    }

    pub(crate) fn property(&self, index: u32) -> Property {
        self.te_info.property(index)
    }
}

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool {
        self.te_info.event_id() == other.te_info.event_id()
            && self.te_info.provider_guid() == other.te_info.provider_guid()
            && self.te_info.event_version() == other.te_info.event_version()
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
