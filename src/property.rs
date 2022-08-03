//! ETW Event Property information
//!
//! The `property` module expose the basic structures that represent the `Properties` an Event contains,
//! based on its [`Schema`](crate::schema::Schema). These `Properties` can then be used to parse accordingly their values.
use crate::native::tdh_types::Property;
use crate::schema::Schema;

/// Event Property information
#[derive(Clone, Default)]
pub struct PropertyInfo {
    /// Property attributes
    pub property: Property,
    /// Buffer with the Property data
    pub buffer: Vec<u8>,
}

impl PropertyInfo {
    pub fn create(property: Property, buffer: Vec<u8>) -> Self {
        PropertyInfo { property, buffer }
    }
}

pub(crate) struct PropertyIter {
    properties: Vec<Property>,
}

impl PropertyIter {
    fn enum_properties(schema: &Schema, prop_count: u32) -> Vec<Property> {
        let mut properties = Vec::new();
        for i in 0..prop_count {
            properties.push(schema.property(i));
        }
        properties
    }

    pub fn new(schema: &Schema) -> Self {
        let prop_count = schema.property_count();
        let properties = PropertyIter::enum_properties(schema, prop_count);

        PropertyIter { properties }
    }

    pub fn property(&self, index: u32) -> Option<&Property> {
        self.properties.get(index as usize)
    }

    pub fn properties_iter(&self) -> &[Property] {
        &self.properties
    }
}
