//! ETW Event Property information
//!
//! The `property` module expose the basic structures that represent the `Properties` an Event contains,
//! based on its [`Schema`](crate::schema::Schema). These `Properties` can then be used to parse accordingly their values.
use crate::native::tdh_types::Property;

/// Event Property information
#[derive(Clone, Debug, Default)]
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
