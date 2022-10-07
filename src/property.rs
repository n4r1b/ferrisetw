//! ETW Event Property information
//!
//! The `property` module expose the basic structures that represent the `Properties` an Event contains,
//! based on its [`Schema`](crate::schema::Schema). These `Properties` can then be used to parse accordingly their values.
use crate::native::tdh_types::Property;

/// A slice to the data of a `Property` for a given ETW record.
#[derive(Clone, Copy, Debug)]
pub struct PropertySlice<'property, 'record> {
    /// Property attributes
    pub property: &'property Property,
    /// Buffer with the Property data
    pub buffer: &'record [u8],
}
