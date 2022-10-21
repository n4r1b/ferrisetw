//! ETW Types Parser
//!
//! This module act as a helper to parse the Buffer from an ETW Event
use crate::native::etw_types::EVENT_HEADER_FLAG_32_BIT_HEADER;
use crate::native::etw_types::EventRecord;
use crate::native::sddl;
use crate::native::tdh;
use crate::native::tdh_types::{Property, PropertyFlags, TdhInType, TdhOutType};
use crate::property::PropertySlice;
use crate::schema::Schema;
use crate::utils;
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use windows::core::GUID;

/// Parser module errors
#[derive(Debug)]
pub enum ParserError {
    /// No property has this name
    NotFound,
    /// An invalid type...
    InvalidType,
    /// Error parsing
    ParseError,
    /// Length mismatch when parsing a type
    LengthMismatch,
    PropertyError(String),
    /// An error while transforming an Utf-8 buffer into String
    Utf8Error(std::string::FromUtf8Error),
    /// An error trying to get an slice as an array
    SliceError(std::array::TryFromSliceError),
    /// Represents an internal [SddlNativeError]
    ///
    /// [SddlNativeError]: sddl::SddlNativeError
    SddlNativeError(sddl::SddlNativeError),
    /// Represents an internal [TdhNativeError]
    ///
    /// [TdhNativeError]: tdh::TdhNativeError
    TdhNativeError(tdh::TdhNativeError),
}

impl From<tdh::TdhNativeError> for ParserError {
    fn from(err: tdh::TdhNativeError) -> Self {
        ParserError::TdhNativeError(err)
    }
}

impl From<sddl::SddlNativeError> for ParserError {
    fn from(err: sddl::SddlNativeError) -> Self {
        ParserError::SddlNativeError(err)
    }
}

impl From<std::string::FromUtf8Error> for ParserError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ParserError::Utf8Error(err)
    }
}

impl From<std::array::TryFromSliceError> for ParserError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        ParserError::SliceError(err)
    }
}

type ParserResult<T> = Result<T, ParserError>;

/// Trait to try and parse a type
///
/// This trait has to be implemented in order to be able to parse a type we want to retrieve from
/// within an Event.
///
/// An implementation for most of the Primitive Types is created by using a Macro, any other needed type
/// requires this trait to be implemented
// TODO: Find a way to use turbofish operator
pub trait TryParse<T> {
    /// Implement the `try_parse` function to provide a way to Parse `T` from an ETW event or
    /// return an Error in case the type `T` can't be parsed
    ///
    /// # Arguments
    /// * `name` - Name of the property to be found in the Schema
    fn try_parse(&self, name: &str) -> Result<T, ParserError>;
}

#[derive(Default)]
/// Cache of the properties we've extracted already
///
/// This is useful because computing their offset can be costly
struct CachedSlices<'schema, 'record> {
    slices: HashMap<String, PropertySlice<'schema, 'record>>,
    /// The user buffer index we've cached up to
    last_cached_offset: usize,
}

/// Represents a Parser
///
/// This structure provides a way to parse an ETW event (= extract its properties).
/// Because properties may have variable length (e.g. strings), a `Parser` is only suited to a single [`EventRecord`]
#[allow(dead_code)]
pub struct Parser<'schema, 'record> {
    properties: &'schema [Property],
    record: &'record EventRecord,
    cache: Mutex<CachedSlices<'schema, 'record>>,
}

impl<'schema, 'record> Parser<'schema, 'record> {
    /// Use the `create` function to create an instance of a Parser
    ///
    /// # Arguments
    /// * `schema` - The [Schema] from the ETW Event we want to parse
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::native::etw_types::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// # use ferrisetw::parser::Parser;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let parser = Parser::create(record, &schema);
    /// };
    /// ```
    pub fn create(event_record: &'record EventRecord, schema: &'schema Schema) -> Self {
        Parser {
            record: &event_record,
            properties: schema.properties(),
            cache: Mutex::new(CachedSlices::default())
        }
    }

    // TODO: Find a cleaner way to do this, not very happy with it rn
    #[allow(clippy::len_zero)]
    fn find_property_size(&self, property: &Property) -> ParserResult<usize> {
        // There are several cases
        //  * regular case, where property.len() directly makes sense
        //  * but EVENT_PROPERTY_INFO.length is an union, and (in its lengthPropertyIndex form) can refeer to another field
        //    e.g.: the WinInet provider manifest has fields such as `<data name="Verb" inType="win:AnsiString" length="_VerbLength"/>`
        //    In this case, we defer to TDH to know the right length.

        if property
            .flags
            .contains(PropertyFlags::PROPERTY_PARAM_LENGTH) == false
            && (property.len() > 0)
        {
            let size = if property.in_type() != TdhInType::InTypePointer {
                property.len()
            } else {
                // There is an exception regarding pointer size though
                // When reading captures, we should take care of the pointer size at the _source_, rather than the current architecture's pointer size.
                // Note that a 32-bit program on a 64-bit OS would still send 32-bit pointers
                if (self.record.event_flags() & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 {
                    4
                } else {
                    8
                }
            };
            return Ok(size);
        }

        // Actually, before asking TDH for the right length, there are some cases where we could determine ourselves.

        // TODO: Study heuristic method used in krabsetw :)
        if property.flags.is_empty() && property.len() > 0 {
            return Ok(property.len());
        }

        Ok(tdh::property_size(self.record, &property.name)? as usize)
    }

    fn find_property(&self, name: &str) -> ParserResult<PropertySlice<'schema, 'record>> {
        let mut cache = self.cache.lock().unwrap();

        // We may have extracted this property already
        if let Some(p) = cache.slices.get(name) {
            return Ok(*p);
        }

        let last_cached_property = cache.slices.len();
        let properties_not_parsed_yet = match self.properties.get(last_cached_property..) {
            Some(s) => s,
            // If we've parsed every property already, that means no property matches this name
            None => return Err(ParserError::NotFound)
        };

        for property in properties_not_parsed_yet {
            let prop_size = self.find_property_size(&property)?;
            let end_offset = cache.last_cached_offset + prop_size;

            let buffer = match self.record.user_buffer().get(cache.last_cached_offset..end_offset) {
                None => return Err(ParserError::PropertyError("Property length out of buffer bounds".to_owned())),
                Some(s) => s,
            };

            let prop_slice = PropertySlice {
                property,
                buffer
            };
            cache.slices.insert(String::clone(&property.name), prop_slice);
            cache.last_cached_offset += prop_size;

            if &property.name == name {
                return Ok(prop_slice);
            }
        }

        Err(ParserError::NotFound)
    }
}

macro_rules! impl_try_parse_primitive {
    ($T:ident) => {
        impl TryParse<$T> for Parser<'_, '_> {
            fn try_parse(&self, name: &str) -> ParserResult<$T> {
                let prop_slice = self.find_property(name)?;

                // TODO: Check In and Out type and do a better type checking
                if std::mem::size_of::<$T>() != prop_slice.buffer.len() {
                    return Err(ParserError::LengthMismatch);
                }
                Ok($T::from_ne_bytes(prop_slice.buffer.try_into()?))
            }
        }
    };
}

impl_try_parse_primitive!(u8);
impl_try_parse_primitive!(i8);
impl_try_parse_primitive!(u16);
impl_try_parse_primitive!(i16);
impl_try_parse_primitive!(u32);
impl_try_parse_primitive!(i32);
impl_try_parse_primitive!(u64);
impl_try_parse_primitive!(i64);
impl_try_parse_primitive!(usize);
impl_try_parse_primitive!(isize);

/// The `String` impl of the `TryParse` trait should be used to retrieve the following [TdhInTypes]:
///
/// * InTypeUnicodeString
/// * InTypeAnsiString
/// * InTypeCountedString
/// * InTypeGuid
///
/// On success a `String` with the with the data from the `name` property will be returned
///
/// # Arguments
/// * `name` - Name of the property to be found in the Schema
///
/// # Example
/// ```
/// # use ferrisetw::native::etw_types::EventRecord;
/// # use ferrisetw::schema_locator::SchemaLocator;
/// # use ferrisetw::parser::{Parser, TryParse};
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let mut parser = Parser::create(record, &schema);
///     let image_name: String = parser.try_parse("ImageName").unwrap();
/// };
/// ```
///
/// [TdhInTypes]: TdhInType
impl TryParse<String> for Parser<'_, '_> {
    fn try_parse(&self, name: &str) -> ParserResult<String> {
        let prop_slice = self.find_property(name)?;

        // TODO: Handle errors and type checking better
        let res = match prop_slice.property.in_type() {
            TdhInType::InTypeUnicodeString => {
                utils::parse_null_utf16_string(prop_slice.buffer)
            }
            TdhInType::InTypeAnsiString => String::from_utf8(prop_slice.buffer.to_vec())?
                .trim_matches(char::default())
                .to_string(),
            TdhInType::InTypeSid => {
                sddl::convert_sid_to_string(prop_slice.buffer.as_ptr() as *const _)?
            }
            TdhInType::InTypeCountedString => unimplemented!(),
            _ => return Err(ParserError::InvalidType),
        };

        Ok(res)
    }
}

impl TryParse<GUID> for Parser<'_, '_> {
    fn try_parse(&self, name: &str) -> Result<GUID, ParserError> {
        let prop_slice = self.find_property(name)?;

        let guid_string = utils::parse_utf16_guid(prop_slice.buffer);

        if guid_string.len() != 36 {
            return Err(ParserError::LengthMismatch);
        }

        Ok(GUID::from(guid_string.as_str()))
    }
}

impl TryParse<IpAddr> for Parser<'_, '_> {
    fn try_parse(&self, name: &str) -> ParserResult<IpAddr> {
        let prop_slice = self.find_property(name)?;

        if prop_slice.property.out_type() != TdhOutType::OutTypeIpv4
            && prop_slice.property.out_type() != TdhOutType::OutTypeIpv6
        {
            return Err(ParserError::InvalidType);
        }

        // Hardcoded values for now
        let res = match prop_slice.property.len() {
            16 => {
                let tmp: [u8; 16] = prop_slice.buffer.try_into()?;
                IpAddr::V6(Ipv6Addr::from(tmp))
            }
            4 => {
                let tmp: [u8; 4] = prop_slice.buffer.try_into()?;
                IpAddr::V4(Ipv4Addr::from(tmp))
            }
            _ => return Err(ParserError::LengthMismatch),
        };

        Ok(res)
    }
}

#[derive(Clone, Default, Debug)]
pub struct Pointer(usize);

impl std::ops::Deref for Pointer {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Pointer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::LowerHex for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::LowerHex::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl std::fmt::UpperHex for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::UpperHex::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl std::fmt::Display for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::Display::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl TryParse<Pointer> for Parser<'_, '_> {
    fn try_parse(&self, name: &str) -> ParserResult<Pointer> {
        let prop_slice = self.find_property(name)?;

        let mut res = Pointer::default();
        if prop_slice.buffer.len() == std::mem::size_of::<u32>() {
            res.0 = TryParse::<u32>::try_parse(self, name)? as usize;
        } else {
            res.0 = TryParse::<u64>::try_parse(self, name)? as usize;
        }

        Ok(res)
    }
}

impl TryParse<Vec<u8>> for Parser<'_, '_> {
    fn try_parse(&self, name: &str) -> Result<Vec<u8>, ParserError> {
        let prop_slice = self.find_property(name)?;
        Ok(prop_slice.buffer.to_vec())
    }
}

// TODO: Implement SocketAddress
// TODO: Study if we can use primitive types for HexInt64, HexInt32 and Pointer
