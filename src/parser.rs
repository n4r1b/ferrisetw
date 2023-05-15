//! ETW Types Parser
//!
//! This module act as a helper to parse the Buffer from an ETW Event

use crate::native::etw_types::event_record::EventRecord;
use crate::native::sddl;
use crate::native::tdh;
use crate::native::tdh_types::{
    Property, PropertyCount, PropertyInfo, PropertyLength, TdhInType, TdhOutType,
};
use crate::native::time::{FileTime, SystemTime};
use crate::property::PropertySlice;
use crate::schema::Schema;
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
    /// An invalid type
    InvalidType,
    /// Error parsing
    ParseError,
    /// Length mismatch when parsing a type
    LengthMismatch,
    PropertyError(String),
    /// An error while transforming an Utf-8 buffer into String
    Utf8Error(std::str::Utf8Error),
    /// An error trying to get an slice as an array
    SliceError(std::array::TryFromSliceError),
    /// Represents an internal [SddlNativeError](crate::native::SddlNativeError)
    SddlNativeError(crate::native::SddlNativeError),
    /// Represents an internal [TdhNativeError](crate::native::TdhNativeError)
    TdhNativeError(crate::native::TdhNativeError),
}

impl From<crate::native::TdhNativeError> for ParserError {
    fn from(err: crate::native::TdhNativeError) -> Self {
        ParserError::TdhNativeError(err)
    }
}

impl From<crate::native::SddlNativeError> for ParserError {
    fn from(err: crate::native::SddlNativeError) -> Self {
        ParserError::SddlNativeError(err)
    }
}

impl From<std::str::Utf8Error> for ParserError {
    fn from(err: std::str::Utf8Error) -> Self {
        ParserError::Utf8Error(err)
    }
}

impl From<std::array::TryFromSliceError> for ParserError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        ParserError::SliceError(err)
    }
}

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::InvalidType => write!(f, "invalid type"),
            Self::ParseError => write!(f, "parse error"),
            Self::LengthMismatch => write!(f, "length mismatch"),
            Self::PropertyError(s) => write!(f, "property error {}", s),
            Self::Utf8Error(e) => write!(f, "utf-8 error {}", e),
            Self::SliceError(e) => write!(f, "slice error {}", e),
            Self::SddlNativeError(e) => write!(f, "sddl native error {}", e),
            Self::TdhNativeError(e) => write!(f, "tdh native error {}", e),
        }
    }
}

type ParserResult<T> = Result<T, ParserError>;

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
///
/// # Example
/// ```
/// # use ferrisetw::EventRecord;
/// # use ferrisetw::schema_locator::SchemaLocator;
/// # use ferrisetw::parser::Parser;
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let parser = Parser::create(record, &schema);
///
///     // There are several ways to define the type requested for `try_parse`
///     // It is possible to use type inference...
///     let property1: Option<String> = parser.try_parse("PropertyName").ok();
///
///     // ...or to use the turbofish operator
///     match parser.try_parse::<u32>("OtherPropertyName") {
///         Ok(_) => println!("OtherPropertyName is a valid u32"),
///         Err(_) => println!("OtherPropertyName is invalid"),
///     }
/// };
/// ```
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
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// # use ferrisetw::parser::Parser;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let parser = Parser::create(record, &schema);
    /// };
    /// ```
    pub fn create(event_record: &'record EventRecord, schema: &'schema Schema) -> Self {
        Parser {
            record: event_record,
            properties: schema.properties(),
            cache: Mutex::new(CachedSlices::default()),
        }
    }

    #[allow(clippy::len_zero)]
    fn find_property_size(
        &self,
        property: &Property,
        remaining_user_buffer: &[u8],
    ) -> ParserResult<usize> {
        match property.info {
            PropertyInfo::Value {
                in_type, length, ..
            } => {
                // There are several cases
                //  * regular case, where property.len() directly makes sense
                //  * but EVENT_PROPERTY_INFO.length is an union, and (in its lengthPropertyIndex form) can refeer to another field
                //    e.g.: the WinInet provider manifest has fields such as `<data name="Verb" inType="win:AnsiString" length="_VerbLength"/>`
                //    In this case, we defer to TDH to know the right length.

                // For pointer input type we can immediately infer the size based on the header flags.
                if in_type == TdhInType::InTypePointer {
                    return Ok(self.record.pointer_size());
                }

                let prop_len = match length {
                    PropertyLength::Length(l) => l,
                    PropertyLength::Index(_) => {
                        // TODO optimize to cache the lookup, the problem is here this is called under an
                        // exclusive mutex, so attempting to extract and cache a related property will
                        // deadlock.
                        return Ok(tdh::property_size(self.record, &property.name)? as usize);
                    }
                };

                if prop_len > 0 {
                    return Ok(prop_len as usize);
                }

                // Length is not set. We'll have to ask TDH for the right length.
                // However, before doing so, there are some cases where we could determine ourselves.
                // The following _very_ common property types can be short-circuited to prevent the expensive call.
                // (that's taken from krabsetw)

                match in_type {
                    TdhInType::InTypeAnsiString => {
                        let mut l = 0;
                        for char in remaining_user_buffer {
                            if char == &0 {
                                l += 1; // include the final null byte
                                break;
                            }
                            l += 1;
                        }
                        return Ok(l);
                    }
                    TdhInType::InTypeUnicodeString => {
                        let mut l = 0;
                        for bytes in remaining_user_buffer.chunks_exact(2) {
                            if bytes[0] == 0 && bytes[1] == 0 {
                                l += 2;
                                break;
                            }
                            l += 2;
                        }
                        return Ok(l);
                    }
                    _ => (),
                }

                Ok(tdh::property_size(self.record, &property.name)? as usize)
            }
            PropertyInfo::Array {
                in_type,
                length,
                count,
                ..
            } => {
                // For pointer input type we can immediately infer the size based on the header flags.
                let prop_len = if in_type == TdhInType::InTypePointer {
                    self.record.pointer_size()
                } else {
                    match length {
                        PropertyLength::Length(l) => l as usize,
                        PropertyLength::Index(_) => {
                            // TODO optimize to cache the lookup, the problem is here this is called under an
                            // exclusive mutex, so attempting to extract and cache a related property will
                            // deadlock.
                            return Ok(tdh::property_size(self.record, &property.name)? as usize);
                        }
                    }
                };

                let prop_count = match count {
                    PropertyCount::Count(c) => c as usize,
                    PropertyCount::Index(_) => {
                        // TODO optimize to cache the lookup, the problem is here this is called under an
                        // exclusive mutex, so attempting to extract and cache a related property will
                        // deadlock.
                        return Ok(tdh::property_size(self.record, &property.name)? as usize);
                    }
                };

                if prop_len > 0 {
                    return Ok(prop_len * prop_count);
                }

                Ok(tdh::property_size(self.record, &property.name)? as usize)
            }
        }
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
            None => return Err(ParserError::NotFound),
        };

        for property in properties_not_parsed_yet {
            let remaining_user_buffer =
                match self.record.user_buffer().get(cache.last_cached_offset..) {
                    None => {
                        return Err(ParserError::PropertyError(
                            "Invalid buffer bounds".to_owned(),
                        ))
                    }
                    Some(s) => s,
                };

            let prop_size = self.find_property_size(property, remaining_user_buffer)?;
            let property_buffer = match remaining_user_buffer.get(..prop_size) {
                None => {
                    return Err(ParserError::PropertyError(
                        "Property length out of buffer bounds".to_owned(),
                    ))
                }
                Some(s) => s,
            };

            let prop_slice = PropertySlice {
                property,
                buffer: property_buffer,
            };
            cache
                .slices
                .insert(String::clone(&property.name), prop_slice);
            cache.last_cached_offset += prop_size;

            if property.name == name {
                return Ok(prop_slice);
            }
        }

        Err(ParserError::NotFound)
    }

    /// Return a property from the event, or an error in case the parsing failed.
    ///
    /// You must explicitly define `T`, the type you want to parse the property into.<br/>
    /// In case this type is not compatible with the ETW type, [`ParserError::InvalidType`] is returned.
    pub fn try_parse<T>(&self, name: &str) -> ParserResult<T>
    where
        Parser<'schema, 'record>: private::TryParse<T>,
    {
        use crate::parser::private::TryParse;
        self.try_parse_impl(name)
    }
}

mod private {
    use super::*;

    /// Trait to try and parse a type
    ///
    /// This trait has to be implemented in order to be able to parse a type we want to retrieve from
    /// within an Event.
    ///
    /// An implementation for most of the Primitive Types is created by using a Macro, any other needed type
    /// requires this trait to be implemented
    pub trait TryParse<T> {
        /// Implement the `try_parse` function to provide a way to Parse `T` from an ETW event or
        /// return an Error in case the type `T` can't be parsed
        ///
        /// # Arguments
        /// * `name` - Name of the property to be found in the Schema
        fn try_parse_impl(&self, name: &str) -> Result<T, ParserError>;
    }
}

macro_rules! impl_try_parse_primitive {
    ($T:ident) => {
        impl private::TryParse<$T> for Parser<'_, '_> {
            fn try_parse_impl(&self, name: &str) -> ParserResult<$T> {
                let prop_slice = self.find_property(name)?;

                match prop_slice.property.info {
                    PropertyInfo::Value { .. } => {
                        // TODO: Check In and Out type and do a better type checking
                        if std::mem::size_of::<$T>() != prop_slice.buffer.len() {
                            return Err(ParserError::LengthMismatch);
                        }
                        Ok($T::from_ne_bytes(prop_slice.buffer.try_into()?))
                    }
                    _ => Err(ParserError::InvalidType),
                }
            }
        }
    };
}

macro_rules! impl_try_parse_primitive_array {
    ($T:ident) => {
        impl<'schema, 'record> private::TryParse<&'record [$T]> for Parser<'schema, 'record> {
            fn try_parse_impl(&self, name: &str) -> ParserResult<&'record [$T]> {
                let prop_slice = self.find_property(name)?;

                match prop_slice.property.info {
                    PropertyInfo::Array { .. } => {
                        // TODO: Check In and Out type and do a better type checking
                        let size = std::mem::size_of::<$T>();
                        if prop_slice.buffer.len() % size != 0 {
                            return Err(ParserError::LengthMismatch);
                        }
                        let count = prop_slice.buffer.len() / size;
                        let slice = unsafe {
                            std::slice::from_raw_parts(
                                prop_slice.buffer.as_ptr() as *const $T,
                                count,
                            )
                        };
                        Ok(slice)
                    }
                    _ => Err(ParserError::InvalidType),
                }
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
impl_try_parse_primitive!(f32);
impl_try_parse_primitive!(f64);

impl_try_parse_primitive_array!(u16);
impl_try_parse_primitive_array!(i16);
impl_try_parse_primitive_array!(u32);
impl_try_parse_primitive_array!(i32);
impl_try_parse_primitive_array!(u64);
impl_try_parse_primitive_array!(i64);

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
/// # use ferrisetw::EventRecord;
/// # use ferrisetw::schema_locator::SchemaLocator;
/// # use ferrisetw::parser::Parser;
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let parser = Parser::create(record, &schema);
///     let image_name: String = parser.try_parse("ImageName").unwrap();
/// };
/// ```
///
/// [TdhInTypes]: TdhInType
impl private::TryParse<String> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<String> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => match in_type {
                TdhInType::InTypeUnicodeString => {
                    if prop_slice.buffer.len() % 2 != 0 {
                        return Err(ParserError::PropertyError(
                            "odd length in bytes for a wide string".into(),
                        ));
                    }

                    let mut wide = unsafe {
                        std::slice::from_raw_parts(
                            prop_slice.buffer.as_ptr() as *const u16,
                            prop_slice.buffer.len() / 2,
                        )
                    };

                    match wide.last() {
                        // remove the null terminator from the slice
                        Some(c) if c == &0 => wide = &wide[..wide.len() - 1],
                        _ => (),
                    }

                    Ok(widestring::decode_utf16_lossy(wide.iter().copied()).collect::<String>())
                }
                TdhInType::InTypeAnsiString => {
                    let string = std::str::from_utf8(prop_slice.buffer)?;
                    Ok(string.trim_matches(char::default()).to_string())
                }
                TdhInType::InTypeSid => {
                    let string =
                        sddl::convert_sid_to_string(prop_slice.buffer.as_ptr() as *const _)?;
                    Ok(string)
                }
                TdhInType::InTypeCountedString => unimplemented!(),
                _ => Err(ParserError::InvalidType),
            },
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<GUID> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> Result<GUID, ParserError> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeGuid {
                    return Err(ParserError::InvalidType);
                }

                if prop_slice.buffer.len() != 16 {
                    return Err(ParserError::LengthMismatch);
                }

                Ok(GUID {
                    data1: u32::from_ne_bytes(prop_slice.buffer[0..4].try_into()?),
                    data2: u16::from_ne_bytes(prop_slice.buffer[4..6].try_into()?),
                    data3: u16::from_be_bytes(prop_slice.buffer[6..8].try_into()?),
                    data4: prop_slice.buffer[8..].try_into()?,
                })
            }
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<IpAddr> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<IpAddr> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { out_type, .. } => {
                if out_type != TdhOutType::OutTypeIpv4 && out_type != TdhOutType::OutTypeIpv6 {
                    return Err(ParserError::InvalidType);
                }

                // Hardcoded values for now
                let res = match prop_slice.buffer.len() {
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
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<bool> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<bool> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeBoolean {
                    return Err(ParserError::InvalidType);
                }

                match prop_slice.buffer.len() {
                    1 => Ok(prop_slice.buffer[0] != 0),
                    4 => Ok(u32::from_ne_bytes(prop_slice.buffer.try_into()?) != 0),
                    8 => Ok(u64::from_ne_bytes(prop_slice.buffer.try_into()?) != 0),
                    _ => Err(ParserError::LengthMismatch),
                }
            }
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<FileTime> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<FileTime> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeFileTime {
                    return Err(ParserError::InvalidType);
                }

                Ok(FileTime::from_slice(prop_slice.buffer.try_into()?))
            }
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<SystemTime> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<SystemTime> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeSystemTime {
                    return Err(ParserError::InvalidType);
                }

                Ok(SystemTime::from_slice(prop_slice.buffer.try_into()?))
            }
            _ => Err(ParserError::InvalidType),
        }
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

impl private::TryParse<Pointer> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<Pointer> {
        let prop_slice = self.find_property(name)?;

        let mut res = Pointer::default();
        if prop_slice.buffer.len() == std::mem::size_of::<u32>() {
            res.0 = private::TryParse::<u32>::try_parse_impl(self, name)? as usize;
        } else {
            res.0 = private::TryParse::<u64>::try_parse_impl(self, name)? as usize;
        }

        Ok(res)
    }
}

impl private::TryParse<Vec<u8>> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> Result<Vec<u8>, ParserError> {
        let prop_slice = self.find_property(name)?;
        Ok(prop_slice.buffer.to_vec())
    }
}

// TODO: Implement SocketAddress
// TODO: Study if we can use primitive types for HexInt64, HexInt32 and Pointer
