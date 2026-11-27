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
use std::sync::{Mutex, PoisonError};
use windows::core::GUID;
use windows::Win32::Globalization::{MultiByteToWideChar, CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS};

#[cfg(test)]
#[path = "parser/reversed_counted_tests.rs"]
mod reversed_counted_tests;

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
        // A poisoned cache is safe to reuse: `slices` and `last_cached_offset` only change
        // together below, after every fallible step for that property, and nothing between the
        // two updates can panic. A panic while the lock is held therefore leaves both fields
        // describing the same prefix of the user buffer.
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);

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

                        // This property type has not been tested yet as I don't have a
                        // provider that uses it. It's possible that the buffer is not
                        // aligned correctly, which would cause this to fail.
                        let size = std::mem::size_of::<$T>();
                        let align = std::mem::align_of::<$T>();

                        if prop_slice.buffer.len() % size != 0 {
                            return Err(ParserError::LengthMismatch);
                        }

                        let count = prop_slice.buffer.len() / size;

                        if prop_slice.buffer.as_ptr() as usize % align != 0 {
                            return Err(ParserError::PropertyError(
                                "buffer alignment mismatch".into(),
                            ));
                        }

                        if size.checked_mul(count).is_none() || (size * count) > isize::MAX as usize
                        {
                            return Err(ParserError::PropertyError("size overflow".into()));
                        }

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
            PropertyInfo::Value {
                in_type, out_type, ..
            } => match in_type {
                TdhInType::InTypeUnicodeString => {
                    if prop_slice.buffer.len() % 2 != 0 {
                        return Err(ParserError::PropertyError(
                            "odd length in bytes for a wide string".into(),
                        ));
                    }

                    // std::slice::from_raw_parts requires a pointer to be aligned, but we can't
                    // guarantee that the buffer is aligned. In testing, I found that the buffer
                    // is in fact never aligned appropriately, so a cheap workaround is to copy
                    // the buffer into a new Vec<u16> and use that as the source for the slice
                    // until we can find a better solution.
                    let mut aligned_buffer = Vec::with_capacity(prop_slice.buffer.len() / 2);
                    for chunk in prop_slice.buffer.chunks_exact(2) {
                        let part = u16::from_ne_bytes([chunk[0], chunk[1]]);
                        aligned_buffer.push(part);
                    }

                    let mut wide = aligned_buffer.as_slice();

                    match wide.last() {
                        // remove the null terminator from the slice
                        Some(c) if c == &0 => wide = &wide[..wide.len() - 1],
                        _ => (),
                    }

                    // Decode UTF-16 to String
                    Ok(widestring::decode_utf16_lossy(wide.iter().copied()).collect::<String>())
                }
                TdhInType::InTypeAnsiString => {
                    let string = std::str::from_utf8(prop_slice.buffer)?;
                    Ok(string.trim_matches(char::default()).to_string())
                }
                TdhInType::InTypeSid => parse_sid(prop_slice.buffer),
                TdhInType::InTypeWbemSid => {
                    let flags = self.record.event_flags();
                    let pointer_size = if flags & 0x20 != 0 {
                        4
                    } else if flags & 0x40 != 0 {
                        8
                    } else {
                        std::mem::size_of::<usize>()
                    };
                    let sid = prop_slice
                        .buffer
                        .get(pointer_size * 2..)
                        .ok_or(ParserError::LengthMismatch)?;
                    parse_sid(sid)
                }
                TdhInType::InTypeCountedString => parse_counted_utf16(prop_slice.buffer, false),
                TdhInType::InTypeReversedCountedString => {
                    parse_counted_utf16(prop_slice.buffer, true)
                }
                TdhInType::InTypeReversedCountedAnsiString => {
                    parse_reversed_counted_ansi(prop_slice.buffer, out_type)
                }
                TdhInType::InTypeCountedAnsiString => {
                    if prop_slice.buffer.len() < 2 {
                        return Err(ParserError::PropertyError(
                            "counted ANSI string does not have length".into(),
                        ));
                    }
                    let str_length = u16::from_le_bytes(
                        prop_slice.buffer[..std::mem::size_of::<u16>()]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    if prop_slice.buffer[std::mem::size_of::<u16>()..].len() < str_length {
                        return Err(ParserError::PropertyError(
                            "invalid counted ANSI string length".into(),
                        ));
                    }
                    let string = std::str::from_utf8(
                        &prop_slice.buffer
                            [std::mem::size_of::<u16>()..std::mem::size_of::<u16>() + str_length],
                    )?;
                    Ok(string.to_string())
                }
                _ => Err(ParserError::InvalidType),
            },
            _ => Err(ParserError::InvalidType),
        }
    }
}

/// Decodes a TDH counted UTF-16 string. The byte count is little-endian for ordinary
/// types and big-endian for reversed types; the text is UTF-16LE in both cases.
/// Anything after the counted bytes is ignored.
fn parse_counted_utf16(data: &[u8], reversed: bool) -> ParserResult<String> {
    if data.len() < 2 {
        return Err(ParserError::PropertyError(
            "counted string does not have length".into(),
        ));
    }
    let (prefix, rest) = data.split_at(2);
    let count = [prefix[0], prefix[1]];
    let byte_len = usize::from(if reversed {
        u16::from_be_bytes(count)
    } else {
        u16::from_le_bytes(count)
    });
    if byte_len % 2 != 0 {
        return Err(ParserError::PropertyError(
            "UTF-16 counted string length is not even".into(),
        ));
    }
    let bytes = rest
        .get(..byte_len)
        .ok_or_else(|| ParserError::PropertyError("invalid counted string length".into()))?;

    // The event buffer can be unaligned, so code units are assembled from bytes rather than
    // reinterpreting the buffer as `[u16]`.
    let units = (0..byte_len)
        .step_by(2)
        .map(|i| u16::from_le_bytes([bytes[i], bytes[i + 1]]));
    Ok(widestring::decode_utf16_lossy(units).collect())
}

/// WBEM reversed counted ANSI: big-endian byte count followed by that many bytes.
/// XML, JSON and UTF-8 output types are UTF-8; other output types use the decoding
/// machine's ANSI code page because the event does not identify its original code page.
fn parse_reversed_counted_ansi(data: &[u8], out_type: TdhOutType) -> ParserResult<String> {
    let prefix = data.get(..2).ok_or_else(|| {
        ParserError::PropertyError("counted ANSI string does not have length".into())
    })?;
    let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    let bytes = data
        .get(2..2 + length)
        .ok_or_else(|| ParserError::PropertyError("invalid counted ANSI string length".into()))?;
    if matches!(
        out_type,
        TdhOutType::OutTypeUtf8 | TdhOutType::OutTypeJson | TdhOutType::OutTypeXml
    ) {
        return Ok(std::str::from_utf8(bytes)?.to_owned());
    }
    if bytes.is_empty() {
        return Ok(String::new());
    }
    // SAFETY: input is a valid bounded slice and the first call only queries the required length.
    let length =
        unsafe { MultiByteToWideChar(CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None) };
    if length == 0 {
        return Err(ParserError::PropertyError(format!(
            "ANSI conversion failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut wide = vec![0u16; length as usize];
    // SAFETY: `wide` has the size returned by the preceding call and both slices are valid.
    let written = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0),
            bytes,
            Some(&mut wide),
        )
    };
    if written == 0 {
        return Err(ParserError::PropertyError(format!(
            "ANSI conversion failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    wide.truncate(written as usize);
    Ok(String::from_utf16_lossy(&wide))
}

fn parse_sid(data: &[u8]) -> ParserResult<String> {
    let header = data.get(..8).ok_or(ParserError::LengthMismatch)?;
    let length = 8 + usize::from(header[1]) * 4;
    let sid = data.get(..length).ok_or(ParserError::LengthMismatch)?;
    // The event buffer can be unaligned; SID sub-authorities require u32 alignment.
    let mut aligned = vec![0u32; (length + 3) / 4];
    for (index, chunk) in sid.chunks(4).enumerate() {
        let mut bytes = [0u8; 4];
        bytes[..chunk.len()].copy_from_slice(chunk);
        aligned[index] = u32::from_ne_bytes(bytes);
    }
    Ok(sddl::convert_sid_to_string(aligned.as_ptr() as *const _)?)
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
                    data1: u32::from_le_bytes(prop_slice.buffer[0..4].try_into()?),
                    data2: u16::from_le_bytes(prop_slice.buffer[4..6].try_into()?),
                    data3: u16::from_le_bytes(prop_slice.buffer[6..8].try_into()?),
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

    fn parse_sid_property(data: &[u8], in_type: TdhInType, flags: u16) -> ParserResult<String> {
        let mut raw_record = EVENT_RECORD::default();
        raw_record.UserData = data.as_ptr() as *const _ as *mut _;
        raw_record.UserDataLength = data.len() as u16;
        raw_record.EventHeader.Flags = flags;
        let record = EventRecord(raw_record);
        let property = Property {
            name: "Sid".to_owned(),
            flags: Default::default(),
            info: PropertyInfo::Value {
                in_type,
                out_type: TdhOutType::default(),
                length: PropertyLength::Length(data.len() as u16),
            },
        };
        let parser = Parser {
            properties: std::slice::from_ref(&property),
            record: &record,
            cache: Mutex::new(CachedSlices::default()),
        };
        parser.try_parse::<String>("Sid")
    }

    #[test]
    fn wbem_sid_uses_event_pointer_width() {
        let sid = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
        for (flags, prefix) in [(0x20, 8), (0x40, 16)] {
            let mut data = vec![0; prefix];
            data.extend_from_slice(&sid);
            assert_eq!(
                parse_sid_property(&data, TdhInType::InTypeWbemSid, flags).unwrap(),
                "S-1-5-32-544"
            );
        }
    }

    #[test]
    fn wbem_sid_rejects_truncated_sid() {
        let sid = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
        for (flags, prefix) in [(0x20, 8), (0x40, 16)] {
            for len in 0..sid.len() {
                let mut data = vec![0; prefix];
                data.extend_from_slice(&sid[..len]);
                assert!(parse_sid_property(&data, TdhInType::InTypeWbemSid, flags).is_err());
            }
        }
    }

    #[test]
    fn wbem_sid_rejects_truncated_prefix() {
        for (flags, prefix) in [(0x20, 8), (0x40, 16)] {
            for len in 1..prefix {
                let data = vec![0; len];
                assert!(matches!(
                    parse_sid_property(&data, TdhInType::InTypeWbemSid, flags),
                    Err(ParserError::LengthMismatch)
                ));
            }
        }
    }

    #[test]
    fn sid_rejects_truncated_subauthorities() {
        let sid = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
        for len in 1..sid.len() {
            assert!(parse_sid_property(&sid[..len], TdhInType::InTypeSid, 0).is_err());
        }
        assert_eq!(
            parse_sid_property(&sid, TdhInType::InTypeSid, 0).unwrap(),
            "S-1-5-32-544"
        );
    }

    fn with_guid_parser(data: &[u8], in_type: TdhInType, check: impl FnOnce(&Parser<'_, '_>)) {
        let mut raw_record = EVENT_RECORD::default();
        raw_record.UserData = data.as_ptr() as *const _ as *mut _;
        raw_record.UserDataLength = data.len() as u16;

        let record = EventRecord(raw_record);
        let property = Property {
            name: "Guid".to_owned(),
            flags: Default::default(),
            info: PropertyInfo::Value {
                in_type,
                out_type: TdhOutType::OutTypeGuid,
                length: PropertyLength::Length(data.len() as u16),
            },
        };
        let parser = Parser {
            properties: std::slice::from_ref(&property),
            record: &record,
            cache: Mutex::new(CachedSlices::default()),
        };

        check(&parser);
    }

    #[test]
    fn guid_property_uses_windows_little_endian_layout() {
        let data = [
            0x40, 0xfc, 0x29, 0x6b, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1d, 0x00, 0xdd, 0x01, 0x06,
            0x62, 0xda,
        ];

        with_guid_parser(&data, TdhInType::InTypeGuid, |parser| {
            assert_eq!(
                parser.try_parse::<GUID>("Guid").unwrap(),
                GUID::from_u128(0x6b29_fc40_ca47_1067_b31d_00dd010662da),
            );
        });
    }

    #[test]
    fn guid_property_rejects_non_guid_type() {
        let data = [0; 16];

        with_guid_parser(&data, TdhInType::InTypeUInt32, |parser| {
            assert!(matches!(
                parser.try_parse::<GUID>("Guid"),
                Err(ParserError::InvalidType)
            ));
        });
    }

    #[test]
    fn guid_property_rejects_non_sixteen_byte_payload() {
        for data in [&[0; 15][..], &[0; 17][..]] {
            with_guid_parser(data, TdhInType::InTypeGuid, |parser| {
                assert!(matches!(
                    parser.try_parse::<GUID>("Guid"),
                    Err(ParserError::LengthMismatch)
                ));
            });
        }
    }

    fn parse_counted_string_property(data: &[u8]) -> ParserResult<String> {
        let record = EventRecord(EVENT_RECORD {
            UserData: data.as_ptr() as *mut _,
            UserDataLength: data.len() as u16,
            ..Default::default()
        });
        let property = Property {
            name: "Str".to_owned(),
            flags: Default::default(),
            info: PropertyInfo::Value {
                in_type: TdhInType::InTypeCountedString,
                out_type: TdhOutType::OutTypeString,
                length: PropertyLength::Length(data.len() as u16),
            },
        };
        let parser = Parser {
            properties: std::slice::from_ref(&property),
            record: &record,
            cache: Mutex::new(CachedSlices::default()),
        };
        parser.try_parse::<String>("Str")
    }

    fn counted_utf16(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut data = ((units.len() * 2) as u16).to_le_bytes().to_vec();
        data.extend(units.iter().flat_map(|u| u.to_le_bytes()));
        data
    }

    #[test]
    fn counted_string_decodes_non_bmp_text() {
        let text = "caf\u{e9} \u{1f980}";
        assert_eq!(
            parse_counted_string_property(&counted_utf16(text)).unwrap(),
            text
        );
    }

    #[test]
    fn counted_string_decodes_empty_string() {
        assert_eq!(parse_counted_string_property(&[0, 0]).unwrap(), "");
    }

    #[test]
    fn counted_string_rejects_truncated_length_prefix() {
        assert!(matches!(
            parse_counted_string_property(&[4]),
            Err(ParserError::PropertyError(_))
        ));
    }

    #[test]
    fn counted_string_rejects_length_beyond_data() {
        let mut data = counted_utf16("abc");
        data[0] += 2;
        assert!(matches!(
            parse_counted_string_property(&data),
            Err(ParserError::PropertyError(_))
        ));
    }

    #[test]
    fn counted_string_rejects_odd_byte_length() {
        let mut data = counted_utf16("abc");
        data[0] -= 1;
        assert!(matches!(
            parse_counted_string_property(&data),
            Err(ParserError::PropertyError(_))
        ));
    }

    #[test]
    fn counted_string_ignores_bytes_after_declared_length() {
        let mut data = counted_utf16("ab");
        data.extend("cd".encode_utf16().flat_map(|u| u.to_le_bytes()));
        assert_eq!(parse_counted_string_property(&data).unwrap(), "ab");
    }

    #[test]
    fn property_cache_recovers_poisoned_lock() {
        let data = 7u32.to_le_bytes();
        let record = EventRecord(EVENT_RECORD {
            UserData: data.as_ptr() as *mut _,
            UserDataLength: data.len() as u16,
            ..Default::default()
        });
        let property = Property {
            name: "Value".to_owned(),
            flags: Default::default(),
            info: PropertyInfo::Value {
                in_type: TdhInType::InTypeUInt32,
                out_type: TdhOutType::default(),
                length: PropertyLength::Length(data.len() as u16),
            },
        };
        let parser = Parser {
            properties: std::slice::from_ref(&property),
            record: &record,
            cache: Mutex::new(CachedSlices::default()),
        };

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = parser.cache.lock().unwrap();
            panic!("poison the property cache lock");
        }));
        assert!(parser.cache.is_poisoned());

        assert_eq!(parser.try_parse::<u32>("Value").unwrap(), 7);
    }

    #[test]
    fn populated_property_cache_recovers_poisoned_lock() {
        let data: Vec<u8> = [11u32, 22, 33]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let record = EventRecord(EVENT_RECORD {
            UserData: data.as_ptr() as *mut _,
            UserDataLength: data.len() as u16,
            ..Default::default()
        });
        let properties: Vec<Property> = ["First", "Second", "Third"]
            .iter()
            .map(|name| Property {
                name: (*name).to_owned(),
                flags: Default::default(),
                info: PropertyInfo::Value {
                    in_type: TdhInType::InTypeUInt32,
                    out_type: TdhOutType::default(),
                    length: PropertyLength::Length(4),
                },
            })
            .collect();
        let parser = Parser {
            properties: &properties,
            record: &record,
            cache: Mutex::new(CachedSlices::default()),
        };

        assert_eq!(parser.try_parse::<u32>("First").unwrap(), 11);

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = parser.cache.lock().unwrap();
            panic!("poison the property cache lock");
        }));
        assert!(parser.cache.is_poisoned());

        // "Third" is parsed from the recovered offset, past the uncached "Second".
        assert_eq!(parser.try_parse::<u32>("Third").unwrap(), 33);
        assert_eq!(parser.try_parse::<u32>("Second").unwrap(), 22);
        assert_eq!(parser.try_parse::<u32>("First").unwrap(), 11);
    }
}

#[cfg(test)]
#[path = "parser/reversed_ansi_out_type_tests.rs"]
mod reversed_ansi_out_type_tests;

#[cfg(all(test, feature = "serde"))]
pub(crate) fn parser_for_test_property<'schema, 'record>(
    record: &'record EventRecord,
    property: &'schema Property,
) -> Parser<'schema, 'record> {
    Parser {
        properties: std::slice::from_ref(property),
        record,
        cache: Mutex::new(CachedSlices::default()),
    }
}

#[cfg(test)]
#[path = "parser/afd_probe.rs"]
mod afd_probe;
