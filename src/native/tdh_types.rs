//! Basic TDH types
//!
//! The `tdh_type` module provides an abstraction over the basic TDH types, this module act as a
//! helper for the parser to determine which IN and OUT type are expected from a property within an
//! event
//!
//! This is a bit extra but is basically a redefinition of the In an Out TDH types following the
//! rust naming convention, it can also come in handy when implementing the `TryParse` trait for a type
//! to determine how to handle a [Property] based on this values
//!
//! [Property]: crate::native::tdh_types::Property
use num_traits::FromPrimitive;

use windows::Win32::System::Diagnostics::Etw;

#[derive(Debug, Clone)]
pub enum PropertyError{
    /// Parsing complex types in properties is not supported in this crate
    /// (yet? See <https://github.com/n4r1b/ferrisetw/issues/76>)
    UnimplementedType
}

impl std::fmt::Display for PropertyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnimplementedType => write!(f, "unimplemented type"),
        }
    }
}

/// Attributes of a property
#[derive(Debug, Clone, Default)]
pub struct Property {
    /// Name of the Property
    pub name: String,
    /// Represent the [PropertyFlags]
    pub flags: PropertyFlags,
    /// TDH In type of the property
    pub length: u16,
    pub in_type: TdhInType,
    /// TDH Out type of the property
    pub out_type: TdhOutType,
}

#[doc(hidden)]
impl Property {
    pub fn new(name: String, property: &Etw::EVENT_PROPERTY_INFO) -> Result<Self, PropertyError> {
        let flags = PropertyFlags::from(property.Flags);

        if !flags.contains(PropertyFlags::PROPERTY_STRUCT) {
            // The property is a non-struct type. It makes sense to access these fields of the unions
            let ot = unsafe { property.Anonymous1.nonStructType.OutType };
            let it = unsafe { property.Anonymous1.nonStructType.InType };

            let length = if flags.contains(PropertyFlags::PROPERTY_PARAM_LENGTH) {
                // TODO: support properties that point at sibling property to tell the length of the property
                return Err(PropertyError::UnimplementedType);
            } else {
                // The property has no param for its length, it makes sense to access this field of the union
                unsafe { property.Anonymous3.length }
            };

            let out_type = FromPrimitive::from_u16(ot)
                .unwrap_or(TdhOutType::OutTypeNull);

            let in_type = FromPrimitive::from_u16(it)
                .unwrap_or(TdhInType::InTypeNull);

            return Ok(Property {
                name,
                flags,
                length,
                in_type,
                out_type,
            });
        }

        Err(PropertyError::UnimplementedType)
    }

    pub fn in_type(&self) -> TdhInType {
        self.in_type
    }

    pub fn out_type(&self) -> TdhOutType {
        self.out_type
    }

    pub fn len(&self) -> usize {
        self.length as usize
    }
}

/// Represent a TDH_IN_TYPE
#[repr(u16)]
#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq, Eq, Default)]
pub enum TdhInType {
    // Deprecated values are not defined
    #[default]
    InTypeNull,
    InTypeUnicodeString,
    InTypeAnsiString,
    InTypeInt8,    // Field size is 1 byte
    InTypeUInt8,   // Field size is 1 byte
    InTypeInt16,   // Field size is 2 bytes
    InTypeUInt16,  // Field size is 2 bytes
    InTypeInt32,   // Field size is 4 bytes
    InTypeUInt32,  // Field size is 4 bytes
    InTypeInt64,   // Field size is 8 bytes
    InTypeUInt64,  // Field size is 8 bytes
    InTypeFloat,   // Field size is 4 bytes
    InTypeDouble,  // Field size is 8 bytes
    InTypeBoolean, // Field size is 4 bytes
    InTypeBinary,  // Depends on the OutType
    InTypeGuid,
    InTypePointer,
    InTypeFileTime,   // Field size is 8 bytes
    InTypeSystemTime, // Field size is 16 bytes
    InTypeSid,        // Field size determined by the first few bytes of the field
    InTypeHexInt32,
    InTypeHexInt64,
    InTypeCountedString = 300,
}

/// Represent a TDH_OUT_TYPE
#[repr(u16)]
#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq, Eq, Default)]
pub enum TdhOutType {
    #[default]
    OutTypeNull,
    OutTypeString,
    OutTypeDateTime,
    OutTypeInt8,    // Field size is 1 byte
    OutTypeUInt8,   // Field size is 1 byte
    OutTypeInt16,   // Field size is 2 bytes
    OutTypeUInt16,  // Field size is 2 bytes
    OutTypeInt32,   // Field size is 4 bytes
    OutTypeUInt32,  // Field size is 4 bytes
    OutTypeInt64,   // Field size is 8 bytes
    OutTypeUInt64,  // Field size is 8 bytes
    OutTypeFloat,   // Field size is 4 bytes
    OutTypeDouble,  // Field size is 8 bytes
    OutTypeBoolean, // Field size is 4 bytes
    OutTypeGuid,
    OutTypeHexBinary,
    OutTypeHexInt8,
    OutTypeHexInt16,
    OutTypeHexInt32,
    OutTypeHexInt64,
    OutTypePid,
    OutTypeTid,
    OutTypePort,
    OutTypeIpv4,
    OutTypeIpv6,
    OutTypeWin32Error = 30,
    OutTypeNtStatus = 31,
    OutTypeHResult = 32,
    OutTypeJson = 34,
    OutTypeUtf8 = 35,
    OutTypePkcs7 = 36,
    OutTypeCodePointer = 37,
    OutTypeDatetimeUtc = 38,
}

bitflags! {
    /// Represents the Property flags
    ///
    /// See: [Property Flags enum](https://docs.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-property_flags)
    #[derive(Default)]
    pub struct PropertyFlags: u32 {
        const PROPERTY_STRUCT = 0x1;
        const PROPERTY_PARAM_LENGTH = 0x2;
        const PROPERTY_PARAM_COUNT = 0x4;
        const PROPERTY_WBEMXML_FRAGMENT = 0x8;
        const PROPERTY_PARAM_FIXED_LENGTH = 0x10;
        const PROPERTY_PARAM_FIXED_COUNT = 0x20;
        const PROPERTY_HAS_TAGS = 0x40;
        const PROPERTY_HAS_CUSTOM_SCHEMA = 0x80;
    }
}

impl From<Etw::PROPERTY_FLAGS> for PropertyFlags {
    fn from(val: Etw::PROPERTY_FLAGS) -> Self {
        let flags: i32 = val.0;
        // Should be a safe cast
        PropertyFlags::from_bits_truncate(flags as u32)
    }
}
